"""Repository-level Java framework facts.

Language parsing gives us methods and call expressions, but Spring injection and
MyBatis statement bindings live across source files (and, for MyBatis, in XML).
This module adds only deterministic, directly evidenced relationships: declared
field types, explicit ``implements`` clauses, and ``${...}`` substitutions in a
mapper statement.  ``#{...}`` placeholders are intentionally not reported as
SQL-injection sinks because MyBatis binds those values as parameters.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .java_ast_semantics import _WEAK_HASH_ALGOS, _is_weak_cipher_transform, _normalize_algo
from .models import CodeAnchor, CodeFacts, FunctionFact, IndexedFile, SinkFact
from .utils import normalize_path, sha256_text, stable_id

MAX_MAPPER_XML_FILES = 2_000
MAX_MAPPER_XML_BYTES = 4 * 1024 * 1024
_SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".idea",
    ".mvn",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
_FIELD = re.compile(
    r"^\s*(?:(?:public|protected|private|transient|volatile|static|final)\s+)*"
    r"(?P<type>[A-Za-z_$][\w$.,]*(?:\s*<[^;=(){}]+>)?(?:\s*\[\])?)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:=[^;]*)?;\s*$"
)
_IMPLEMENTS = re.compile(r"\b(?:class|record)\s+(?P<name>[A-Za-z_$][\w$]*)[^{}]*?\bimplements\s+(?P<types>[^\{]+)")
_MAPPER_NAMESPACE = re.compile(r"<mapper\b[^>]*\bnamespace\s*=\s*['\"](?P<namespace>[^'\"]+)['\"]", re.IGNORECASE)
_MAPPER_STATEMENT = re.compile(
    r"<(?P<tag>select|insert|update|delete)\b(?P<attrs>[^>]*)>(?P<body>.*?)</\s*(?P=tag)\s*>",
    re.IGNORECASE | re.DOTALL,
)
_MAPPER_FRAGMENT = re.compile(r"<sql\b(?P<attrs>[^>]*)>(?P<body>.*?)</\s*sql\s*>", re.IGNORECASE | re.DOTALL)
_STATEMENT_ID = re.compile(r"\bid\s*=\s*['\"](?P<id>[^'\"]+)['\"]", re.IGNORECASE)
_INCLUDE_REF = re.compile(r"<include\b[^>]*\brefid\s*=\s*['\"](?P<refid>[^'\"]+)['\"][^>]*/?>", re.IGNORECASE)
_DYNAMIC_PARAMETER = re.compile(r"\$\{\s*(?P<value>[^}]+?)\s*\}")
_MAPPER_ANNOTATION = re.compile(r"@(?P<tag>Select|Insert|Update|Delete)\b", re.IGNORECASE)
_PARAM_ALIAS = re.compile(
    r"@Param\s*\(\s*['\"](?P<alias>[A-Za-z_$][\w$]*)['\"]\s*\)\s*"
    r"(?:final\s+)?(?:[A-Za-z_$][\w$.$<>?,\[\]\s]*\s+)(?P<name>[A-Za-z_$][\w$]*)"
)
_PLACEHOLDER_ROOT = re.compile(r"(?P<root>[A-Za-z_$][\w$]*)(?P<suffix>(?:\s*(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\]))*)")


def augment_java_framework_facts(repo_path: Path, facts: CodeFacts) -> None:
    """Add Spring call-resolution bindings and MyBatis dynamic SQL sinks.

    The augmentation is bounded and entirely local.  A missing source/XML file
    simply reduces framework coverage; it never turns an inferred relationship
    into a finding.
    """

    java_functions = _unique_functions([item for item in facts.functions if item.anchor.file.lower().endswith(".java")])
    if not java_functions:
        return
    class_names = {item.id: item.name for item in facts.classes if item.anchor.file.lower().endswith(".java")}
    class_qualified_names: dict[str, str] = {}
    source_cache: dict[str, list[str]] = {}
    fields_by_class: dict[str, dict[str, str]] = {}
    implementations: dict[str, set[str]] = defaultdict(set)
    for class_fact in facts.classes:
        if not class_fact.anchor.file.lower().endswith(".java"):
            continue
        lines = _read_java_lines(repo_path, class_fact.anchor.file, source_cache)
        if lines is None:
            continue
        class_qualified_names[class_fact.id] = _qualified_java_class_name(lines, class_fact.name)
        fields_by_class[class_fact.id] = _declared_fields(lines, class_fact.anchor.start_line, class_fact.anchor.end_line)
        declaration = "\n".join(lines[class_fact.anchor.start_line - 1 : min(class_fact.anchor.end_line, class_fact.anchor.start_line + 8)])
        match = _IMPLEMENTS.search(declaration)
        if match:
            for interface in _split_implemented_types(match.group("types")):
                implementations[_simple_type(interface)].add(_simple_type(match.group("name")))

    class_receiver_types = _class_receiver_types(fields_by_class)
    local_receiver_types = _local_receiver_types(repo_path, java_functions, source_cache)
    package_names = _java_package_names(repo_path, java_functions, source_cache)
    repo_properties = _load_java_properties(repo_path)
    property_sinks = _property_crypto_hash_sinks(facts, repo_properties, repo_path, source_cache)
    mapper_functions = _mapper_functions(java_functions, class_names, class_qualified_names)
    param_aliases = _parameter_aliases(repo_path, java_functions, source_cache)
    xml_files = _mapper_xml_files(repo_path)
    xml_sinks = _mybatis_sinks(xml_files, mapper_functions, param_aliases)
    annotation_sinks = _mybatis_annotation_sinks(java_functions, source_cache, param_aliases)
    new_sinks = [*xml_sinks, *annotation_sinks, *property_sinks]
    facts.sinks.extend(new_sinks)
    _add_xml_files(facts, repo_path, xml_files)
    diagnostics = facts.analysis_diagnostics.setdefault("java_framework", {})
    diagnostics.update(
        {
            "receiver_types": local_receiver_types,
            "class_receiver_types": class_receiver_types,
            "implementation_types": [
                {"interface": interface, "implementations": sorted(values)} for interface, values in sorted(implementations.items())
            ],
            "package_names": package_names,
            "properties": len(repo_properties),
            "mybatis": {
                "xml_files": len(xml_files),
                "dynamic_sql_sinks": len([*xml_sinks, *annotation_sinks]),
                "annotation_dynamic_sql_sinks": len(annotation_sinks),
                "ignored_bound_parameters": "#{...}",
            },
        }
    )


def _unique_functions(functions: list[FunctionFact]) -> list[FunctionFact]:
    return list({item.id: item for item in functions}.values())


def _read_java_lines(repo_path: Path, relative: str, cache: dict[str, list[str]]) -> list[str] | None:
    if relative in cache:
        return cache[relative]
    path = repo_path / relative
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(repo_path.resolve(strict=True))
        if resolved.stat().st_size > MAX_MAPPER_XML_BYTES:
            return None
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    cache[relative] = lines
    return lines


def _declared_fields(lines: list[str], start_line: int, end_line: int) -> dict[str, str]:
    fields: dict[str, str] = {}
    depth = 0
    for index in range(max(0, start_line - 1), min(len(lines), end_line)):
        text = re.sub(r"//.*$", "", lines[index]).strip()
        if index == start_line - 1:
            depth += text.count("{") - text.count("}")
            continue
        if depth == 1 and "(" not in text and not text.startswith(("return ", "throw ", "new ")):
            match = _FIELD.match(text)
            if match:
                type_name = _simple_type(match.group("type"))
                if type_name and type_name not in {"String", "Object", "Integer", "Long", "Boolean", "int", "long", "boolean"}:
                    fields[match.group("name")] = type_name
        depth += text.count("{") - text.count("}")
    return fields


def _class_receiver_types(fields_by_class: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    """Store injection fields once per declaring class, not once per method."""

    return [
        {"class_id": class_id, "receivers": {name: [type_name] for name, type_name in sorted(fields.items())}}
        for class_id, fields in sorted(fields_by_class.items())
        if fields
    ]


_NON_RECEIVER_TYPES = {
    "boolean",
    "byte",
    "char",
    "double",
    "float",
    "int",
    "long",
    "short",
    "void",
    "String",
    "Object",
    "Integer",
    "Long",
    "Double",
    "Float",
    "Boolean",
    "Character",
    "List",
    "ArrayList",
    "LinkedList",
    "Map",
    "HashMap",
    "Set",
    "HashSet",
    "var",
    "return",
    "throw",
    "new",
    "package",
    "import",
    "case",
    "default",
    "else",
}
_LOCAL_VAR_DECL = re.compile(
    r"^\s*(?:final\s+)?(?P<type>[A-Za-z_$][\w$.]*(?:\s*<[^;=(){}]+>)?(?:\s*\[\s*\])?)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:=|;)"
)
_PARAM_DECL = re.compile(
    r"(?:@[A-Za-z_$][\w$]*(?:\([^)]*\))?\s+)*(?:final\s+)?(?P<type>[A-Za-z_$][\w$.]*(?:\s*<[^>]+>)?)\s+(?P<name>[A-Za-z_$][\w$]*)\s*$"
)
_GET_PROPERTY = re.compile(r"\.getProperty\s*\(\s*\"([^\"]+)\"(?:\s*,\s*\"([^\"]*)\")?\s*\)")


def _local_receiver_types(
    repo_path: Path,
    functions: list[FunctionFact],
    source_cache: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Extract declared parameter and local variable receiver types for Java methods."""
    records: list[dict[str, Any]] = []
    for function in functions:
        lines = _read_java_lines(repo_path, function.anchor.file, source_cache)
        if not lines:
            continue
        found: dict[str, str] = {}
        start = max(0, function.anchor.start_line - 1)
        end = min(len(lines), function.anchor.end_line)
        sig_end = min(end, start + 6)
        sig_text = " ".join(lines[start:sig_end])
        paren_open = sig_text.find("(")
        paren_close = sig_text.find(")", paren_open + 1) if paren_open >= 0 else -1
        if paren_open >= 0 and paren_close > paren_open:
            raw_params = sig_text[paren_open + 1 : paren_close]
            for param_item in raw_params.split(","):
                pm = _PARAM_DECL.match(param_item.strip())
                if pm:
                    tname = _simple_type(pm.group("type"))
                    vname = pm.group("name")
                    if tname and tname not in _NON_RECEIVER_TYPES and vname in function.params:
                        found[vname] = tname
        for idx in range(start, end):
            stripped = re.sub(r"//.*$", "", lines[idx]).strip()
            lm = _LOCAL_VAR_DECL.match(stripped)
            if not lm:
                continue
            tname = _simple_type(lm.group("type"))
            vname = lm.group("name")
            if tname and tname not in _NON_RECEIVER_TYPES:
                found[vname] = tname
        for vname, tname in sorted(found.items()):
            records.append(
                {
                    "file": function.anchor.file,
                    "function_id": function.id,
                    "receiver": vname,
                    "types": [tname],
                    "reason": "typed_receiver",
                }
            )
    return records


def _java_package_names(
    repo_path: Path,
    functions: list[FunctionFact],
    source_cache: dict[str, list[str]],
) -> list[dict[str, str]]:
    seen_files: set[str] = set()
    output: list[dict[str, str]] = []
    for function in functions:
        if function.anchor.file in seen_files:
            continue
        seen_files.add(function.anchor.file)
        lines = _read_java_lines(repo_path, function.anchor.file, source_cache)
        if not lines:
            continue
        pkg = next((m.group(1) for line in lines[:40] if (m := re.match(r"\s*package\s+([\w.]+)\s*;", line))), "")
        if pkg:
            output.append({"file": function.anchor.file, "package": pkg})
    return output


def _load_java_properties(repo_path: Path) -> dict[str, str]:
    """Load key-value entries from bounded Java ``.properties`` resource files."""
    props: dict[str, str] = {}
    root = repo_path.resolve(strict=True)
    count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in sorted(directories) if name not in _SKIPPED_DIRECTORIES]
        for name in sorted(files):
            if count >= 500:
                return props
            if not name.lower().endswith(".properties"):
                continue
            candidate = Path(current) / name
            try:
                if candidate.is_symlink() or candidate.stat().st_size > MAX_MAPPER_XML_BYTES:
                    continue
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
                text = resolved.read_text(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                continue
            count += 1
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith(("#", "!")):
                    continue
                sep = "=" if "=" in line else (":" if ":" in line else "")
                if not sep:
                    continue
                key, value = line.split(sep, 1)
                k = key.strip()
                if k:
                    props[k] = value.strip()
    return props


def _property_crypto_hash_sinks(
    facts: CodeFacts,
    props: dict[str, str],
    repo_path: Path,
    source_cache: dict[str, list[str]],
) -> list[SinkFact]:
    """Resolve ``Properties.getProperty(...)`` arguments reaching ``MessageDigest`` / ``Cipher``."""
    var_props: dict[tuple[str | None, str], tuple[int, str]] = {}
    for flow in facts.data_flows:
        if flow.kind != "assignment" or not flow.target or not flow.anchor.file.lower().endswith(".java"):
            continue
        match = _GET_PROPERTY.search(flow.expression)
        if not match:
            continue
        prop_key = match.group(1)
        default_val = match.group(2) if match.group(2) is not None else ""
        resolved_val = props.get(prop_key, default_val)
        if resolved_val:
            var_props[(flow.enclosing_function_id, flow.target)] = (flow.anchor.start_line, resolved_val)

    existing_sinks = {(normalize_path(s.anchor.file), s.anchor.start_line, s.kind) for s in facts.sinks}
    output: list[SinkFact] = []
    for call in facts.call_sites:
        if not call.anchor.file.lower().endswith(".java"):
            continue
        callee = call.callee.strip()
        is_digest = callee.endswith("MessageDigest.getInstance")
        is_cipher = callee.endswith("Cipher.getInstance")
        if not (is_digest or is_cipher):
            continue
        lines = _read_java_lines(repo_path, call.anchor.file, source_cache)
        snippet = "\n".join(lines[call.anchor.start_line - 1 : call.anchor.end_line]) if lines else callee
        resolved_val = ""
        inline_match = _GET_PROPERTY.search(snippet)
        if inline_match:
            resolved_val = props.get(inline_match.group(1), inline_match.group(2) or "")
        elif call.argument_sources and call.argument_sources[0]:
            arg_var = call.argument_sources[0][0]
            binding = var_props.get((call.enclosing_function_id, arg_var))
            if binding and binding[0] <= call.anchor.start_line:
                resolved_val = binding[1]
        if not resolved_val:
            continue
        if is_digest and _normalize_algo(resolved_val) in _WEAK_HASH_ALGOS:
            kind, vuln_class, taxonomy_id, cwe_ids = "weak_hash", "auth", "weak_cryptography", ["CWE-328", "CWE-327"]
        elif is_cipher and _is_weak_cipher_transform(resolved_val):
            kind, vuln_class, taxonomy_id, cwe_ids = "weak_cipher", "auth", "weak_cryptography", ["CWE-327"]
        else:
            continue
        marker = (normalize_path(call.anchor.file), call.anchor.start_line, kind)
        if marker in existing_sinks:
            continue
        existing_sinks.add(marker)
        output.append(
            SinkFact(
                id=stable_id("sink", call.anchor.file, call.anchor.start_line, f"{kind}:prop:{resolved_val}"),
                kind=kind,
                vuln_class=vuln_class,  # type: ignore[arg-type]
                expression=f"{snippet.strip()} /* property={resolved_val} */",
                anchor=CodeAnchor(
                    file=call.anchor.file,
                    start_line=call.anchor.start_line,
                    end_line=call.anchor.end_line,
                    snippet_hash=sha256_text(snippet),
                    symbol=kind,
                ),
                confidence="high",
                variables=[],
                enclosing_function_id=call.enclosing_function_id,
                analysis_method="heuristic",
                taxonomy_id=taxonomy_id,
                cwe_ids=cwe_ids,
            )
        )
    return output


def _mapper_functions(
    functions: list[FunctionFact],
    class_names: dict[str, str],
    class_qualified_names: dict[str, str],
) -> dict[tuple[str, str], list[FunctionFact]]:
    output: dict[tuple[str, str], list[FunctionFact]] = defaultdict(list)
    for function in functions:
        class_name = class_qualified_names.get(function.class_id or "") or class_names.get(function.class_id or "")
        if class_name:
            output[(class_name, function.name)].append(function)
    return output


def _parameter_aliases(
    repo_path: Path,
    functions: list[FunctionFact],
    source_cache: dict[str, list[str]],
) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for function in functions:
        aliases = {name: name for name in function.params}
        for index, name in enumerate(function.params, 1):
            aliases[f"param{index}"] = name
        if len(function.params) == 1:
            aliases.update(
                {
                    "_parameter": function.params[0],
                    "value": function.params[0],
                    "__single_param__": function.params[0],
                }
            )
        lines = _read_java_lines(repo_path, function.anchor.file, source_cache)
        if lines:
            signature = "\n".join(lines[function.anchor.start_line - 1 : min(len(lines), function.anchor.start_line + 12)])
            for match in _PARAM_ALIAS.finditer(signature):
                if match.group("name") in function.params:
                    aliases[match.group("alias")] = match.group("name")
        output[function.id] = aliases
    return output


def _mapper_xml_files(repo_path: Path) -> list[tuple[str, Path]]:
    output: list[tuple[str, Path]] = []
    root = repo_path.resolve(strict=True)
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in sorted(directories) if name not in _SKIPPED_DIRECTORIES]
        for name in sorted(files):
            if len(output) >= MAX_MAPPER_XML_FILES:
                return output
            if not name.lower().endswith(".xml"):
                continue
            candidate = Path(current) / name
            try:
                if candidate.is_symlink() or candidate.stat().st_size > MAX_MAPPER_XML_BYTES:
                    continue
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
                relative = normalize_path(resolved.relative_to(root))
                with resolved.open("rb") as handle:
                    head = handle.read(8192)
            except (OSError, ValueError):
                continue
            if b"<mapper" in head.lower():
                output.append((relative, resolved))
    return output


def _mybatis_sinks(
    xml_files: list[tuple[str, Path]],
    mapper_functions: dict[tuple[str, str], list[FunctionFact]],
    param_aliases: dict[str, dict[str, str]],
) -> list[SinkFact]:
    output: list[SinkFact] = []
    for relative, xml_file in xml_files:
        try:
            content = xml_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        namespace_match = _MAPPER_NAMESPACE.search(content)
        if not namespace_match:
            continue
        mapper_namespace = namespace_match.group("namespace")
        mapper_name = _simple_type(mapper_namespace)
        fragments = _mapper_fragments(content)
        emitted_sinks: set[tuple[str, str]] = set()
        for statement in _MAPPER_STATEMENT.finditer(content):
            identifier = _STATEMENT_ID.search(statement.group("attrs"))
            if identifier is None:
                continue
            targets = _unique_functions(mapper_functions.get((mapper_namespace, identifier.group("id")), []))
            if not targets:
                # Older/incomplete source trees may omit package declarations.
                # Preserve that compatibility only when the simple mapper name
                # remains unambiguous.
                targets = _unique_functions(mapper_functions.get((mapper_name, identifier.group("id")), []))
            if len(targets) != 1:
                continue
            target = targets[0]
            aliases = param_aliases.get(target.id, {})
            seen: set[tuple[int, str]] = set()
            for body, body_start in _expand_mapper_includes(statement.group("body"), statement.start("body"), fragments):
                for dynamic in _DYNAMIC_PARAMETER.finditer(body):
                    if _is_generated_criterion_condition(body, dynamic.group("value")):
                        continue
                    variable = _placeholder_variable(dynamic.group("value"), aliases)
                    if not variable:
                        continue
                    offset = body_start + dynamic.start()
                    marker = (offset, variable)
                    semantic_marker = (target.id, variable)
                    if marker in seen or semantic_marker in emitted_sinks:
                        continue
                    seen.add(marker)
                    emitted_sinks.add(semantic_marker)
                    line = content.count("\n", 0, offset) + 1
                    line_text = content.splitlines()[line - 1] if line <= len(content.splitlines()) else dynamic.group(0)
                    anchor = CodeAnchor(
                        file=relative,
                        start_line=line,
                        end_line=line,
                        snippet_hash=sha256_text(line_text),
                        symbol=f"{namespace_match.group('namespace')}.{identifier.group('id')}",
                    )
                    output.append(
                        SinkFact(
                            id=stable_id("sink", relative, line, f"mybatis_dynamic_sql:{anchor.symbol}:{variable}"),
                            kind="raw_sql",
                            vuln_class="injection",
                            expression=(
                                f"MyBatis {statement.group('tag').lower()} {anchor.symbol} uses dynamic SQL "
                                f"placeholder ${{{dynamic.group('value').strip()}}}."
                            ),
                            anchor=anchor,
                            confidence="high",
                            variables=[variable],
                            enclosing_function_id=target.id,
                            analysis_method="heuristic",
                            taxonomy_id="sql_injection",
                            cwe_ids=["CWE-89"],
                        )
                    )
    return output


def _placeholder_variable(raw: str, aliases: dict[str, str]) -> str | None:
    match = _PLACEHOLDER_ROOT.match(raw.strip())
    if match is None:
        return None
    root = match.group("root")
    mapped = aliases.get(root)
    if mapped is None:
        single_parameter = aliases.get("__single_param__")
        if single_parameter:
            mapped = f"{single_parameter}.{root}"
        else:
            mapped = root
    suffix = re.sub(r"\s+", "", match.group("suffix"))
    return f"{mapped}{suffix}"


def _mapper_fragments(content: str) -> dict[str, tuple[str, int]]:
    fragments: dict[str, tuple[str, int]] = {}
    for fragment in _MAPPER_FRAGMENT.finditer(content):
        identifier = _STATEMENT_ID.search(fragment.group("attrs"))
        if identifier:
            fragments[identifier.group("id")] = (fragment.group("body"), fragment.start("body"))
    return fragments


def _expand_mapper_includes(
    body: str,
    body_start: int,
    fragments: dict[str, tuple[str, int]],
    visited: tuple[str, ...] = (),
) -> list[tuple[str, int]]:
    """Return a statement body plus its bounded, local ``<include>`` fragments."""

    output = [(body, body_start)]
    for include in _INCLUDE_REF.finditer(body):
        refid = include.group("refid").rsplit(".", 1)[-1]
        if refid in visited or refid not in fragments:
            continue
        fragment, fragment_start = fragments[refid]
        output.extend(_expand_mapper_includes(fragment, fragment_start, fragments, (*visited, refid)))
    return output


def _is_generated_criterion_condition(body: str, placeholder: str) -> bool:
    """Suppress MyBatis Generator's internally constructed criterion syntax.

    ``Example_Where_Clause`` uses ``${criterion.condition}`` for SQL operators,
    but its ``Criterion`` object is built by generated Java methods with fixed
    operator literals. Treating every generated copy as an external SQL sink
    produces hundreds of duplicate, non-actionable paths.  This narrow pattern
    leaves custom ``${...}`` fragments and direct properties (such as an
    ``orderByClause``) visible.
    """

    compact = re.sub(r"\s+", "", placeholder)
    return (
        compact == "criterion.condition"
        and re.search(r"<foreach\b[^>]*\bitem\s*=\s*['\"]criterion['\"]", body, re.IGNORECASE) is not None
        and re.search(r"<when\b[^>]*\btest\s*=\s*['\"]criterion\.(?:noValue|singleValue|betweenValue|listValue)", body, re.IGNORECASE)
        is not None
    )


def _mybatis_annotation_sinks(
    functions: list[FunctionFact],
    source_cache: dict[str, list[str]],
    param_aliases: dict[str, dict[str, str]],
) -> list[SinkFact]:
    """Recognise direct MyBatis annotation SQL without guessing provider output."""

    output: list[SinkFact] = []
    for function in functions:
        lines = source_cache.get(function.anchor.file)
        if lines is None:
            continue
        window_start = max(0, function.anchor.start_line - 13)
        window = "\n".join(lines[window_start : function.anchor.start_line - 1])
        annotations = list(_MAPPER_ANNOTATION.finditer(window))
        if not annotations:
            continue
        annotation = annotations[-1]
        tail = window[annotation.start() :]
        aliases = param_aliases.get(function.id, {})
        for dynamic in _DYNAMIC_PARAMETER.finditer(tail):
            variable = _placeholder_variable(dynamic.group("value"), aliases)
            if not variable:
                continue
            absolute_offset = window_start + window[: annotation.start() + dynamic.start()].count("\n")
            line_number = absolute_offset + 1
            line_text = lines[line_number - 1] if line_number <= len(lines) else dynamic.group(0)
            anchor = CodeAnchor(
                file=function.anchor.file,
                start_line=line_number,
                end_line=line_number,
                snippet_hash=sha256_text(line_text),
                symbol=function.qualified_name or function.name,
            )
            output.append(
                SinkFact(
                    id=stable_id("sink", anchor.file, line_number, f"mybatis_annotation_sql:{anchor.symbol}:{variable}"),
                    kind="raw_sql",
                    vuln_class="injection",
                    expression=(
                        f"MyBatis @{annotation.group('tag')} on {anchor.symbol} uses dynamic SQL "
                        f"placeholder ${{{dynamic.group('value').strip()}}}."
                    ),
                    anchor=anchor,
                    confidence="high",
                    variables=[variable],
                    enclosing_function_id=function.id,
                    analysis_method="heuristic",
                    taxonomy_id="sql_injection",
                    cwe_ids=["CWE-89"],
                )
            )
    return output


def _add_xml_files(facts: CodeFacts, repo_path: Path, xml_files: list[tuple[str, Path]]) -> None:
    known = {item.path for item in facts.files}
    for relative, path in xml_files:
        if relative in known:
            continue
        try:
            stat = path.stat()
            lines = path.read_text(encoding="utf-8", errors="replace").count("\n") + 1
        except OSError:
            continue
        facts.files.append(
            IndexedFile(
                id=stable_id("file", relative, 1, path.name),
                path=relative,
                language="xml",
                bytes=stat.st_size,
                lines=lines,
                parsed_by="heuristic",
            )
        )
        known.add(relative)


def _simple_type(value: str) -> str:
    without_generics = re.sub(r"<.*", "", value).strip()
    return without_generics.rsplit(".", 1)[-1].strip()


def _qualified_java_class_name(lines: list[str], class_name: str) -> str:
    package = next((match.group(1) for line in lines if (match := re.match(r"\s*package\s+([\w.]+)\s*;", line))), "")
    return f"{package}.{class_name}" if package else class_name


def _split_implemented_types(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]
