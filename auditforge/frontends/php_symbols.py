"""Repository-level Composer and PHP receiver-type facts.

The PHP frontend intentionally remains dependency-free. This module augments
its syntax facts with deterministic repository context that cannot be derived
from one source file: Composer autoload roots, fully qualified declared types,
constructor injection, and local ``new`` assignments.
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..core.models import ClassFact, CodeFacts, FunctionFact, ImportFact
from ..core.utils import normalize_path
from .language_frontend import split_arguments
from .php_analysis import _logical_php_statements

MAX_COMPOSER_MANIFESTS = 64
MAX_COMPOSER_BYTES = 1024 * 1024
MAX_PHP_SOURCE_BYTES = 4 * 1024 * 1024
_SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".idea",
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
_NAMESPACE = re.compile(r"\bnamespace\s+(?P<name>[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\s*[;{]", re.IGNORECASE)
_PROPERTY = re.compile(
    r"\b(?:(?:public|protected|private|static|readonly|var)\s+)+"
    r"(?P<type>[?\\A-Za-z_][\\A-Za-z0-9_|&?]*)\s+\$(?P<name>[A-Za-z_]\w*)\b",
    re.IGNORECASE,
)
_IMPLEMENTS = re.compile(
    r"\b(?:final\s+|abstract\s+|readonly\s+)*class\s+(?P<name>[A-Za-z_]\w*)\b[^{}]*?\bimplements\s+(?P<types>[^\{]+)",
    re.IGNORECASE | re.DOTALL,
)
_PARAMETER = re.compile(
    r"(?:(?:public|protected|private|readonly)\s+)*"
    r"(?P<type>[?\\A-Za-z_][\\A-Za-z0-9_|&?]*)\s+(?:&\s*)?(?:\.\.\.\s*)?\$(?P<name>[A-Za-z_]\w*)\b",
    re.IGNORECASE,
)
_CONSTRUCTOR_ASSIGNMENT = re.compile(
    r"\$this\s*->\s*(?P<receiver>[A-Za-z_]\w*)\s*=\s*\$(?P<parameter>[A-Za-z_]\w*)\s*;",
    re.IGNORECASE,
)
_NEW_ASSIGNMENT = re.compile(
    r"\$(?P<receiver>[A-Za-z_]\w*)\s*=\s*new\s+(?P<type>\\?[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\s*\(",
    re.IGNORECASE,
)
_CONTAINER_BINDING = re.compile(
    r"(?:\$this\s*->\s*app|\$[A-Za-z_]*(?:app|container)[A-Za-z_]*|\bapp\s*\(\s*\))"
    r"\s*->\s*(?:bind|bindIf|singleton|scoped|instance)\s*\(\s*"
    r"(?P<interface>\\?[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\s*::\s*class\s*,\s*"
    r"(?P<implementation>\\?[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\s*::\s*class",
    re.IGNORECASE,
)
_BUILTIN_TYPES = {
    "array",
    "bool",
    "callable",
    "false",
    "float",
    "int",
    "iterable",
    "mixed",
    "never",
    "null",
    "object",
    "resource",
    "string",
    "true",
    "void",
}


def augment_php_symbol_facts(repo_path: Path, facts: CodeFacts) -> None:
    """Add bounded Composer and typed-receiver context to ``facts``."""

    php_functions = [item for item in facts.functions if _is_php_path(item.anchor.file)]
    php_classes = [item for item in facts.classes if _is_php_path(item.anchor.file)]
    php_files = {item.path for item in facts.files if item.language == "php" or _is_php_path(item.path)}
    if not php_files and not php_functions and not php_classes:
        return

    root = repo_path.resolve(strict=True)
    composer = _composer_diagnostics(root, php_classes)
    imports_by_file = _imports_by_file(facts.imports)
    classes_by_file: dict[str, list[ClassFact]] = defaultdict(list)
    functions_by_file: dict[str, list[FunctionFact]] = defaultdict(list)
    for item in php_classes:
        classes_by_file[item.anchor.file].append(item)
    for item in php_functions:
        functions_by_file[item.anchor.file].append(item)

    receiver_types: dict[tuple[str, str, str], dict[str, Any]] = {}
    class_receivers: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    implementations: dict[str, set[str]] = defaultdict(set)
    container_bindings: dict[str, set[str]] = defaultdict(set)
    errors: list[dict[str, str]] = []
    analysed_files = 0

    for relative in sorted(php_files | set(classes_by_file) | set(functions_by_file)):
        lines, error = _read_php_lines(root, relative)
        if lines is None:
            if error:
                errors.append({"file": relative, "error": error})
            continue
        analysed_files += 1
        content = "\n".join(lines)
        namespace = _namespace(content)
        aliases = imports_by_file.get(relative, {})
        file_classes = classes_by_file.get(relative, [])
        _collect_container_bindings(content, namespace, aliases, container_bindings)

        for class_fact in file_classes:
            class_namespace = _namespace_for_class(class_fact, namespace)
            _collect_declared_properties(lines, class_fact, class_namespace, aliases, class_receivers[class_fact.id])
            _collect_implementations(lines, class_fact, class_namespace, aliases, implementations)

        for function in functions_by_file.get(relative, []):
            owner = next((item for item in file_classes if item.id == function.class_id), None)
            function_namespace = _namespace_for_class(owner, namespace) if owner else namespace
            parameter_text = _function_parameter_text(lines, function)
            parameter_types = _typed_parameters(parameter_text, function_namespace, aliases)
            for receiver, types in parameter_types.items():
                _merge_receiver_entry(
                    receiver_types,
                    relative,
                    function.id,
                    receiver,
                    types,
                    "parameter_type",
                )
            body = "\n".join(lines[function.anchor.start_line - 1 : function.anchor.end_line])
            if owner:
                promoted = _promoted_parameters(parameter_text, function_namespace, aliases)
                for receiver, types in promoted.items():
                    class_receivers[owner.id][receiver].update(types)
                for match in _CONSTRUCTOR_ASSIGNMENT.finditer(body):
                    types = parameter_types.get(match.group("parameter"), [])
                    if types:
                        class_receivers[owner.id][match.group("receiver")].update(types)
            for match in _NEW_ASSIGNMENT.finditer(body):
                types = _resolve_types(match.group("type"), function_namespace, aliases)
                if types:
                    _merge_receiver_entry(
                        receiver_types,
                        relative,
                        function.id,
                        match.group("receiver"),
                        types,
                        "local_new",
                    )

    class_receiver_types = [
        {
            "language": "php",
            "class_id": class_id,
            "receivers": {name: sorted(types) for name, types in sorted(receivers.items()) if types},
            "binding_kind": "declared_or_constructor_type",
        }
        for class_id, receivers in sorted(class_receivers.items())
        if any(receivers.values())
    ]
    implementation_types = []
    for interface in sorted(set(implementations) | set(container_bindings)):
        values = container_bindings.get(interface) or implementations.get(interface, set())
        if values:
            implementation_types.append({"interface": interface, "implementations": sorted(values), "language": "php"})
    diagnostics = facts.analysis_diagnostics.setdefault("php_symbols", {})
    diagnostics.update(
        {
            "schema_version": 1,
            "composer": composer,
            "analysed_files": analysed_files,
            "receiver_types": list(receiver_types.values()),
            "class_receiver_types": class_receiver_types,
            "implementation_types": implementation_types,
            "container_bindings": [
                {"interface": interface, "implementations": sorted(values)}
                for interface, values in sorted(container_bindings.items())
            ],
            "errors": errors[:100],
        }
    )


def _composer_diagnostics(root: Path, classes: list[ClassFact]) -> dict[str, Any]:
    manifests = _composer_manifests(root)
    psr4: list[dict[str, Any]] = []
    classmap: list[dict[str, Any]] = []
    autoload_files: list[dict[str, Any]] = []
    invalid_entries: list[dict[str, str]] = []
    manifest_paths: list[str] = []

    for path in manifests:
        relative = normalize_path(path.relative_to(root))
        manifest_paths.append(relative)
        try:
            if path.stat().st_size > MAX_COMPOSER_BYTES:
                invalid_entries.append({"manifest": relative, "entry": "", "reason": "manifest exceeds size limit"})
                continue
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            invalid_entries.append({"manifest": relative, "entry": "", "reason": f"{type(exc).__name__}: {exc}"})
            continue
        if not isinstance(document, Mapping):
            invalid_entries.append({"manifest": relative, "entry": "", "reason": "manifest root is not an object"})
            continue
        for section_name, is_dev in (("autoload", False), ("autoload-dev", True)):
            section = document.get(section_name)
            if not isinstance(section, Mapping):
                continue
            mapping = section.get("psr-4")
            if isinstance(mapping, Mapping):
                for prefix, values in mapping.items():
                    if not isinstance(prefix, str):
                        continue
                    roots = _composer_paths(root, path.parent, values, relative, f"{section_name}.psr-4.{prefix}", invalid_entries)
                    if roots:
                        psr4.append({"prefix": prefix.lstrip("\\"), "roots": roots, "manifest": relative, "dev": is_dev})
            for key, output in (("classmap", classmap), ("files", autoload_files)):
                for item in _composer_paths(root, path.parent, section.get(key), relative, f"{section_name}.{key}", invalid_entries):
                    output.append({"path": item, "manifest": relative, "dev": is_dev})

    matched_classes = 0
    unmatched_classes: list[str] = []
    for item in classes:
        qualified = (item.qualified_name or item.name).lstrip("\\")
        file_path = item.anchor.file.replace("\\", "/")
        matches = [entry for entry in psr4 if qualified.startswith(str(entry["prefix"])) and _under_any_root(file_path, entry["roots"])]
        if matches:
            matched_classes += 1
        elif psr4:
            unmatched_classes.append(qualified)

    return {
        "manifests": manifest_paths,
        "psr4": psr4,
        "classmap": classmap,
        "files": autoload_files,
        "matched_classes": matched_classes,
        "unmatched_classes": sorted(set(unmatched_classes))[:200],
        "invalid_entries": invalid_entries[:100],
        "truncated": len(manifests) >= MAX_COMPOSER_MANIFESTS,
    }


def _composer_manifests(root: Path) -> list[Path]:
    output: list[Path] = []
    for current, directories, files in os.walk(root):
        directories[:] = sorted(item for item in directories if item not in _SKIPPED_DIRECTORIES)
        if "composer.json" in files:
            candidate = Path(current) / "composer.json"
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            output.append(resolved)
            if len(output) >= MAX_COMPOSER_MANIFESTS:
                break
    return output


def _composer_paths(
    root: Path,
    manifest_dir: Path,
    value: Any,
    manifest: str,
    entry: str,
    errors: list[dict[str, str]],
) -> list[str]:
    values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    output: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            errors.append({"manifest": manifest, "entry": entry, "reason": "autoload path is not a non-empty string"})
            continue
        try:
            candidate = (manifest_dir / item).resolve(strict=False)
            relative = normalize_path(candidate.relative_to(root)) or "."
        except ValueError:
            errors.append({"manifest": manifest, "entry": item, "reason": "autoload path escapes repository"})
            continue
        if relative not in output:
            output.append(relative)
    return output


def _read_php_lines(root: Path, relative: str) -> tuple[list[str] | None, str | None]:
    try:
        path = (root / relative).resolve(strict=True)
        path.relative_to(root)
        if path.stat().st_size > MAX_PHP_SOURCE_BYTES:
            return None, "source exceeds PHP symbol size limit"
        return path.read_text(encoding="utf-8", errors="replace").splitlines(), None
    except (OSError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _imports_by_file(imports: list[ImportFact]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = defaultdict(dict)
    for item in imports:
        if not _is_php_path(item.anchor.file):
            continue
        for alias in item.aliases:
            output[item.anchor.file][alias] = item.module.lstrip("\\")
    return output


def _collect_declared_properties(
    lines: list[str],
    class_fact: ClassFact,
    namespace: str,
    aliases: Mapping[str, str],
    output: dict[str, set[str]],
) -> None:
    for line, statement in _logical_php_statements(lines):
        if not class_fact.anchor.start_line <= line <= class_fact.anchor.end_line or re.search(r"\bfunction\b", statement, re.IGNORECASE):
            continue
        for match in _PROPERTY.finditer(statement):
            types = _resolve_types(match.group("type"), namespace, aliases)
            if types:
                output[match.group("name")].update(types)


def _collect_implementations(
    lines: list[str],
    class_fact: ClassFact,
    namespace: str,
    aliases: Mapping[str, str],
    output: dict[str, set[str]],
) -> None:
    declaration = "\n".join(lines[class_fact.anchor.start_line - 1 : min(len(lines), class_fact.anchor.start_line + 32)])
    match = _IMPLEMENTS.search(declaration)
    if not match or match.group("name") != class_fact.name:
        return
    implementation = (class_fact.qualified_name or class_fact.name).lstrip("\\")
    for raw in split_arguments(match.group("types")):
        for interface in _resolve_types(raw, namespace, aliases):
            output[interface].add(implementation)


def _collect_container_bindings(
    content: str,
    namespace: str,
    aliases: Mapping[str, str],
    output: dict[str, set[str]],
) -> None:
    for match in _CONTAINER_BINDING.finditer(content):
        interfaces = _resolve_types(match.group("interface"), namespace, aliases)
        implementations = _resolve_types(match.group("implementation"), namespace, aliases)
        for interface in interfaces:
            output[interface].update(implementations)


def _function_parameter_text(lines: list[str], function: FunctionFact) -> str:
    window = "\n".join(lines[function.anchor.start_line - 1 : min(len(lines), function.anchor.start_line + 64)])
    match = re.search(rf"\bfunction\s+&?\s*{re.escape(function.name)}\s*\(", window, re.IGNORECASE)
    if not match:
        return ""
    opening = window.find("(", match.start())
    return _balanced_parentheses(window, opening)


def _balanced_parentheses(value: str, opening: int) -> str:
    if opening < 0:
        return ""
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(value)):
        char = value[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return value[opening + 1 : index]
    return value[opening + 1 :]


def _typed_parameters(value: str, namespace: str, aliases: Mapping[str, str]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for item in split_arguments(value):
        clean = re.sub(r"#\[.*?]\s*", "", item, flags=re.DOTALL)
        match = _PARAMETER.search(clean)
        if not match:
            continue
        types = _resolve_types(match.group("type"), namespace, aliases)
        if types:
            output[match.group("name")] = types
    return output


def _promoted_parameters(value: str, namespace: str, aliases: Mapping[str, str]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for item in split_arguments(value):
        if not re.search(r"\b(?:public|protected|private)\b", item, re.IGNORECASE):
            continue
        output.update(_typed_parameters(item, namespace, aliases))
    return output


def _resolve_types(raw: str, namespace: str, aliases: Mapping[str, str]) -> list[str]:
    output: list[str] = []
    for item in re.split(r"[|&]", raw):
        name = item.strip().strip("()?")
        if not name or name.lower() in _BUILTIN_TYPES:
            continue
        if name.lower() in {"self", "static", "parent"}:
            continue
        absolute = name.startswith("\\")
        name = name.lstrip("\\")
        first, separator, suffix = name.partition("\\")
        if first in aliases:
            resolved = aliases[first] + (f"\\{suffix}" if separator and suffix else "")
        elif absolute or not namespace:
            resolved = name
        else:
            resolved = f"{namespace}\\{name}"
        if resolved and resolved not in output:
            output.append(resolved)
    return output


def _merge_receiver_entry(
    output: dict[tuple[str, str, str], dict[str, Any]],
    file: str,
    function_id: str,
    receiver: str,
    types: list[str],
    binding_kind: str,
) -> None:
    key = (file, function_id, receiver)
    entry = output.setdefault(
        key,
        {
            "language": "php",
            "file": file,
            "function_id": function_id,
            "receiver": receiver,
            "types": [],
            "binding_kind": binding_kind,
        },
    )
    entry["types"] = sorted(set(entry["types"]) | set(types))


def _namespace(content: str) -> str:
    match = _NAMESPACE.search(content)
    return match.group("name").lstrip("\\") if match else ""


def _namespace_for_class(class_fact: ClassFact | None, fallback: str) -> str:
    if class_fact and class_fact.qualified_name and "\\" in class_fact.qualified_name:
        return class_fact.qualified_name.rsplit("\\", 1)[0]
    return fallback


def _under_any_root(file_path: str, roots: Any) -> bool:
    if not isinstance(roots, list):
        return False
    normalized = file_path.strip("/")
    return any(root == "." or normalized == str(root).strip("/") or normalized.startswith(f"{str(root).strip('/')}/") for root in roots)


def _is_php_path(path: str) -> bool:
    return path.lower().endswith((".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8"))
