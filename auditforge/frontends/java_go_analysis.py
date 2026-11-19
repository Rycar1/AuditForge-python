"""Lightweight semantic frontends for Java and Go web applications.

The frontends intentionally emit the shared language-neutral facts instead of
pretending to be full compilers.  They recognize common framework bindings and
security-sensitive APIs, retain function scope, and leave ``analysis_method`` as
``heuristic`` as required by :mod:`auditforge.language_frontend`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from .language_frontend import (
    LanguageAnalysisResult,
    LanguageFactBuilder,
    dedupe_strings,
    find_brace_block_end,
    split_arguments,
    strip_literals_and_comments,
)
from .models import FunctionFact

_WORD = re.compile(r"[A-Za-z_$][\w$]*")
_ACCESS = re.compile(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^\]\n]+\])*")
_CALL = re.compile(r"\b(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\((?P<args>[^()]*)\)")
_NON_VARIABLES = {
    "boolean",
    "byte",
    "char",
    "class",
    "double",
    "else",
    "error",
    "false",
    "float",
    "for",
    "func",
    "if",
    "int",
    "interface",
    "long",
    "map",
    "new",
    "nil",
    "null",
    "package",
    "return",
    "short",
    "string",
    "struct",
    "switch",
    "this",
    "true",
    "var",
    "void",
}


def _variables(expression: str) -> list[str]:
    clean = strip_literals_and_comments(expression)
    values: list[str] = []
    for match in _ACCESS.finditer(clean):
        value = re.sub(r"\s+", "", match.group(0))
        root = value.split(".", 1)[0].split("[", 1)[0]
        if root.lower() in _NON_VARIABLES:
            continue
        values.append(value)
    return dedupe_strings(values)


def _join_route(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    if not path:
        return prefix or "/"
    return f"/{prefix.strip('/')}/{path.strip('/')}".replace("//", "/")


def _string_argument(text: str) -> str | None:
    match = re.search(r"['\"]([^'\"]+)['\"]", text)
    return match.group(1) if match else None


def _call_arguments(line: str, pattern: str) -> list[str] | None:
    match = re.search(pattern, line, re.IGNORECASE)
    if not match:
        return None
    start = match.end()
    depth = 1
    quote: str | None = None
    escaped = False
    for index in range(start, len(line)):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return split_arguments(line[start:index])
    return None


def _strip_java_comments_per_line(lines: list[str]) -> list[str]:
    """Strip ``//`` and ``/* ... */`` comments while preserving line count and string literals."""

    cleaned: list[str] = []
    in_block = False
    for raw in lines:
        buf: list[str] = []
        quote: str | None = None
        escaped = False
        idx = 0
        length = len(raw)
        while idx < length:
            ch = raw[idx]
            nxt = raw[idx + 1] if idx + 1 < length else ""
            if in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    idx += 2
                    continue
                idx += 1
                continue
            if quote:
                buf.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                idx += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block = True
                idx += 2
                continue
            if ch in {'"', "'"}:
                quote = ch
            buf.append(ch)
            idx += 1
        cleaned.append("".join(buf))
    return cleaned


def _add_calls(builder: LanguageFactBuilder, line_no: int, text: str, function: FunctionFact | None) -> None:
    for match in _CALL.finditer(strip_literals_and_comments(text)):
        name = match.group("name")
        if name.rsplit(".", 1)[-1] in {"if", "for", "switch", "while", "catch"}:
            continue
        args = split_arguments(match.group("args"))
        builder.add_call(name, line_no, [_variables(argument) for argument in args], function=function)


@dataclass(frozen=True)
class _JavaMethod:
    function: FunctionFact
    annotations: tuple[tuple[int, str], ...]
    raw_params: str
    class_prefix: str
    servlet_path: str = ""
    class_is_servlet: bool = False


_JAVA_CLASS = re.compile(r"\b(?:class|interface|record)\s+(?P<name>[A-Za-z_$][\w$]*)(?:\s+extends\s+(?P<extends>[A-Za-z_$][\w$.<>]*))?")
_JAVA_METHOD = re.compile(
    r"^(?P<prefix>(?:(?:public|protected|private|static|final|synchronized|abstract|native|default)\s+)*"
    r"(?:<[^>{}]+>\s*)?[A-Za-z_$][\w$<>,.?\[\]@\s]*)\b(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"\((?P<params>.*)\)\s*(?:throws\s+[^{}]+)?\s*\{\s*$"
)
_JAVA_METHOD_DECLARATION = re.compile(
    r"^(?P<prefix>(?:(?:public|protected|private|static|final|synchronized|abstract|native|default)\s+)*"
    r"(?:<[^>{}]+>\s*)?[A-Za-z_$][\w$<>,.?\[\]@\s]*\s+)\b(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"\((?P<params>.*)\)\s*(?:throws\s+[^;]+)?\s*;\s*$"
)


def _java_params(raw: str) -> list[str]:
    params: list[str] = []
    for item in split_arguments(raw):
        without_annotations = re.sub(r"@[A-Za-z_$][\w$]*(?:\([^)]*\))?", " ", item)
        identifiers = _WORD.findall(without_annotations)
        if identifiers:
            params.append(identifiers[-1])
    return dedupe_strings(params)


def _servlet_route_path(annotations: list[tuple[int, str]], class_name: str) -> tuple[bool, str]:
    for _, text in annotations:
        match = re.search(r"@WebServlet\s*\((?P<body>.*)\)", text, re.IGNORECASE | re.DOTALL)
        if not match:
            if re.search(r"@WebServlet\b", text, re.IGNORECASE):
                return True, f"/{class_name}"
            continue
        body = match.group("body")
        named = re.search(r"(?:value|urlPatterns)\s*=\s*\{?\s*['\"]([^'\"]+)['\"]", body)
        path = named.group(1) if named else (_string_argument(body) or f"/{class_name}")
        return True, path
    return False, ""


def _collect_java(builder: LanguageFactBuilder) -> list[_JavaMethod]:
    pending: list[tuple[int, str]] = []
    annotation_buffer: list[str] = []
    annotation_start = 0
    annotation_depth = 0
    signature_buffer: list[str] = []
    signature_start = 0
    methods: list[_JavaMethod] = []
    class_prefixes: dict[str, str] = {}
    class_servlets: dict[str, tuple[bool, str]] = {}
    for line_no, raw in enumerate(builder.lines, 1):
        stripped = raw.strip()
        if annotation_buffer:
            annotation_buffer.append(stripped)
            annotation_depth += stripped.count("(") - stripped.count(")")
            if annotation_depth <= 0:
                pending.append((annotation_start, " ".join(annotation_buffer)))
                annotation_buffer = []
                annotation_depth = 0
            continue
        if stripped.startswith("@") and not signature_buffer:
            depth = stripped.count("(") - stripped.count(")")
            if depth > 0:
                annotation_buffer = [stripped]
                annotation_start = line_no
                annotation_depth = depth
            else:
                pending.append((line_no, stripped))
            continue
        if not signature_buffer:
            class_match = _JAVA_CLASS.search(stripped)
            if class_match and "{" in stripped:
                end = find_brace_block_end(builder.lines, line_no)
                class_fact = builder.add_class(class_match.group("name"), line_no, end)
                mapping = next((text for _, text in pending if "RequestMapping" in text or "@Path" in text), "")
                class_prefixes[class_fact.id] = _string_argument(mapping) or ""
                is_web_servlet, servlet_path = _servlet_route_path(pending, class_match.group("name"))
                extends_name = (class_match.group("extends") or "").rsplit(".", 1)[-1]
                if is_web_servlet or extends_name == "HttpServlet":
                    class_servlets[class_fact.id] = (True, servlet_path or f"/{class_match.group('name')}")
                pending = []
                continue
        if signature_buffer or (
            re.match(r"^(?:public|protected|private)\s+", stripped)
            and "(" in stripped
            and not stripped.endswith(("{", ";"))
            and "=" not in stripped.split("(", 1)[0]
        ):
            if not signature_buffer:
                signature_start = line_no
            signature_buffer.append(stripped)
            combined_sig = " ".join(signature_buffer)
            if not combined_sig.endswith(("{", ";")):
                if len(signature_buffer) > 8:
                    signature_buffer = []
                    pending = []
                continue
            header_line = signature_start
            stripped_for_method = combined_sig
            signature_buffer = []
        else:
            header_line = line_no
            stripped_for_method = stripped
        is_non_decl_stmt = bool(re.match(r"^(?:new|return|throw|case|else|assert|yield|try|catch|finally|do)\b", stripped_for_method))
        has_assign_before_paren = "(" in stripped_for_method and "=" in stripped_for_method.split("(", 1)[0]
        method_match = (
            None
            if is_non_decl_stmt or has_assign_before_paren
            else (None if ";" in stripped_for_method else _JAVA_METHOD.match(stripped_for_method))
            or _JAVA_METHOD_DECLARATION.match(stripped_for_method)
        )
        if method_match and method_match.group("name") not in {"if", "for", "switch", "while", "catch"}:
            end = header_line if _JAVA_METHOD_DECLARATION.match(stripped_for_method) else find_brace_block_end(builder.lines, line_no)
            owner = min(
                (item for item in builder.result.classes if item.anchor.start_line <= header_line <= item.anchor.end_line),
                key=lambda item: item.anchor.end_line - item.anchor.start_line,
                default=None,
            )
            name = method_match.group("name")
            function = builder.add_function(
                name,
                header_line,
                _java_params(method_match.group("params")),
                end,
                # Keep the function identity compatible with the generic frontend,
                # which is also present during the transition to language packs.
                # The display name can remain class-qualified without splitting
                # source and sink facts into two artificial scopes.
                qualified_name=name,
                class_id=owner.id if owner else None,
            )
            if owner:
                function = replace(function, qualified_name=f"{owner.name}.{name}")
                builder.result.functions[-1] = function
            is_servlet, servlet_path = class_servlets.get(owner.id, (False, "")) if owner else (False, "")
            methods.append(
                _JavaMethod(
                    function,
                    tuple(pending),
                    method_match.group("params"),
                    class_prefixes.get(owner.id, "") if owner else "",
                    servlet_path=servlet_path,
                    class_is_servlet=is_servlet,
                )
            )
            pending = []
            continue
        if stripped and not stripped.startswith(("//", "*")):
            pending = []
    return methods


def _java_route(annotation: str) -> tuple[str, str] | None:
    match = re.search(r"@(Get|Post|Put|Patch|Delete)Mapping\s*(?:\((.*)\))?", annotation, re.IGNORECASE)
    if match:
        return match.group(1).upper(), _string_argument(match.group(2) or "") or ""
    match = re.search(r"@RequestMapping\s*(?:\((.*)\))?", annotation, re.IGNORECASE)
    if match:
        body = match.group(1) or ""
        method = re.search(r"RequestMethod\.([A-Z]+)", body)
        return method.group(1) if method else "ANY", _string_argument(body) or ""
    match = re.search(r"@(GET|POST|PUT|PATCH|DELETE)\b", annotation)
    if match:
        return match.group(1).upper(), ""
    match = re.search(r"@Path\s*\((.*)\)", annotation, re.IGNORECASE)
    if match:
        return "ANY", _string_argument(match.group(1) or "") or ""
    return None


def _java_bound_sources(builder: LanguageFactBuilder, method: _JavaMethod) -> None:
    mapping = {
        "RequestParam": "http_query",
        "PathVariable": "http_path",
        "RequestBody": "http_body",
        "RequestHeader": "http_header",
        "CookieValue": "cookie",
    }
    for raw in split_arguments(method.raw_params):
        variable_candidates = _java_params(raw)
        if not variable_candidates:
            continue
        variable = variable_candidates[-1]
        for annotation, kind in mapping.items():
            if re.search(rf"@{annotation}\b", raw):
                builder.add_source(
                    kind,
                    raw.strip(),
                    method.function.anchor.start_line,
                    [variable],
                    function=method.function,
                )
                break


def _java_assignment(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped.endswith(";") or stripped.startswith(("if ", "for ", "while ", "switch ", "return ")):
        return None
    compound = re.match(
        r"^(?P<target>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])*)\s*\+=\s*(?P<expr>.+);$",
        stripped,
    )
    if compound:
        target = compound.group("target")
        return target, f"{target} + {compound.group('expr')}"
    match = re.match(
        r"(?:(?:final|volatile)\s+)?(?:[A-Za-z_$][\w$.]*(?:\s*<[^;=(){}]+>)?(?:\s*\[\s*\])*\s+)?"
        r"(?P<target>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])*)\s*=\s*(?P<expr>.+);$",
        stripped,
    )
    return (match.group("target"), match.group("expr")) if match else None


def _java_sources(builder: LanguageFactBuilder, line_no: int, text: str, function: FunctionFact | None) -> None:
    assigned = _java_assignment(text)
    target = assigned[0] if assigned else ("@return" if text.strip().startswith("return ") else None)
    patterns = (
        ("http_query", r"\.getParameter(?:Values|Map|Names)?\s*\(|\.getQueryString\s*\("),
        ("http_path", r"\.getPathInfo\s*\(|\.getRequestUR[IL]\s*\("),
        ("http_header", r"\.getHeader(?:s|Names)?\s*\("),
        ("cookie", r"\.getCookies?\s*\("),
        ("http_body", r"\.getInputStream\s*\(|\.getReader\s*\("),
    )
    for kind, pattern in patterns:
        if re.search(pattern, text) and target:
            builder.add_source(kind, text.strip(), line_no, [target], function=function)


def _sink_arguments(text: str, patterns: tuple[str, ...]) -> list[str] | None:
    for pattern in patterns:
        arguments = _call_arguments(text, pattern)
        if arguments is not None:
            return arguments
    return None


def _java_sinks(
    builder: LanguageFactBuilder,
    line_no: int,
    text: str,
    function: FunctionFact | None,
    *,
    response_writers: set[str],
    runtime_vars: set[str],
    pb_vars: set[str],
    file_text_lower: str,
) -> None:
    sql = _sink_arguments(
        text,
        (
            r"\.(?:executeQuery|executeUpdate|execute|executeBatch|executeLargeUpdate|addBatch|prepareStatement|prepareCall)\s*\(",
            r"\.(?:createQuery|createNativeQuery|createCall)\s*\(",
            r"\b(?:jdbcTemplate|namedParameterJdbcTemplate)\.(?:query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|update|execute|batchUpdate)\s*\(",
        ),
    )
    if sql:
        builder.add_sink("raw_sql", text.strip(), line_no, _variables(sql[0]), function=function)

    command = _sink_arguments(
        text,
        (
            r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(",
            r"new\s+ProcessBuilder\s*\(",
            r"\.command\s*\(",
        ),
    )
    if not command:
        for var in runtime_vars:
            command = _call_arguments(text, rf"\b{re.escape(var)}\s*\.exec\s*\(")
            if command:
                break
    if not command:
        for var in pb_vars:
            command = _call_arguments(text, rf"\b{re.escape(var)}\s*\.command\s*\(")
            if command:
                break
    if command:
        builder.add_sink(
            "command_execution",
            text.strip(),
            line_no,
            dedupe_strings([name for argument in command for name in _variables(argument)]),
            function=function,
        )

    file_args = _sink_arguments(
        text,
        (
            r"new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(",
            r"\b(?:Paths\.get|Path\.of|Files\.(?:readAllBytes|readString|write|writeString|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|delete|copy|move))\s*\(",
            r"new\s+FileSystemResource\s*\(",
        ),
    )
    if file_args:
        path_vars = _variables(file_args[0])
        if len(file_args) > 1 and re.search(r"new\s+(?:java\.io\.)?File\s*\(", text):
            path_vars = dedupe_strings([*path_vars, *_variables(file_args[1])])
        if path_vars:
            builder.add_sink("file_path", text.strip(), line_no, path_vars, function=function)

    if "javax.naming" in file_text_lower or "dircontext" in file_text_lower or "ldap" in file_text_lower:
        ldap_args = _sink_arguments(text, (r"\.search\s*\(",))
        if ldap_args:
            ldap_vars = dedupe_strings([name for argument in ldap_args[:2] for name in _variables(argument)])
            if ldap_vars:
                builder.add_sink("ldap_injection", text.strip(), line_no, ldap_vars, function=function)

    if "xpath" in file_text_lower:
        xpath_args = _sink_arguments(text, (r"\b\w*xpath\w*\.(?:evaluate|compile)\s*\(",))
        if xpath_args:
            xpath_vars = _variables(xpath_args[0])
            if xpath_vars:
                builder.add_sink("xpath_injection", text.strip(), line_no, xpath_vars, function=function)

    redirect_args = _sink_arguments(text, (r"\.sendRedirect\s*\(",))
    if redirect_args:
        redirect_vars = _variables(redirect_args[0])
        if redirect_vars:
            builder.add_sink("open_redirect", text.strip(), line_no, redirect_vars, function=function)

    session_args = _sink_arguments(text, (r"(?:getSession\s*\(\s*\)\s*\.|session\.)(?:setAttribute|putValue)\s*\(",))
    if session_args:
        session_vars = dedupe_strings([name for argument in session_args[:2] for name in _variables(argument)])
        if session_vars:
            builder.add_sink("trust_boundary", text.strip(), line_no, session_vars, function=function)

    deser_args = _sink_arguments(text, (r"\.(?:readObject|readUnshared)\s*\(", r"XMLDecoder\s*\("))
    if deser_args is not None:
        deser_vars = dedupe_strings([name for argument in deser_args for name in _variables(argument)]) or _variables(text)
        if deser_vars:
            builder.add_sink("deserialization", text.strip(), line_no, deser_vars, function=function)

    html_patterns = [
        r"\.(?:getWriter|getOutputStream)\s*\(\s*\)\s*\.(?:write|print|println|printf|format|append)\s*\(",
        r"(?:templateEngine|freemarker|velocityEngine)\.(?:process|mergeTemplate)\s*\(",
    ]
    for writer in response_writers:
        html_patterns.append(rf"\b{re.escape(writer)}\s*\.\s*(?:write|print|println|printf|format|append)\s*\(")
    html = None if re.search(r"\bSystem\.(?:out|err)\.", text) else _sink_arguments(text, tuple(html_patterns))
    if html:
        builder.add_sink(
            "html_output",
            text.strip(),
            line_no,
            dedupe_strings([name for argument in html for name in _variables(argument)]),
            confidence="medium",
            function=function,
        )

    external = _sink_arguments(
        text,
        (
            r"\.(?:getForObject|getForEntity|postForObject|postForEntity|exchange|uri)\s*\(",
            r"new\s+URL\s*\(",
            r"URI\.create\s*\(",
        ),
    )
    if external:
        builder.add_sink("external_request", text.strip(), line_no, _variables(external[0]), function=function)
    send = _sink_arguments(text, (r"\.(?:send|execute)\s*\(",))
    if send and re.search(r"(?:httpClient|client)\.", text, re.IGNORECASE):
        builder.add_sink("external_request", text.strip(), line_no, _variables(send[0]), confidence="medium", function=function)


def _java_sanitizers(builder: LanguageFactBuilder, line_no: int, text: str, function: FunctionFact | None) -> None:
    assigned = _java_assignment(text)
    target = assigned[0] if assigned else None
    out_vars = [target] if target else []
    specs: list[tuple[tuple[str, ...], str, list[str]]] = [
        (
            (
                r"\bESAPI\.encoder\(\)\.encodeForHTML(?:Attribute)?\s*\(",
                r"\bESAPI\.encoder\(\)\.encodeForJavaScript\s*\(",
                r"\b(?:HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml\d*|Encode\.forHtml\w*|Utils\.encodeForHTML)\s*\(",
            ),
            "html_escape",
            ["html_output"],
        ),
        ((r"\bESAPI\.encoder\(\)\.encodeForSQL\s*\(",), "sql_escape", ["raw_sql"]),
        ((r"\bESAPI\.encoder\(\)\.encodeForLDAP\s*\(", r"\bESAPI\.encoder\(\)\.encodeForDN\s*\("), "ldap_escape", ["ldap_injection"]),
        ((r"\bESAPI\.encoder\(\)\.encodeForXPath\s*\(",), "xpath_escape", ["xpath_injection"]),
        ((r"\bESAPI\.encoder\(\)\.encodeForOS\s*\(",), "command_escape", ["command_execution"]),
        ((r"\bESAPI\.encoder\(\)\.encodeForURL\s*\(",), "url_escape", ["open_redirect", "external_request"]),
        ((r"\bFilenameUtils\.getName\s*\(",), "path_basename", ["file_path"]),
        (
            (r"\b(?:Integer\.(?:parseInt|valueOf)|Long\.(?:parseLong|valueOf)|Double\.parseDouble|UUID\.fromString)\s*\(",),
            "typed_conversion",
            [
                "raw_sql",
                "command_execution",
                "file_path",
                "html_output",
                "ldap_injection",
                "xpath_injection",
                "open_redirect",
                "external_request",
                "trust_boundary",
            ],
        ),
    ]
    for patterns, kind, sink_kinds in specs:
        args = _sink_arguments(text, patterns)
        if args is None:
            continue
        in_vars = dedupe_strings([name for arg in args for name in _variables(arg)])
        if in_vars:
            builder.add_sanitizer(kind, text.strip(), line_no, out_vars, in_vars, function=function, applies_to=sink_kinds)


def analyze_java(source_file: Any) -> LanguageAnalysisResult:
    builder = LanguageFactBuilder(source_file)
    methods = _collect_java(builder)
    file_text_lower = source_file.content.lower()
    for method in methods:
        has_explicit_route = False
        for annotation_line, annotation in method.annotations:
            route = _java_route(annotation)
            if route:
                has_explicit_route = True
                http_method, path = route
                builder.add_route(
                    http_method,
                    _join_route(method.class_prefix, path),
                    annotation_line,
                    "spring",
                    handler=method.function,
                )
        if (
            not has_explicit_route
            and method.class_is_servlet
            and method.function.name
            in {
                "doGet",
                "doPost",
                "doPut",
                "doDelete",
                "doHead",
                "doOptions",
                "service",
            }
        ):
            http_method = "ANY" if method.function.name == "service" else method.function.name[2:].upper()
            builder.add_route(
                http_method,
                method.servlet_path or f"/{method.function.qualified_name.split('.')[0]}",
                method.function.anchor.start_line,
                "servlet",
                handler=method.function,
            )
        _java_bound_sources(builder, method)

    writers_by_scope: dict[str | None, set[str]] = {}
    runtimes_by_scope: dict[str | None, set[str]] = {}
    pbs_by_scope: dict[str | None, set[str]] = {}
    cleaned_lines = _strip_java_comments_per_line(builder.lines)
    for line_no, raw in enumerate(cleaned_lines, 1):
        if not raw.strip():
            continue
        function = builder.function_for_line(line_no)
        scope_key = function.id if function else None
        assignment = _java_assignment(raw)
        if assignment:
            target, expression = assignment
            if ".getWriter(" in expression or ".getOutputStream(" in expression:
                writers_by_scope.setdefault(scope_key, set()).add(target)
            if "Runtime.getRuntime(" in expression:
                runtimes_by_scope.setdefault(scope_key, set()).add(target)
            if "new ProcessBuilder(" in expression:
                pbs_by_scope.setdefault(scope_key, set()).add(target)
            builder.add_assignment(target, _variables(expression), expression, line_no, function=function)
        enhanced_for = re.match(r"\s*for\s*\(\s*[^:;=]+\b([A-Za-z_$][\w$]*)\s*:\s*([^)]+)\)", raw)
        if enhanced_for:
            loop_var = enhanced_for.group(1)
            iterable_expr = enhanced_for.group(2)
            builder.add_assignment(loop_var, _variables(iterable_expr), raw.strip(), line_no, function=function)
        return_match = re.match(r"\s*return\s+(.+?);\s*$", raw)
        if return_match:
            expression = return_match.group(1)
            builder.add_return(expression, _variables(expression), line_no, function=function)
        control = re.match(r"\s*(if|while|for)\s*\((.*)\)", raw)
        if control:
            builder.add_control(
                "for" if control.group(1) == "for" else control.group(1),
                control.group(2),
                line_no,
                _variables(control.group(2)),
                function=function,
            )
        _java_sources(builder, line_no, raw, function)
        _java_sinks(
            builder,
            line_no,
            raw,
            function,
            response_writers=writers_by_scope.get(scope_key, set()),
            runtime_vars=runtimes_by_scope.get(scope_key, set()),
            pb_vars=pbs_by_scope.get(scope_key, set()),
            file_text_lower=file_text_lower,
        )
        _java_sanitizers(builder, line_no, raw, function)
        _add_calls(builder, line_no, raw, function)
    return builder.result


@dataclass(frozen=True)
class _GoFunction:
    function: FunctionFact
    receiver: str | None


_GO_FUNCTION = re.compile(
    r"^func\s*(?:\(\s*(?P<receiver_name>[A-Za-z_]\w*)\s+\*?(?P<receiver_type>[A-Za-z_]\w*)\s*\)\s*)?"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>.*)\)\s*(?:\([^)]*\)|[^\{]+)?\s*\{\s*$"
)


def _go_params(raw: str) -> list[str]:
    result: list[str] = []
    pending: list[str] = []
    for item in split_arguments(raw):
        tokens = _WORD.findall(item)
        if not tokens:
            continue
        if len(tokens) == 1:
            pending.append(tokens[0])
            continue
        names = [*pending, tokens[0]]
        pending = []
        result.extend(name for name in names if name != "_")
    result.extend(name for name in pending if name != "_")
    return dedupe_strings(result)


def _collect_go(builder: LanguageFactBuilder) -> list[_GoFunction]:
    functions: list[_GoFunction] = []
    for line_no, raw in enumerate(builder.lines, 1):
        match = _GO_FUNCTION.match(raw.strip())
        if not match:
            continue
        end = find_brace_block_end(builder.lines, line_no)
        receiver = match.group("receiver_type")
        name = match.group("name")
        fact = builder.add_function(
            name,
            line_no,
            _go_params(match.group("params")),
            end,
            qualified_name=f"{receiver}.{name}" if receiver else name,
        )
        functions.append(_GoFunction(fact, receiver))
    return functions


def _go_assignment(line: str) -> tuple[list[str], str] | None:
    stripped = strip_literals_and_comments(line).strip().rstrip(";")
    match = re.match(r"(?P<targets>[^=]+?)\s*(?::=|=(?!=))\s*(?P<expr>.+)$", stripped)
    if not match or stripped.startswith(("if ", "for ", "switch ")):
        return None
    targets = [item.strip().lstrip("&*") for item in match.group("targets").split(",")]
    targets = [item for item in targets if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[^\]]+\])*", item) and item != "_"]
    return (targets, match.group("expr")) if targets else None


def _go_routes(builder: LanguageFactBuilder, functions: list[_GoFunction]) -> None:
    by_name = {item.function.name: item.function for item in functions}
    groups: dict[str, str] = {}
    for line_no, raw in enumerate(builder.lines, 1):
        group = re.search(r"\b(?P<alias>[A-Za-z_]\w*)\s*:?=\s*[A-Za-z_]\w*\.Group\(\s*['\"](?P<path>[^'\"]+)", raw)
        if group:
            groups[group.group("alias")] = group.group("path")
        native = re.search(
            r"\b(?:http|[A-Za-z_]\w*)\.HandleFunc\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*(?P<handler>[A-Za-z_]\w*)",
            raw,
        )
        if native:
            path = native.group("path")
            method = "ANY"
            method_path = re.match(r"([A-Z]+)\s+(.+)", path)
            if method_path:
                method, path = method_path.groups()
            builder.add_route(method, path, line_no, "go-net-http", handler=by_name.get(native.group("handler")))
        route = re.search(
            r"\b(?P<router>[A-Za-z_]\w*)\.(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\(\s*"
            r"['\"](?P<path>[^'\"]+)['\"]\s*,\s*(?P<handler>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
            raw,
        )
        if route:
            router = route.group("router")
            framework = "echo" if router in {"e", "echo"} else "gin"
            builder.add_route(
                route.group("method"),
                _join_route(groups.get(router, ""), route.group("path")),
                line_no,
                framework,
                handler=by_name.get(route.group("handler").rsplit(".", 1)[-1]),
            )


def _go_sources(builder: LanguageFactBuilder, line_no: int, text: str, function: FunctionFact | None) -> None:
    assignment = _go_assignment(text)
    targets = assignment[0] if assignment else []
    source_patterns = (
        ("http_query", r"\.URL\.Query\(\)\.Get\s*\(|\.(?:Query|DefaultQuery|QueryParam)\s*\("),
        ("http_body", r"\.(?:FormValue|PostForm|FormValue)\s*\("),
        ("http_path", r"\.(?:Param|PathValue)\s*\("),
        ("http_header", r"\.(?:GetHeader|Header\.Get)\s*\("),
        ("cookie", r"\.Cookie\s*\("),
    )
    for kind, pattern in source_patterns:
        if targets and re.search(pattern, text):
            builder.add_source(kind, text.strip(), line_no, [targets[0]], function=function)
    body = _sink_arguments(
        text,
        (
            r"\.(?:ShouldBindJSON|BindJSON|Bind)\s*\(",
            r"\.Decode\s*\(",
        ),
    )
    if body:
        variables = [name.lstrip("&*") for name in _variables(body[0])]
        if variables:
            builder.add_source("http_body", text.strip(), line_no, variables, function=function)
    if targets and re.search(r"io\.ReadAll\s*\(\s*[A-Za-z_]\w*\.Body", text):
        builder.add_source("http_body", text.strip(), line_no, [targets[0]], function=function)


def _go_sinks(builder: LanguageFactBuilder, line_no: int, text: str, function: FunctionFact | None) -> None:
    sql = _sink_arguments(
        text,
        (
            r"\b(?:db|tx|conn|database|sqlDB|gormDB)\.(?:Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext)\s*\(",
            r"\.(?:Raw|Where)\s*\(",
        ),
    )
    if sql:
        builder.add_sink("raw_sql", text.strip(), line_no, _variables(sql[0]), function=function)

    command = _sink_arguments(text, (r"\bexec\.Command(?:Context)?\s*\(",))
    if command:
        start = 1 if "CommandContext" in text else 0
        builder.add_sink(
            "command_execution",
            text.strip(),
            line_no,
            dedupe_strings([name for argument in command[start:] for name in _variables(argument)]),
            function=function,
        )

    unsafe_template = _sink_arguments(text, (r"\btemplate\.(?:HTML|HTMLAttr|JS|JSStr|URL)\s*\(",))
    if unsafe_template:
        builder.add_sink("html_output", text.strip(), line_no, _variables(unsafe_template[0]), function=function)
    writer = _sink_arguments(text, (r"\.(?:Write|WriteString)\s*\(", r"\bfmt\.Fprintf\s*\("))
    if writer:
        arguments = writer[1:] if re.search(r"fmt\.Fprintf", text) else writer
        builder.add_sink(
            "html_output",
            text.strip(),
            line_no,
            dedupe_strings([name for argument in arguments for name in _variables(argument)]),
            confidence="medium",
            function=function,
        )
    rendered = _sink_arguments(text, (r"\.(?:HTML|HTMLBlob|Execute|ExecuteTemplate)\s*\(",))
    if rendered:
        start = 1 if re.search(r"\.(?:HTML|HTMLBlob|Execute|ExecuteTemplate)\s*\(", text) else 0
        builder.add_sink(
            "html_output",
            text.strip(),
            line_no,
            dedupe_strings([name for argument in rendered[start:] for name in _variables(argument)]),
            confidence="medium",
            function=function,
        )

    external = _sink_arguments(
        text,
        (
            r"\bhttp\.(?:Get|Post|PostForm)\s*\(",
            r"\b(?:client|httpClient|defaultClient)\.(?:Get|Post)\s*\(",
            r"\bhttp\.NewRequest(?:WithContext)?\s*\(",
        ),
    )
    if external:
        if "NewRequestWithContext" in text:
            index = 2
        elif "NewRequest" in text or re.search(r"http\.Post(?:Form)?", text):
            index = 1
        else:
            index = 0
        if index < len(external):
            builder.add_sink("external_request", text.strip(), line_no, _variables(external[index]), function=function)
    do_call = _sink_arguments(text, (r"\.(?:Do|RoundTrip)\s*\(",))
    if do_call:
        builder.add_sink("external_request", text.strip(), line_no, _variables(do_call[0]), confidence="medium", function=function)


def analyze_go(source_file: Any) -> LanguageAnalysisResult:
    builder = LanguageFactBuilder(source_file)
    functions = _collect_go(builder)
    _go_routes(builder, functions)
    for line_no, raw in enumerate(builder.lines, 1):
        function = builder.function_for_line(line_no)
        assignment = _go_assignment(raw)
        if assignment:
            targets, expression = assignment
            for target in targets:
                builder.add_assignment(target, _variables(expression), expression, line_no, function=function)
        return_match = re.match(r"\s*return\s+(.+)$", strip_literals_and_comments(raw))
        if return_match:
            expression = return_match.group(1)
            builder.add_return(expression, _variables(expression), line_no, function=function)
        control = re.match(r"\s*(if|for|switch)\s+(.+?)(?:\{|$)", strip_literals_and_comments(raw))
        if control:
            kind = "if" if control.group(1) == "if" else "for" if control.group(1) == "for" else "switch"
            builder.add_control(kind, control.group(2), line_no, _variables(control.group(2)), function=function)
        _go_sources(builder, line_no, raw, function)
        _go_sinks(builder, line_no, raw, function)
        _add_calls(builder, line_no, raw, function)
    return builder.result


def analyze_java_go(source_file: Any) -> LanguageAnalysisResult:
    language = str(source_file.file.language).lower()
    if language == "java":
        return analyze_java(source_file)
    if language == "go":
        return analyze_go(source_file)
    raise ValueError(f"unsupported Java/Go frontend language: {language}")
