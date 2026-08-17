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


_JAVA_CLASS = re.compile(r"\b(?:class|interface|record)\s+(?P<name>[A-Za-z_$][\w$]*)")
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


def _collect_java(builder: LanguageFactBuilder) -> list[_JavaMethod]:
    pending: list[tuple[int, str]] = []
    methods: list[_JavaMethod] = []
    class_prefixes: dict[str, str] = {}
    for line_no, raw in enumerate(builder.lines, 1):
        stripped = raw.strip()
        if stripped.startswith("@"):
            pending.append((line_no, stripped))
            continue
        class_match = _JAVA_CLASS.search(stripped)
        if class_match and "{" in stripped:
            end = find_brace_block_end(builder.lines, line_no)
            class_fact = builder.add_class(class_match.group("name"), line_no, end)
            mapping = next((text for _, text in pending if "RequestMapping" in text), "")
            class_prefixes[class_fact.id] = _string_argument(mapping) or ""
            pending = []
            continue
        method_match = _JAVA_METHOD.match(stripped) or _JAVA_METHOD_DECLARATION.match(stripped)
        if method_match and method_match.group("name") not in {"if", "for", "switch", "while", "catch"}:
            end = line_no if _JAVA_METHOD_DECLARATION.match(stripped) else find_brace_block_end(builder.lines, line_no)
            owner = min(
                (item for item in builder.result.classes if item.anchor.start_line <= line_no <= item.anchor.end_line),
                key=lambda item: item.anchor.end_line - item.anchor.start_line,
                default=None,
            )
            name = method_match.group("name")
            function = builder.add_function(
                name,
                line_no,
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
            methods.append(
                _JavaMethod(
                    function,
                    tuple(pending),
                    method_match.group("params"),
                    class_prefixes.get(owner.id, "") if owner else "",
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
    if not match:
        return None
    body = match.group(1) or ""
    method = re.search(r"RequestMethod\.([A-Z]+)", body)
    return method.group(1) if method else "ANY", _string_argument(body) or ""


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
    match = re.match(
        r"(?:(?:final|volatile)\s+)?(?:[A-Za-z_$][\w$<>,.?\[\]]*\s+)?"
        r"(?P<target>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])*)\s*=\s*(?P<expr>.+);$",
        stripped,
    )
    return (match.group("target"), match.group("expr")) if match else None


def _java_sources(builder: LanguageFactBuilder, line_no: int, text: str, function: FunctionFact | None) -> None:
    assigned = _java_assignment(text)
    target = assigned[0] if assigned else None
    patterns = (
        ("http_query", r"\.getParameter(?:Values|Map)?\s*\("),
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


def _java_sinks(builder: LanguageFactBuilder, line_no: int, text: str, function: FunctionFact | None) -> None:
    sql = _sink_arguments(
        text,
        (
            r"\.(?:executeQuery|executeUpdate|execute|addBatch|prepareStatement)\s*\(",
            r"\.(?:createQuery|createNativeQuery)\s*\(",
            r"\b(?:jdbcTemplate|namedParameterJdbcTemplate)\.(?:query|update|execute|batchUpdate)\s*\(",
        ),
    )
    if sql:
        builder.add_sink("raw_sql", text.strip(), line_no, _variables(sql[0]), function=function)

    command = _sink_arguments(text, (r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(", r"new\s+ProcessBuilder\s*\("))
    if command:
        builder.add_sink(
            "command_execution",
            text.strip(),
            line_no,
            dedupe_strings([name for argument in command for name in _variables(argument)]),
            function=function,
        )

    html = _sink_arguments(
        text,
        (
            r"(?:getWriter\s*\(\s*\)\.)?(?:write|print|println)\s*\(",
            r"(?:templateEngine|freemarker|velocityEngine)\.(?:process|mergeTemplate)\s*\(",
        ),
    )
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


def analyze_java(source_file: Any) -> LanguageAnalysisResult:
    builder = LanguageFactBuilder(source_file)
    methods = _collect_java(builder)
    for method in methods:
        for annotation_line, annotation in method.annotations:
            route = _java_route(annotation)
            if route:
                http_method, path = route
                builder.add_route(
                    http_method,
                    _join_route(method.class_prefix, path),
                    annotation_line,
                    "spring",
                    handler=method.function,
                )
        _java_bound_sources(builder, method)

    for line_no, raw in enumerate(builder.lines, 1):
        function = builder.function_for_line(line_no)
        assignment = _java_assignment(raw)
        if assignment:
            target, expression = assignment
            builder.add_assignment(target, _variables(expression), expression, line_no, function=function)
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
        _java_sinks(builder, line_no, raw, function)
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
