"""Lightweight JavaScript/TypeScript semantic frontend without a grammar.

This module deliberately uses balanced-delimiter and line-oriented heuristics so
AuditForge can emit structured language-neutral facts without requiring Node or
a tree-sitter runtime.  Every emitted fact remains ``analysis_method=heuristic``;
callers must not treat this frontend as an AST parser.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from .language_frontend import (
    LanguageAnalysisResult,
    LanguageFactBuilder,
    extract_variables,
    find_brace_block_end,
    parse_parameters,
    split_arguments,
    strip_literals_and_comments,
)

FUNCTION_DECLARATION = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\((.*?)\)")
ARROW_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)"
    r"(?:\s*:[^=]+)?\s*=\s*(?:async\s*)?(?:\((.*?)\)|([A-Za-z_$][\w$]*))\s*(?:\:[^=]+)?=>"
)
CLASS_DECLARATION = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)")
METHOD_DECLARATION = re.compile(
    r"^\s*(?:(?:public|private|protected|static|readonly|override|abstract)\s+)*(?:async\s+)?"
    r"([A-Za-z_$][\w$]*)\s*(?:<[^>{}]+>)?\s*\((.*?)\)\s*(?:\:[^{=]+)?\s*\{"
)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "all", "use"}
ROUTE_CALL = re.compile(
    r"\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|options|head|all|use)\s*\(\s*(['\"`])([^'\"`]+)\3",
    re.I,
)
NEST_ROUTE = re.compile(r"^\s*@(Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(\s*(?:['\"`]([^'\"`]*)['\"`])?", re.I)
NEST_CONTROLLER = re.compile(r"^\s*@Controller\s*\(\s*(?:['\"`]([^'\"`]*)['\"`])?", re.I)
NEXT_HTTP_FUNCTIONS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

SQL_CALLEES = (
    ".query",
    ".execute",
    ".raw",
    ".$queryraw",
    ".$queryrawunsafe",
    ".$executeraw",
    ".$executerawunsafe",
)
COMMAND_CALLEES = {
    "exec",
    "execsync",
    "child_process.exec",
    "child_process.execsync",
    "childprocess.exec",
    "spawn",
    "spawnsync",
    "execa",
}
FILE_CALLEE_SUFFIXES = (
    "fs.readfile",
    "fs.readfilesync",
    "fs.writefile",
    "fs.writefilesync",
    "fs.createreadstream",
    "fs.createwritestream",
    "fs.unlink",
    "fs.rename",
    "sendfile",
    "download",
)
DESERIALIZATION_CALLEES = {
    "deserialize",
    "unserialize",
    "yaml.load",
    "jsyaml.load",
    "serialize.unserialize",
    "node_serialize.unserialize",
}
CODE_EVALUATION_CALLEES = {
    "eval",
    "vm.runinnewcontext",
    "vm.runinthiscontext",
}
SSRF_CALLEES = {
    "fetch",
    "axios",
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.request",
    "http.get",
    "http.request",
    "https.get",
    "https.request",
    "got",
    "got.get",
    "request",
    "undici.request",
}
XSS_CALLEE_SUFFIXES = (".send", ".write", ".end", "document.write", "render")
HTML_SANITIZERS = ("dompurify.sanitize", "sanitizehtml", "escapehtml", "he.encode", "encodeforhtml")
TYPE_SANITIZERS = ("parseint", "parsefloat", "number", "zod.parse", ".safeparse", "joi.validate")
PATH_SANITIZERS = ("path.basename", "path.normalize", "path.resolve")
URL_SANITIZERS = ("isallowedurl", "validateurl", "isallowedhost", "isurl")
TEMPLATE_COMPILATION_CALLEES = {"_.template", "lodash.template", "lodash_template"}
PROTOTYPE_MUTATION_CALLEES = {"_.merge", "_.defaultsdeep", "lodash.merge", "lodash.defaultsdeep", "deepmerge"}


def analyze_javascript_typescript(source_file: Any) -> LanguageAnalysisResult:
    """Return heuristic semantic facts for JS/TS/JSX/TSX source."""

    builder = LanguageFactBuilder(source_file)
    _discover_classes(builder)
    _discover_functions(builder)
    _discover_routes(builder)
    for line_no, raw_line in enumerate(builder.lines, 1):
        line = strip_literals_and_comments(raw_line).strip()
        if not line:
            continue
        function = builder.function_for_line(line_no)
        targets, right_hand_side = assignment_parts(raw_line)
        _add_sources(builder, raw_line, line_no, targets, function)
        _add_sinks_and_sanitizers(builder, raw_line, line_no, targets, function)
        if targets and right_hand_side:
            sources = js_variables(right_hand_side)
            for target in targets:
                builder.add_assignment(target, sources, right_hand_side.strip(), line_no, function=function)
        return_match = re.search(r"\breturn\s+(.+?)(?:;|$)", raw_line)
        if return_match:
            expression = return_match.group(1).strip()
            builder.add_return(expression, js_variables(expression), line_no, function=function)
        _add_calls(builder, raw_line, line_no, function)
        _add_control(builder, raw_line, line_no, function)
    return builder.result


# Friendly aliases for direct language-pack callers.
analyze_javascript = analyze_javascript_typescript
analyze_typescript = analyze_javascript_typescript


def _discover_classes(builder: LanguageFactBuilder) -> None:
    for line_no, line in enumerate(builder.lines, 1):
        match = CLASS_DECLARATION.match(strip_literals_and_comments(line))
        if match:
            builder.add_class(match.group(1), line_no, find_brace_block_end(builder.lines, line_no))


def _discover_functions(builder: LanguageFactBuilder) -> None:
    seen: set[tuple[str, int]] = set()
    for line_no, raw_line in enumerate(builder.lines, 1):
        clean = strip_literals_and_comments(raw_line)
        match = FUNCTION_DECLARATION.match(clean)
        if match:
            _add_function(builder, match.group(1), match.group(2), line_no, seen)
            continue
        match = ARROW_ASSIGNMENT.match(clean)
        if match:
            _add_function(builder, match.group(1), match.group(2) or match.group(3) or "", line_no, seen)
            continue
        class_fact = next(
            (item for item in builder.result.classes if item.anchor.start_line < line_no <= item.anchor.end_line),
            None,
        )
        if class_fact is None:
            continue
        signature = parse_method_signature(raw_line)
        if not signature or signature[0] in {"if", "for", "while", "switch", "catch", "constructor"}:
            continue
        name, raw_params = signature
        key = (f"{class_fact.name}.{name}", line_no)
        if key in seen:
            continue
        seen.add(key)
        builder.add_function(
            name,
            line_no,
            parse_js_parameters(raw_params),
            find_brace_block_end(builder.lines, line_no),
            qualified_name=f"{class_fact.name}.{name}",
            class_id=class_fact.id,
        )


def _add_function(builder: LanguageFactBuilder, name: str, raw_params: str, line_no: int, seen: set[tuple[str, int]]) -> None:
    key = (name, line_no)
    if key in seen:
        return
    seen.add(key)
    clean = strip_literals_and_comments(builder.lines[line_no - 1])
    end_line = find_brace_block_end(builder.lines, line_no) if "{" in clean else line_no
    builder.add_function(name, line_no, parse_js_parameters(raw_params), end_line)


def _discover_routes(builder: LanguageFactBuilder) -> None:
    content_lower = "\n".join(builder.lines).lower()
    functions_by_name = {item.name: item for item in builder.result.functions}
    for line_no, raw_line in enumerate(builder.lines, 1):
        if raw_line.lstrip().startswith("//"):
            continue
        clean = strip_literals_and_comments(raw_line)
        for match in ROUTE_CALL.finditer(raw_line):
            receiver, method, path = match.group(1), match.group(2).lower(), match.group(4)
            framework = "koa" if "koa" in content_lower or "ctx" in clean else "express"
            tail = raw_line[match.end() :]
            handler = None
            named = re.search(r",\s*([A-Za-z_$][\w$]*)\s*\)?\s*;?\s*$", tail)
            if named:
                handler = functions_by_name.get(named.group(1))
            arrow = re.search(r",\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{", tail)
            if handler is None and arrow:
                synthetic = f"route_{receiver}_{method}_{line_no}"
                handler = builder.add_function(
                    synthetic,
                    line_no,
                    parse_js_parameters(arrow.group(1)),
                    find_brace_block_end(builder.lines, line_no),
                )
                functions_by_name[synthetic] = handler
            builder.add_route(method.upper(), path, line_no, framework, handler=handler)

        nest = NEST_ROUTE.match(raw_line)
        if nest:
            handler = next(
                (item for item in builder.result.functions if line_no < item.anchor.start_line <= line_no + 8),
                None,
            )
            prefix = _nest_controller_prefix(builder, line_no)
            path = join_route_path(prefix, nest.group(2) or "")
            builder.add_route(nest.group(1).upper(), path, line_no, "nestjs", handler=handler)

    for function in builder.result.functions:
        if function.name in NEXT_HTTP_FUNCTIONS:
            builder.add_route(function.name, next_route_path(builder.path), function.anchor.start_line, "nextjs", handler=function)
        elif function.name == "handler" and re.search(r"(?:pages|app)/api/", builder.path.replace("\\", "/")):
            builder.add_route("ANY", next_route_path(builder.path), function.anchor.start_line, "nextjs", handler=function)


def _nest_controller_prefix(builder: LanguageFactBuilder, route_line: int) -> str:
    class_fact = next(
        (item for item in builder.result.classes if item.anchor.start_line <= route_line <= item.anchor.end_line),
        None,
    )
    if class_fact is None:
        return ""
    for line_no in range(max(1, class_fact.anchor.start_line - 8), class_fact.anchor.start_line + 1):
        match = NEST_CONTROLLER.match(builder.lines[line_no - 1])
        if match:
            return match.group(1) or ""
    return ""


def join_route_path(prefix: str, suffix: str) -> str:
    parts = [part.strip("/") for part in (prefix, suffix) if part.strip("/")]
    return "/" + "/".join(parts) if parts else "/"


def next_route_path(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")
    parts = normalized.split("/")
    if "app" in parts and parts[-1].startswith("route."):
        parts = parts[parts.index("app") + 1 : -1]
    elif "pages" in parts:
        parts = parts[parts.index("pages") + 1 :]
        parts[-1] = parts[-1].rsplit(".", 1)[0]
        if parts[-1] == "index":
            parts.pop()
    else:
        parts = [parts[-1].rsplit(".", 1)[0]]
    return "/" + "/".join(re.sub(r"^\[([^]]+)\]$", r":\1", part) for part in parts)


def _add_sources(builder: LanguageFactBuilder, line: str, line_no: int, targets: list[str], function: Any) -> None:
    source_patterns = [
        ("http_path", r"\b(?:req|request|ctx)\.(?:params|param)(?:\.[A-Za-z_$][\w$]*|\[[^]]+\])?"),
        ("http_query", r"\b(?:req|request|ctx)\.(?:query|querystring)(?:\.[A-Za-z_$][\w$]*|\[[^]]+\])?"),
        ("http_body", r"\b(?:req|request)\.body(?:\.[A-Za-z_$][\w$]*|\[[^]]+\])?|\bctx\.request\.body(?:\.[A-Za-z_$][\w$]*)?"),
        ("http_header", r"\b(?:req|request|ctx)\.(?:headers?|header)(?:\.[A-Za-z_$][\w$]*|\[[^]]+\])?"),
        ("http_cookie", r"\b(?:req|request|ctx)\.cookies?(?:\.[A-Za-z_$][\w$]*|\[[^]]+\])?"),
        ("http_file", r"\b(?:req|request)\.files?(?:\.[A-Za-z_$][\w$]*|\[[^]]+\])?"),
        ("http_query", r"\b(?:request|req)\.nextUrl\.searchParams\.(?:get|getAll)\s*\([^)]*\)"),
        ("http_body", r"\b(?:request|req)\.(?:json|formData)\s*\(\s*\)"),
        ("http_header", r"\b(?:request|req)\.headers\.get\s*\([^)]*\)"),
        ("http_cookie", r"\b(?:request|req)\.cookies\.get\s*\([^)]*\)"),
        # Browser-controlled values are first-class DOM taint sources. These
        # patterns also apply when JavaScript is embedded in a PHP/HTML script
        # block and retains its original source anchors.
        (
            "browser_location",
            r"\b(?:(?:window|document)\.location|location)(?:\.(?:href|search|hash|pathname|host|hostname))?\b",
        ),
        ("browser_url", r"\bdocument\.(?:URL|documentURI|baseURI|referrer)\b"),
        ("browser_state", r"\bwindow\.name\b|\b(?:localStorage|sessionStorage)\.getItem\s*\([^)]*\)"),
        ("browser_query", r"\bURLSearchParams\s*\([^)]*\)\.get(?:All)?\s*\([^)]*\)"),
    ]
    seen: set[tuple[str, str]] = set()
    for kind, pattern in source_patterns:
        for match in re.finditer(pattern, line, re.I):
            expression = match.group(0)
            key = (kind, expression)
            if key in seen:
                continue
            seen.add(key)
            builder.add_source(kind, expression, line_no, [*targets, *js_variables(expression)], function=function)
    nest_sources = {
        "Param": "http_path",
        "Query": "http_query",
        "Body": "http_body",
        "Headers": "http_header",
        "Req": "http_request",
        "Request": "http_request",
        "UploadedFile": "http_file",
        "UploadedFiles": "http_file",
    }
    for match in re.finditer(r"@(Param|Query|Body|Headers|Req|Request|UploadedFiles?)\s*\([^)]*\)\s*([A-Za-z_$][\w$]*)", line):
        builder.add_source(nest_sources[match.group(1)], match.group(0), line_no, [match.group(2)], function=function)


def _add_sinks_and_sanitizers(
    builder: LanguageFactBuilder,
    line: str,
    line_no: int,
    targets: list[str],
    function: Any,
) -> None:
    calls = list(iter_calls(line))
    for callee, arguments, raw_call in calls:
        lowered = callee.lower()
        variables = [name for argument in arguments for name in js_variables(argument)]
        if is_sql_call(lowered, arguments):
            confidence = "high" if unsafe_string_construction(arguments[0] if arguments else "") or "unsafe" in lowered else "medium"
            builder.add_sink("raw_sql", raw_call, line_no, variables, confidence=confidence, function=function)
            if is_proven_parameterized_query(arguments):
                builder.add_sanitizer(
                    "parameterized_query",
                    raw_call,
                    line_no,
                    variables,
                    variables,
                    ["raw_sql"],
                    confidence="high",
                    function=function,
                )
        if lowered in COMMAND_CALLEES or any(lowered.endswith(f".{name}") for name in COMMAND_CALLEES):
            builder.add_sink("command_execution", raw_call, line_no, variables, function=function)
        if any(lowered.endswith(suffix) for suffix in FILE_CALLEE_SUFFIXES):
            builder.add_sink("file_path", raw_call, line_no, variables, function=function)
        if lowered in DESERIALIZATION_CALLEES or any(lowered.endswith(f".{name}") for name in DESERIALIZATION_CALLEES):
            builder.add_sink("deserialization", raw_call, line_no, variables, function=function)
        if lowered in CODE_EVALUATION_CALLEES or any(lowered.endswith(f".{name}") for name in CODE_EVALUATION_CALLEES):
            builder.add_sink("code_evaluation", raw_call, line_no, variables, function=function)
        if lowered in SSRF_CALLEES:
            builder.add_sink("external_request", raw_call, line_no, variables, function=function)
        if lowered in TEMPLATE_COMPILATION_CALLEES:
            builder.add_sink("template_compilation", raw_call, line_no, variables, function=function)
        if lowered in PROTOTYPE_MUTATION_CALLEES:
            builder.add_sink("prototype_mutation", raw_call, line_no, variables, confidence="medium", function=function)
        if (
            any(lowered.endswith(suffix) for suffix in XSS_CALLEE_SUFFIXES)
            and lowered not in {"res.json", "response.json"}
            and is_html_output_call(lowered, arguments)
        ):
            builder.add_sink("html_output", raw_call, line_no, variables, confidence="medium", function=function)

        applies_to: list[str] = []
        sanitizer_kind = ""
        if any(token in lowered for token in HTML_SANITIZERS):
            sanitizer_kind, applies_to = "html_escape", ["html_output"]
        elif any(token in lowered for token in TYPE_SANITIZERS):
            sanitizer_kind, applies_to = "type_validation", ["raw_sql", "command_execution", "file_path", "external_request"]
        elif any(token in lowered for token in PATH_SANITIZERS):
            sanitizer_kind, applies_to = "path_normalization", ["file_path"]
        elif any(token in lowered for token in URL_SANITIZERS):
            sanitizer_kind, applies_to = "url_allowlist", ["external_request"]
        if sanitizer_kind:
            builder.add_sanitizer(
                sanitizer_kind,
                raw_call,
                line_no,
                targets or variables,
                variables,
                applies_to,
                function=function,
            )

    if re.search(r"\.(?:innerHTML|outerHTML)\s*=", line) or "dangerouslySetInnerHTML" in line:
        builder.add_sink("html_output", line.strip(), line_no, js_variables(line), function=function)
    elif re.search(r"\bctx\.body\s*=", line):
        builder.add_sink("html_output", line.strip(), line_no, js_variables(line), confidence="medium", function=function)


def _add_calls(builder: LanguageFactBuilder, line: str, line_no: int, function: Any) -> None:
    if line.lstrip().startswith("@"):
        return
    declaration = FUNCTION_DECLARATION.match(strip_literals_and_comments(line))
    method_signature = parse_method_signature(line)
    declared_name = declaration.group(1) if declaration else method_signature[0] if method_signature else None
    for callee, arguments, _ in iter_calls(line):
        if callee == declared_name:
            continue
        builder.add_call(callee, line_no, [js_variables(argument) for argument in arguments], function=function)


def _add_control(builder: LanguageFactBuilder, line: str, line_no: int, function: Any) -> None:
    clean = strip_literals_and_comments(line)
    patterns = [
        ("elif", r"\belse\s+if\s*\((.*?)\)"),
        ("if", r"\bif\s*\((.*?)\)"),
        ("for", r"\bfor\s*\((.*?)\)"),
        ("while", r"\bwhile\s*\((.*?)\)"),
        ("switch", r"\bswitch\s*\((.*?)\)"),
        ("catch", r"\bcatch\s*\((.*?)\)"),
    ]
    for kind, pattern in patterns:
        match = re.search(pattern, clean)
        if match:
            builder.add_control(kind, match.group(1), line_no, js_variables(match.group(1)), function=function)
            return


def assignment_parts(line: str) -> tuple[list[str], str | None]:
    clean = re.sub(r"//.*$", "", line)
    if re.match(r"^\s*(?:if|for|while|switch|return|function|class)\b", clean) or re.search(r"===|!==|==|!=|>=|<=", clean):
        return [], None
    match = re.match(r"^\s*(?:(?:const|let|var)\s+)?(.+?)\s*=\s*(?!=|>)(.+?)(?:;)?\s*$", clean)
    if not match or "=>" in match.group(1) or "=>" in match.group(2):
        return [], None
    raw_target, expression = match.group(1).strip(), match.group(2).strip()
    raw_target = re.sub(r"\s*:[^,}\]]+(?=,|}|]|$)", "", raw_target)
    if raw_target.startswith(("{", "[")):
        targets = [name for name in re.findall(r"[A-Za-z_$][\w$]*", raw_target) if name not in {"const", "let", "var"}]
    else:
        target_match = re.match(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^]]+\])*)", raw_target)
        targets = [target_match.group(1)] if target_match else []
    return list(dict.fromkeys(targets)), expression


def parse_method_signature(line: str) -> tuple[str, str] | None:
    masked = mask_js_literals_and_comments(line)
    match = re.match(
        r"^\s*(?:(?:public|private|protected|static|readonly|override|abstract)\s+)*(?:async\s+)?"
        r"([A-Za-z_$][\w$]*)\s*(?:<[^>{}]+>)?\s*\(",
        masked,
    )
    if not match:
        return None
    open_index = masked.find("(", match.start())
    close_index = matching_parenthesis(masked, open_index)
    if close_index < 0 or "{" not in masked[close_index + 1 :]:
        return None
    return match.group(1), line[open_index + 1 : close_index]


def parse_js_parameters(raw: str) -> list[str]:
    cleaned = re.sub(r"@[A-Za-z_$][\w$]*(?:\([^)]*\))?\s*", "", raw)
    return parse_parameters(cleaned)


def iter_calls(line: str) -> Iterator[tuple[str, list[str], str]]:
    clean = mask_js_literals_and_comments(line)
    pattern = re.compile(r"\b([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*)\s*\(")
    for match in pattern.finditer(clean):
        callee = match.group(1).replace("?.", ".")
        if callee in {"if", "for", "while", "switch", "catch", "function"}:
            continue
        open_index = clean.find("(", match.start())
        close_index = matching_parenthesis(clean, open_index)
        if close_index < 0:
            continue
        raw_arguments = line[open_index + 1 : close_index]
        yield callee, split_arguments(raw_arguments), line[match.start() : close_index + 1].strip()


def matching_parenthesis(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def mask_js_literals_and_comments(text: str) -> str:
    masked = list(text)
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            masked[index] = " "
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            masked[index] = " "
            index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            for offset in range(index, len(text)):
                masked[offset] = " "
            break
        if char == "/" and index + 1 < len(text) and text[index + 1] == "*":
            end = text.find("*/", index + 2)
            end = len(text) - 2 if end < 0 else end
            for offset in range(index, min(len(text), end + 2)):
                masked[offset] = " "
            index = end + 2
            continue
        index += 1
    return "".join(masked)


def js_variables(expression: str) -> list[str]:
    variables = extract_variables(expression)
    for embedded in re.findall(r"\$\{([^}]*)\}", expression):
        variables.extend(extract_variables(embedded))
    return list(dict.fromkeys(variables))


def unsafe_string_construction(expression: str) -> bool:
    return "+" in expression or "${" in expression or bool(re.search(r"\.replace\s*\(", expression))


def is_proven_parameterized_query(arguments: list[str]) -> bool:
    """Require a visible placeholder to match a non-empty binding argument."""

    if len(arguments) < 2:
        return False
    sql = arguments[0].strip()
    if not sql or unsafe_string_construction(sql):
        return False
    binding_text = " ".join(arguments[1:]).strip()
    if re.sub(r"\s+", "", binding_text).lower() in {"", "[]", "{}", "null", "undefined"}:
        return False

    named = re.findall(r"(?<!:):([A-Za-z_$][\w$]*)", sql)
    if named:
        return all(re.search(rf"\b{re.escape(name)}\b", binding_text) for name in named)

    numbered = [int(value) for value in re.findall(r"\$([1-9]\d*)", sql)]
    question_count = len(re.findall(r"\?", sql))
    required = max([question_count, *numbered], default=0)
    if required == 0:
        return False
    first_binding = arguments[1].strip()
    if first_binding.startswith("[") and first_binding.endswith("]"):
        values = [value for value in split_arguments(first_binding[1:-1]) if value.strip()]
        return len(values) >= required
    return len(arguments) - 1 >= required


def is_sql_call(callee: str, arguments: list[str]) -> bool:
    if any(callee.endswith(suffix) for suffix in SQL_CALLEES):
        return True
    if callee not in {"query", "execute", "raw"} or not arguments:
        return False
    return bool(re.search(r"\b(?:select|insert|update|delete|replace|merge|with|create|alter|drop)\b", arguments[0], re.I))


def is_html_output_call(callee: str, arguments: list[str]) -> bool:
    if callee in {"document.write", "render"} or callee.endswith(".render"):
        return True
    if not arguments:
        return False
    expression = arguments[0].strip()
    if "<" in expression or ">" in expression or "${" in expression:
        return True
    # Collection/query result objects are normally serialized by Express rather
    # than interpreted as attacker-controlled HTML. Keep direct scalar input as
    # a medium-confidence XSS sink while avoiding rows/results false positives.
    identifier = re.fullmatch(r"[A-Za-z_$][\w$]*", expression)
    return not identifier or identifier.group(0).lower() not in {
        "rows",
        "results",
        "records",
        "items",
        "data",
        "json",
        "payload",
    }
