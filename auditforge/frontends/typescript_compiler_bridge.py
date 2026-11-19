"""Optional TypeScript Compiler API frontend.

The existing JavaScript/TypeScript frontend intentionally has no runtime
dependency.  This module adds a strictly optional grammar-backed path: when a
local or user-installed ``typescript`` package can be resolved, a short-lived
Node process parses the source and returns syntax events.  If Node, TypeScript,
or parsing is unavailable the caller receives a diagnostic and can keep using
the existing heuristic frontend unchanged.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any

from .javascript_analysis import (
    CODE_EVALUATION_CALLEES,
    COMMAND_CALLEES,
    DESERIALIZATION_CALLEES,
    FILE_CALLEE_SUFFIXES,
    HTML_SANITIZERS,
    NEXT_HTTP_FUNCTIONS,
    PATH_SANITIZERS,
    PROTOTYPE_MUTATION_CALLEES,
    SSRF_CALLEES,
    TEMPLATE_COMPILATION_CALLEES,
    TYPE_SANITIZERS,
    URL_SANITIZERS,
    XSS_CALLEE_SUFFIXES,
    is_html_output_call,
    is_proven_parameterized_query,
    is_sql_call,
    join_route_path,
    next_route_path,
    unsafe_string_construction,
)
from .language_frontend import LanguageAnalysisResult, LanguageFactBuilder, dedupe_strings

BRIDGE_TIMEOUT_SECONDS = 12
MAX_BRIDGE_OUTPUT_BYTES = 12 * 1024 * 1024
MAX_COMPILER_EVENTS = 30000
BRIDGE_ENABLED_ENV = "AUDITFORGE_TYPESCRIPT_COMPILER"
TYPESCRIPT_PATH_ENV = "AUDITFORGE_TYPESCRIPT_PATH"


def analyze_typescript_with_compiler(source_file: Any) -> tuple[LanguageAnalysisResult | None, dict[str, Any]]:
    """Analyze one TS/TSX file with the Compiler API when available.

    A ``None`` result always means the scanner should use the existing
    heuristic frontend.  The returned diagnostic is safe to persist in scan
    artifacts and deliberately distinguishes unavailability from parse/runtime
    failure.
    """

    if not _env_enabled(os.getenv(BRIDGE_ENABLED_ENV, "1")):
        return None, _diagnostic("disabled", "TypeScript Compiler API bridge disabled by environment")

    node = shutil.which("node")
    if not node:
        return None, _diagnostic("node_not_found", "Node.js executable was not found")

    bridge_path = Path(__file__).with_name("typescript_compiler_bridge.cjs")
    if not bridge_path.is_file():
        return None, _diagnostic("bridge_missing", "bundled TypeScript bridge script was not found")

    request = {
        "fileName": str(source_file.file.path),
        "source": str(source_file.content),
        "searchPaths": _typescript_search_paths(Path(source_file.absolute_path)),
        "typescriptPath": os.getenv(TYPESCRIPT_PATH_ENV, "").strip(),
    }
    try:
        completed = subprocess.run(
            [node, str(bridge_path)],
            input=json.dumps(request, ensure_ascii=False),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=BRIDGE_TIMEOUT_SECONDS,
            check=False,
            cwd=str(bridge_path.parent),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return None, _diagnostic("timeout", f"Compiler API bridge exceeded {BRIDGE_TIMEOUT_SECONDS}s")
    except OSError as exc:
        return None, _diagnostic("bridge_error", f"{type(exc).__name__}: {exc}")

    stdout = completed.stdout or ""
    if len(stdout.encode("utf-8", errors="replace")) > MAX_BRIDGE_OUTPUT_BYTES:
        return None, _diagnostic("invalid_output", "Compiler API bridge output exceeded the safety limit")
    if completed.returncode != 0:
        reason = (completed.stderr or stdout or f"Node exited with status {completed.returncode}").strip()
        return None, _diagnostic("bridge_error", reason[:1200])
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return None, _diagnostic("invalid_output", f"Compiler API bridge returned invalid JSON: {exc}")
    if not isinstance(payload, dict):
        return None, _diagnostic("invalid_output", "Compiler API bridge response must be an object")

    status = _safe_text(payload.get("status"), 80) or "invalid_output"
    if status != "ok":
        return None, _diagnostic(status, _safe_text(payload.get("reason"), 1200) or status)
    try:
        result = compiler_payload_to_result(source_file, payload)
    except (KeyError, TypeError, ValueError) as exc:
        return None, _diagnostic("invalid_output", f"Compiler API fact conversion failed: {exc}")

    compiler = payload.get("compiler") if isinstance(payload.get("compiler"), dict) else {}
    diagnostic = _diagnostic("ok", "TypeScript Compiler API facts emitted")
    diagnostic.update(
        {
            "version": _safe_text(compiler.get("version"), 80) or "unknown",
            "module_path": _safe_text(compiler.get("modulePath"), 1000) or None,
            "facts": _result_fact_count(result),
        }
    )
    return result, diagnostic


def compiler_payload_to_result(source_file: Any, payload: dict[str, Any]) -> LanguageAnalysisResult:
    """Convert bounded Compiler API syntax events into language-neutral facts."""

    raw = payload.get("facts")
    if not isinstance(raw, dict):
        raise ValueError("facts must be an object")
    total_events = sum(len(value) for value in raw.values() if isinstance(value, list))
    if total_events > MAX_COMPILER_EVENTS:
        raise ValueError(f"fact event limit exceeded ({MAX_COMPILER_EVENTS})")

    builder = LanguageFactBuilder(source_file)
    class_map: dict[str, Any] = {}
    function_map: dict[str, Any] = {}

    for item in _object_list(raw.get("classes")):
        key = _safe_text(item.get("key"), 240)
        name = _safe_text(item.get("name"), 240)
        if not key or not name:
            continue
        line = _line(source_file, item.get("line"))
        fact = builder.add_class(
            name,
            line,
            _line(source_file, item.get("endLine"), minimum=line),
            qualified_name=_safe_text(item.get("qualifiedName"), 500) or name,
        )
        class_map[key] = fact

    raw_functions = _object_list(raw.get("functions"))
    for item in raw_functions:
        key = _safe_text(item.get("key"), 240)
        name = _safe_text(item.get("name"), 240)
        if not key or not name:
            continue
        line = _line(source_file, item.get("line"))
        class_fact = class_map.get(_safe_text(item.get("classKey"), 240))
        fact = builder.add_function(
            name,
            line,
            _string_list(item.get("params"), 200),
            _line(source_file, item.get("endLine"), minimum=line),
            qualified_name=_safe_text(item.get("qualifiedName"), 500) or name,
            class_id=class_fact.id if class_fact else None,
        )
        function_map[key] = fact

    # Parent function ids are available only after all functions have been built.
    updated_functions = []
    for item in raw_functions:
        key = _safe_text(item.get("key"), 240)
        fact = function_map.get(key)
        if fact is None:
            continue
        parent = function_map.get(_safe_text(item.get("parentKey"), 240))
        updated = replace(fact, parent_function_id=parent.id if parent else None)
        function_map[key] = updated
        updated_functions.append(updated)
    builder.result.functions = updated_functions

    assignments = _object_list(raw.get("assignments"))
    targets_by_line: dict[int, list[str]] = {}
    for item in assignments:
        target = _safe_text(item.get("target"), 500)
        if not target:
            continue
        line = _line(source_file, item.get("line"))
        targets_by_line.setdefault(line, []).append(target)
        builder.add_assignment(
            target,
            _string_list(item.get("sources"), 500),
            _safe_text(item.get("expression"), 1600),
            line,
            function=function_map.get(_safe_text(item.get("scopeKey"), 240)),
        )

    for item in _object_list(raw.get("returns")):
        builder.add_return(
            _safe_text(item.get("expression"), 1600),
            _string_list(item.get("sources"), 500),
            _line(source_file, item.get("line")),
            function=function_map.get(_safe_text(item.get("scopeKey"), 240)),
        )

    calls = _object_list(raw.get("calls"))
    functions_by_name = {fact.name: fact for fact in builder.result.functions}
    for item in calls:
        callee = _safe_text(item.get("callee"), 600)
        if not callee:
            continue
        line = _line(source_file, item.get("line"))
        argument_sources = _nested_string_lists(item.get("argumentSources"), 100, 200)
        builder.add_call(
            callee,
            line,
            argument_sources,
            function=function_map.get(_safe_text(item.get("scopeKey"), 240)),
        )
        _add_call_security_facts(builder, item, line, argument_sources, targets_by_line, function_map)

    for item in _object_list(raw.get("accesses")):
        access = _safe_text(item.get("path"), 800)
        kind = _source_kind_for_access(access)
        if not kind:
            continue
        line = _line(source_file, item.get("line"))
        variables = dedupe_strings([*_string_list(item.get("targetVariables"), 100), access])
        builder.add_source(
            kind,
            _safe_text(item.get("expression"), 1600) or access,
            line,
            variables,
            function=function_map.get(_safe_text(item.get("scopeKey"), 240)),
        )

    decorators = _object_list(raw.get("decorators"))
    _add_decorator_facts(builder, decorators, class_map, function_map)
    _add_route_facts(builder, calls, decorators, class_map, function_map, functions_by_name)

    for item in _object_list(raw.get("controls")):
        kind = _safe_text(item.get("kind"), 20)
        if kind not in {"if", "elif", "else", "for", "while", "switch", "case", "catch"}:
            continue
        builder.add_control(
            kind,
            _safe_text(item.get("condition"), 1600),
            _line(source_file, item.get("line")),
            _string_list(item.get("variables"), 500),
            function=function_map.get(_safe_text(item.get("scopeKey"), 240)),
        )

    return _mark_result_ast(builder.result)


def _add_call_security_facts(
    builder: LanguageFactBuilder,
    item: dict[str, Any],
    line: int,
    argument_sources: list[list[str]],
    targets_by_line: dict[int, list[str]],
    function_map: dict[str, Any],
) -> None:
    callee = _safe_text(item.get("callee"), 600)
    lowered = callee.lower()
    argument_texts = _string_list(item.get("argumentTexts"), 100, item_limit=1600)
    variables = dedupe_strings([name for values in argument_sources for name in values])
    expression = _safe_text(item.get("expression"), 1600) or callee
    function = function_map.get(_safe_text(item.get("scopeKey"), 240))

    source_kind = _source_kind_for_call(lowered)
    if source_kind:
        builder.add_source(source_kind, expression, line, [*targets_by_line.get(line, []), *variables], function=function)

    if is_sql_call(lowered, argument_texts):
        first = argument_texts[0] if argument_texts else ""
        confidence = "high" if unsafe_string_construction(first) or "unsafe" in lowered else "medium"
        builder.add_sink("raw_sql", expression, line, variables, confidence=confidence, function=function)
        if is_proven_parameterized_query(argument_texts):
            builder.add_sanitizer(
                "parameterized_query",
                expression,
                line,
                variables,
                variables,
                ["raw_sql"],
                confidence="high",
                function=function,
            )
    if lowered in COMMAND_CALLEES or any(lowered.endswith(f".{name}") for name in COMMAND_CALLEES):
        builder.add_sink("command_execution", expression, line, variables, function=function)
    if any(lowered.endswith(suffix) for suffix in FILE_CALLEE_SUFFIXES):
        builder.add_sink("file_path", expression, line, variables, function=function)
    if lowered in DESERIALIZATION_CALLEES or any(lowered.endswith(f".{name}") for name in DESERIALIZATION_CALLEES):
        builder.add_sink("deserialization", expression, line, variables, function=function)
    if lowered in CODE_EVALUATION_CALLEES or any(lowered.endswith(f".{name}") for name in CODE_EVALUATION_CALLEES):
        builder.add_sink("code_evaluation", expression, line, variables, function=function)
    if lowered in SSRF_CALLEES:
        builder.add_sink("external_request", expression, line, variables, function=function)
    if lowered in TEMPLATE_COMPILATION_CALLEES:
        builder.add_sink("template_compilation", expression, line, variables, function=function)
    if lowered in PROTOTYPE_MUTATION_CALLEES:
        builder.add_sink("prototype_mutation", expression, line, variables, confidence="medium", function=function)
    if (
        any(lowered.endswith(suffix) for suffix in XSS_CALLEE_SUFFIXES)
        and lowered not in {"res.json", "response.json"}
        and is_html_output_call(lowered, argument_texts)
    ):
        builder.add_sink("html_output", expression, line, variables, confidence="medium", function=function)

    sanitizer_kind = ""
    applies_to: list[str] = []
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
            expression,
            line,
            targets_by_line.get(line, []) or variables,
            variables,
            applies_to,
            function=function,
        )

    for target in targets_by_line.get(line, []):
        target_lower = target.lower()
        if target_lower.endswith((".innerhtml", ".outerhtml", ".dangerouslysetinnerhtml")):
            builder.add_sink("html_output", expression, line, variables, function=function)
        elif target_lower == "ctx.body":
            builder.add_sink("html_output", expression, line, variables, confidence="medium", function=function)


def _add_decorator_facts(
    builder: LanguageFactBuilder,
    decorators: list[dict[str, Any]],
    class_map: dict[str, Any],
    function_map: dict[str, Any],
) -> None:
    del class_map  # retained in the signature because decorators carry both scope types
    kinds = {
        "param": "http_path",
        "query": "http_query",
        "body": "http_body",
        "headers": "http_header",
        "req": "http_request",
        "request": "http_request",
        "uploadedfile": "http_file",
        "uploadedfiles": "http_file",
    }
    for item in decorators:
        name = _safe_text(item.get("name"), 240).rsplit(".", 1)[-1].lower()
        kind = kinds.get(name)
        variables = _string_list(item.get("parameterNames"), 50)
        if not kind or not variables:
            continue
        builder.add_source(
            kind,
            _safe_text(item.get("expression"), 1600) or f"@{name}",
            _line(builder.source_file, item.get("line")),
            variables,
            function=function_map.get(_safe_text(item.get("scopeKey"), 240)),
        )


def _add_route_facts(
    builder: LanguageFactBuilder,
    calls: list[dict[str, Any]],
    decorators: list[dict[str, Any]],
    class_map: dict[str, Any],
    function_map: dict[str, Any],
    functions_by_name: dict[str, Any],
) -> None:
    methods = {"get", "post", "put", "patch", "delete", "options", "head", "all", "use"}
    content_lower = str(builder.source_file.content).lower()
    for item in calls:
        callee = _safe_text(item.get("callee"), 600)
        parts = callee.split(".")
        if len(parts) < 2 or parts[-1].lower() not in methods:
            continue
        literals = item.get("argumentLiterals") if isinstance(item.get("argumentLiterals"), list) else []
        route_path = literals[0] if literals and isinstance(literals[0], str) else None
        if not route_path:
            continue
        handler = _resolve_call_handler(item, function_map, functions_by_name)
        framework = "koa" if "@koa/router" in content_lower or "from 'koa'" in content_lower or 'from "koa"' in content_lower else "express"
        builder.add_route(parts[-1].upper(), route_path, _line(builder.source_file, item.get("line")), framework, handler=handler)

    controller_prefix: dict[str, str] = {}
    for item in decorators:
        name = _safe_text(item.get("name"), 240).rsplit(".", 1)[-1].lower()
        if name == "controller":
            controller_prefix[_safe_text(item.get("classKey"), 240)] = _safe_text(item.get("value"), 500)
    nest_methods = {
        "get": "GET",
        "post": "POST",
        "put": "PUT",
        "patch": "PATCH",
        "delete": "DELETE",
        "options": "OPTIONS",
        "head": "HEAD",
        "all": "ALL",
    }
    for item in decorators:
        name = _safe_text(item.get("name"), 240).rsplit(".", 1)[-1].lower()
        method = nest_methods.get(name)
        handler = function_map.get(_safe_text(item.get("scopeKey"), 240))
        if not method or handler is None:
            continue
        class_key = _safe_text(item.get("classKey"), 240)
        path = join_route_path(controller_prefix.get(class_key, ""), _safe_text(item.get("value"), 500))
        builder.add_route(method, path, _line(builder.source_file, item.get("line")), "nestjs", handler=handler)

    for function in builder.result.functions:
        if function.name in NEXT_HTTP_FUNCTIONS:
            builder.add_route(
                function.name,
                next_route_path(builder.path),
                function.anchor.start_line,
                "nextjs",
                handler=function,
            )
        elif function.name == "handler" and re.search(r"(?:pages|app)/api/", builder.path.replace("\\", "/")):
            builder.add_route("ANY", next_route_path(builder.path), function.anchor.start_line, "nextjs", handler=function)


def _resolve_call_handler(item: dict[str, Any], function_map: dict[str, Any], functions_by_name: dict[str, Any]) -> Any | None:
    keys = item.get("argumentFunctionKeys") if isinstance(item.get("argumentFunctionKeys"), list) else []
    for key in keys[1:]:
        if isinstance(key, str) and key in function_map:
            return function_map[key]
    texts = item.get("argumentTexts") if isinstance(item.get("argumentTexts"), list) else []
    for value in reversed(texts[1:]):
        if isinstance(value, str) and value.strip() in functions_by_name:
            return functions_by_name[value.strip()]
    return None


def _source_kind_for_access(value: str) -> str | None:
    normalized = value.replace("?.", ".").lower()
    if re.match(r"^(?:req|request|ctx)\.(?:params?|param)(?:\.|$)", normalized):
        return "http_path"
    if re.match(r"^(?:req|request|ctx)\.(?:query|querystring)(?:\.|$)", normalized):
        return "http_query"
    if re.match(r"^(?:req|request)\.body(?:\.|$)", normalized) or re.match(r"^ctx\.request\.body(?:\.|$)", normalized):
        return "http_body"
    if re.match(r"^(?:req|request|ctx)\.headers?(?:\.|$)", normalized):
        return "http_header"
    if re.match(r"^(?:req|request|ctx)\.cookies?(?:\.|$)", normalized):
        return "http_cookie"
    if re.match(r"^(?:req|request)\.files?(?:\.|$)", normalized):
        return "http_file"
    if re.match(r"^(?:request|req)\.nexturl\.searchparams(?:\.|$)", normalized):
        return "http_query"
    return None


def _source_kind_for_call(callee: str) -> str | None:
    normalized = callee.replace("?.", ".")
    if re.match(r"^(?:request|req)\.nexturl\.searchparams\.(?:get|getall)$", normalized):
        return "http_query"
    if re.match(r"^(?:request|req)\.(?:json|formdata)$", normalized):
        return "http_body"
    if re.match(r"^(?:request|req)\.headers\.get$", normalized):
        return "http_header"
    if re.match(r"^(?:request|req)\.cookies\.get$", normalized):
        return "http_cookie"
    return None


def _mark_result_ast(result: LanguageAnalysisResult) -> LanguageAnalysisResult:
    for name in (
        "functions",
        "classes",
        "routes",
        "call_sites",
        "data_flows",
        "control_flows",
        "sources",
        "sinks",
        "sanitizers",
    ):
        setattr(result, name, [replace(item, analysis_method="ast") for item in getattr(result, name)])
    return result


def _typescript_search_paths(source_path: Path) -> list[str]:
    candidates = [source_path.parent]
    raw_node_path = os.getenv("NODE_PATH", "")
    candidates.extend(Path(item) for item in raw_node_path.split(os.pathsep) if item.strip())
    global_root = _global_typescript_root()
    if global_root:
        candidates.append(Path(global_root))
    common = [
        Path.home() / ".npm-global" / "lib" / "node_modules",
        Path.home() / "AppData" / "Roaming" / "npm" / "node_modules",
        Path("/usr/local/lib/node_modules"),
        Path("/usr/lib/node_modules"),
    ]
    candidates.extend(common)
    return list(dict.fromkeys(str(item.resolve(strict=False)) for item in candidates))


@lru_cache(maxsize=1)
def _global_typescript_root() -> str | None:
    npm = shutil.which("npm")
    if not npm:
        return None
    try:
        completed = subprocess.run(
            [npm, "root", "-g"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=4,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    value = (completed.stdout or "").strip()
    return value if value else None


def _diagnostic(status: str, reason: str) -> dict[str, Any]:
    return {"status": status, "reason": reason[:1200], "used": status == "ok", "fallback": status != "ok"}


def _result_fact_count(result: LanguageAnalysisResult) -> int:
    return sum(
        len(getattr(result, name))
        for name in (
            "functions",
            "classes",
            "routes",
            "call_sites",
            "data_flows",
            "control_flows",
            "sources",
            "sinks",
            "sanitizers",
        )
    )


def _env_enabled(value: str) -> bool:
    return value.strip().lower() not in {"0", "false", "no", "off", "disabled"}


def _safe_text(value: Any, limit: int = 1600) -> str:
    return str(value)[:limit] if isinstance(value, (str, int, float)) else ""


def _object_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _string_list(value: Any, limit: int, *, item_limit: int = 500) -> list[str]:
    if not isinstance(value, list):
        return []
    return dedupe_strings([_safe_text(item, item_limit) for item in value[:limit]])


def _nested_string_lists(value: Any, outer_limit: int, inner_limit: int) -> list[list[str]]:
    if not isinstance(value, list):
        return []
    return [_string_list(item, inner_limit) for item in value[:outer_limit]]


def _line(source_file: Any, value: Any, *, minimum: int = 1) -> int:
    try:
        line = int(value)
    except (TypeError, ValueError):
        line = minimum
    maximum = max(1, len(source_file.lines))
    return min(max(minimum, line), maximum)
