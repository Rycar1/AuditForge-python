"""Lightweight semantic frontend for PHP, Laravel and Symfony source files.

The frontend is deliberately dependency-free.  It recognizes stable PHP
syntax/framework idioms and emits the shared language facts, while retaining
``analysis_method=heuristic`` to avoid claiming parser-level precision.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from .language_frontend import (
    LanguageAnalysisResult,
    LanguageFactBuilder,
    dedupe_strings,
    find_brace_block_end,
    parse_parameters,
    split_arguments,
    strip_literals_and_comments,
)

PHP_VARIABLE = re.compile(r"\$[A-Za-z_]\w*(?:(?:\s*->\s*[A-Za-z_]\w*)|(?:\s*\[\s*(?:['\"][^'\"]+['\"]|[^\]]+)\s*\]))*")
ASSIGNMENT = re.compile(
    r"(?P<target>\$[A-Za-z_]\w*(?:(?:\s*->\s*[A-Za-z_]\w*)|(?:\s*\[\s*[^\]]+\s*\]))*)"
    r"\s*(?P<operator>\.?=)\s*(?!=|>)(?P<value>.+?);?\s*$",
    re.DOTALL,
)
FUNCTION = re.compile(
    r"\b(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?\s*(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)",
    re.IGNORECASE,
)
CLASS_LIKE = re.compile(
    r"\b(?:(?:final|abstract|readonly)\s+)*(?:class|interface|trait|enum)\s+(?P<name>[A-Za-z_]\w*)\b",
    re.IGNORECASE,
)
NAMESPACE = re.compile(r"\bnamespace\s+(?P<name>[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\s*[;{]", re.IGNORECASE)

SUPERGLOBAL_SOURCES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\$_GET\s*(?:\[[^\]]+\])?", re.IGNORECASE), "http_query", "high"),
    (re.compile(r"\$_POST\s*(?:\[[^\]]+\])?", re.IGNORECASE), "http_body", "high"),
    (re.compile(r"\$_REQUEST\s*(?:\[[^\]]+\])?", re.IGNORECASE), "http_body", "high"),
    (re.compile(r"\$_COOKIE\s*(?:\[[^\]]+\])?", re.IGNORECASE), "cookie", "high"),
    (re.compile(r"\$_FILES\s*(?:\[[^\]]+\])?", re.IGNORECASE), "file_upload", "high"),
    (re.compile(r"\$_SERVER\s*\[\s*['\"]HTTP_[A-Z0-9_]+['\"]\s*\]", re.IGNORECASE), "http_header", "high"),
    # Session values frequently originate in an earlier request. Treat them as
    # a medium-confidence persistent input so second-order flows remain visible.
    (re.compile(r"\$_SESSION\s*(?:\[[^\]]+\])?", re.IGNORECASE), "session_data", "medium"),
)

DATABASE_RESULT_CALL = re.compile(
    r"\b(?:mysqli?_fetch_(?:assoc|array|row|object)|pg_fetch_(?:assoc|array|row|object))\s*\("
    r"|\$[A-Za-z_]\w*\s*->\s*(?:fetch|fetchAll|fetchArray|fetchAssoc|fetchAssociative|fetchNumeric)\s*\(",
    re.IGNORECASE,
)

REQUEST_SOURCE_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(
            r"(?:\$[A-Za-z_]*(?:request|req)[A-Za-z_]*|\brequest\s*\(\s*\))\s*->\s*(?:query|queryParams)(?:\s*->\s*get)?\s*\([^)]*\)",
            re.IGNORECASE,
        ),
        "http_query",
        "high",
    ),
    (
        re.compile(r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*request\s*->\s*get\s*\([^)]*\)", re.IGNORECASE),
        "http_body",
        "high",
    ),
    (
        re.compile(
            r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*(?:attributes|route)\s*(?:->\s*get)?\s*\([^)]*\)",
            re.IGNORECASE,
        ),
        "http_path",
        "high",
    ),
    (
        re.compile(
            r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*(?:headers|header)\s*(?:->\s*get)?\s*\([^)]*\)",
            re.IGNORECASE,
        ),
        "http_header",
        "medium",
    ),
    (
        re.compile(
            r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*(?:cookies|cookie)\s*(?:->\s*get)?\s*\([^)]*\)",
            re.IGNORECASE,
        ),
        "cookie",
        "medium",
    ),
    (
        re.compile(
            r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*(?:files|file)\s*(?:->\s*get)?\s*\([^)]*\)",
            re.IGNORECASE,
        ),
        "file_upload",
        "high",
    ),
    (
        re.compile(
            r"(?:\$[A-Za-z_]*(?:request|req)[A-Za-z_]*|\brequest\s*\(\s*\))\s*->\s*(?:input|get|getContent|post|all|only|except|json)\s*\([^)]*\)",
            re.IGNORECASE,
        ),
        "http_body",
        "medium",
    ),
    (
        re.compile(r"\b(?:getallheaders|apache_request_headers)\s*\(\s*\)", re.IGNORECASE),
        "http_header",
        "medium",
    ),
    (
        re.compile(r"\bfilter_input\s*\(\s*INPUT_GET\b[^)]*\)", re.IGNORECASE),
        "http_query",
        "high",
    ),
    (
        re.compile(r"\bfilter_input\s*\(\s*INPUT_POST\b[^)]*\)", re.IGNORECASE),
        "http_body",
        "high",
    ),
    (
        re.compile(r"\bfilter_input\s*\(\s*INPUT_COOKIE\b[^)]*\)", re.IGNORECASE),
        "cookie",
        "high",
    ),
    (
        re.compile(
            r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*getBody\s*\(\s*\)\s*->\s*getContents\s*\(\s*\)",
            re.IGNORECASE,
        ),
        "http_body",
        "high",
    ),
    (
        re.compile(r"\(\s*string\s*\)\s*\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*getBody\s*\(\s*\)", re.IGNORECASE),
        "http_body",
        "high",
    ),
    (
        re.compile(
            r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*getQueryParams\s*\(\s*\)(?:\s*\[[^\]]+\])?",
            re.IGNORECASE,
        ),
        "http_query",
        "high",
    ),
    (
        re.compile(
            r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*getParsedBody\s*\(\s*\)(?:\s*\[[^\]]+\])?",
            re.IGNORECASE,
        ),
        "http_body",
        "high",
    ),
    (
        re.compile(r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*getCookieParams\s*\(\s*\)(?:\s*\[[^\]]+\])?", re.IGNORECASE),
        "cookie",
        "high",
    ),
    (
        re.compile(r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*getUploadedFiles\s*\(\s*\)(?:\s*\[[^\]]+\])?", re.IGNORECASE),
        "file_upload",
        "high",
    ),
    (
        re.compile(r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*getHeader(?:Line)?\s*\([^)]*\)", re.IGNORECASE),
        "http_header",
        "high",
    ),
    (
        re.compile(r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*getAttribute\s*\([^)]*\)", re.IGNORECASE),
        "http_path",
        "medium",
    ),
    (
        re.compile(r"\$[A-Za-z_]*(?:args|routeArgs|routeArguments)[A-Za-z_]*\s*\[[^\]]+\]", re.IGNORECASE),
        "http_path",
        "medium",
    ),
    (
        re.compile(r"\b(?:Request|Input)\s*::\s*(?:input|get|query|post|cookie|file|header)\s*\([^)]*\)", re.IGNORECASE),
        "http_body",
        "medium",
    ),
    (
        re.compile(
            r"\$[A-Za-z_]*(?:request|req)[A-Za-z_]*\s*->\s*(?:get_param|get_params|get_query_params|get_body_params|get_json_params|get_file_params|get_header)\s*\([^)]*\)",
            re.IGNORECASE,
        ),
        "http_body",
        "high",
    ),
    (
        re.compile(r"\bget_query_var\s*\([^)]*\)", re.IGNORECASE),
        "http_query",
        "medium",
    ),
)

SQL_CALL = re.compile(
    r"(?P<callee>\$[A-Za-z_]\w*\s*->\s*(?:query|exec|executeQuery|executeStatement|createQuery|createNativeQuery)|"
    r"\$(?:pdo|db|conn|connection|wpdb)\w*\s*->\s*prepare|"
    r"(?:DB|PDO)\s*::\s*(?:query|exec|raw|select|statement|unprepared)|"
    r"\$[A-Za-z_]\w*\s*->\s*(?:whereRaw|selectRaw|orderByRaw|havingRaw)|"
    r"\$wpdb\s*->\s*(?:query|get_results|get_row|get_var|get_col))\s*\(",
    re.IGNORECASE,
)
DOCTRINE_CLAUSE_CALL = re.compile(
    r"(?P<callee>\$[A-Za-z_]*(?:query|qb|builder)[A-Za-z_]*\s*->\s*(?:where|andWhere|orWhere|having|orderBy|groupBy|set))\s*\(",
    re.IGNORECASE,
)
MYSQL_CALL = re.compile(r"\b(?P<callee>mysqli?_query)\s*\(", re.IGNORECASE)
COMMAND_CALL = re.compile(r"(?<!->)(?<!::)\b(?P<callee>shell_exec|system|exec|passthru|popen|proc_open)\s*\(", re.IGNORECASE)
FILE_CALL = re.compile(
    r"(?<!->)(?<!::)\b(?P<callee>fopen|file|readfile|file_put_contents|move_uploaded_file|unlink|copy|rename|mkdir|rmdir|glob|scandir|opendir)\s*\(",
    re.IGNORECASE,
)
UNSERIALIZE_CALL = re.compile(r"\b(?P<callee>unserialize|igbinary_unserialize|yaml_parse)\s*\(", re.IGNORECASE)
CODE_EVALUATION_CALL = re.compile(r"(?<!->)(?<!::)\b(?P<callee>eval|assert|create_function)\s*\(", re.IGNORECASE)
CURL_INIT = re.compile(r"\bcurl_init\s*\(", re.IGNORECASE)
CURL_SETOPT = re.compile(r"\bcurl_setopt\s*\(", re.IGNORECASE)
CURL_EXEC = re.compile(r"\bcurl_exec\s*\(", re.IGNORECASE)
FILE_GET_CONTENTS = re.compile(r"\bfile_get_contents\s*\(", re.IGNORECASE)
PHP_INPUT_SOURCE = re.compile(
    r"\bfile_get_contents\s*\(\s*(['\"])php://input\1\s*\)",
    re.IGNORECASE,
)
HTTP_CLIENT_CALL = re.compile(
    r"(?P<callee>"
    r"\$[A-Za-z_]*(?:client|http|guzzle)[A-Za-z_]*\s*->\s*(?:request|requestAsync|get|post|put|patch|delete|send|sendAsync)|"
    r"(?:Http|HttpClient)\s*::\s*(?:get|post|put|patch|delete|send|request)|"
    r"HttpClient\s*::\s*create\s*\([^)]*\)\s*->\s*request|"
    r"wp_remote_(?:get|post|request)"
    r")\s*\(",
    re.IGNORECASE,
)
PROCESS_CALL = re.compile(
    r"(?P<callee>Process\s*::\s*fromShellCommandline)\s*\(",
    re.IGNORECASE,
)
PROCESS_CONSTRUCTOR = re.compile(r"\bnew\s+(?:\\?[A-Za-z_]\w*\\)*Process\s*\(", re.IGNORECASE)
TEMPLATE_COMPILATION_CALL = re.compile(
    r"(?P<callee>Blade\s*::\s*compileString|\$[A-Za-z_]\w*\s*->\s*createTemplate)\s*\(",
    re.IGNORECASE,
)

SANITIZER_CALLS: tuple[tuple[re.Pattern[str], str, list[str], str], ...] = (
    (
        re.compile(
            r"(?:->\s*(?:bindParam|bindValue|setParameter|setParameters)|\bmysqli_stmt_bind_param)\s*\(",
            re.IGNORECASE,
        ),
        "parameterized_query",
        ["raw_sql"],
        "high",
    ),
    (
        re.compile(r"\b(?:htmlspecialchars|htmlentities|e|esc_html|esc_attr|wp_kses|wp_kses_post)\s*\(", re.IGNORECASE),
        "html_encoding",
        ["html_output"],
        "high",
    ),
    (
        re.compile(r"\b(?:escapeshellarg|escapeshellcmd)\s*\(", re.IGNORECASE),
        "shell_escaping",
        ["command_execution"],
        "high",
    ),
    (
        re.compile(r"\b(?:basename|realpath)\s*\(", re.IGNORECASE),
        "path_normalization",
        ["file_path"],
        "medium",
    ),
    (
        re.compile(r"(?:->\s*quote|\b(?:mysqli_real_escape_string|pg_escape_string))\s*\(", re.IGNORECASE),
        "sql_escaping",
        [],
        "medium",
    ),
    (
        re.compile(r"\b(?:intval|floatval)\s*\(", re.IGNORECASE),
        "type_validation",
        ["raw_sql", "command_execution", "file_path", "html_output"],
        "medium",
    ),
)


def analyze_php(source_file: Any) -> LanguageAnalysisResult:
    """Analyze one PHP source file and return language-neutral facts."""

    analyzer = _PHPAnalyzer(source_file)
    return analyzer.analyze()


class _PHPAnalyzer:
    def __init__(self, source_file: Any) -> None:
        self.builder = LanguageFactBuilder(source_file)
        self.lines = list(source_file.lines)
        self.statements = _logical_php_statements(self.lines)
        self.sql_escaped_variables: set[str] = set()
        content = "\n".join(strip_literals_and_comments(line) for line in self.lines)
        self.namespaces = [
            (content.count("\n", 0, match.start()) + 1, match.group("name").lstrip("\\")) for match in NAMESPACE.finditer(content)
        ]

    def analyze(self) -> LanguageAnalysisResult:
        self._collect_structure()
        self._collect_routes()
        for line_number, statement in self.statements:
            self._analyze_line(line_number, statement)
        self._collect_embedded_javascript()
        return self.builder.result

    def _collect_embedded_javascript(self) -> None:
        script_lines = _embedded_script_lines(self.lines)
        if not any(line.strip() for line in script_lines):
            return
        # Keep blank placeholders outside <script> blocks so JS facts retain
        # the physical line numbers and original PHP file path.
        from .javascript_analysis import analyze_javascript_typescript

        source_file = self.builder.source_file
        embedded = analyze_javascript_typescript(
            SimpleNamespace(
                file=source_file.file,
                absolute_path=getattr(source_file, "absolute_path", None),
                content="\n".join(script_lines),
                lines=script_lines,
            )
        )
        for field in (
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
            getattr(self.builder.result, field).extend(getattr(embedded, field))

    def _collect_structure(self) -> None:
        content = "\n".join(strip_literals_and_comments(line) for line in self.lines)
        for match in CLASS_LIKE.finditer(content):
            line_number = content.count("\n", 0, match.start()) + 1
            end_line = _php_block_end(self.lines, line_number)
            name = match.group("name")
            namespace = self._namespace_for_line(line_number)
            qualified_name = f"{namespace}\\{name}" if namespace else name
            self.builder.add_class(name, line_number, end_line, qualified_name=qualified_name)

        for match in re.finditer(FUNCTION.pattern, content, re.IGNORECASE | re.DOTALL):
            line_number = content.count("\n", 0, match.start()) + 1
            end_line = _php_block_end(self.lines, line_number)
            owner = self._class_for_line(line_number)
            name = match.group("name")
            namespace = self._namespace_for_line(line_number)
            qualified_name = (
                f"{owner.qualified_name or owner.name}.{name}"
                if owner
                else (f"{namespace}\\{name}" if namespace else name)
            )
            self.builder.add_function(
                name,
                line_number,
                [value if value.startswith("$") else f"${value}" for value in parse_parameters(match.group("params"))],
                end_line,
                qualified_name=qualified_name,
                class_id=owner.id if owner else None,
            )

    def _namespace_for_line(self, line: int) -> str:
        return next((name for start, name in reversed(self.namespaces) if start <= line), "")

    def _class_for_line(self, line: int):  # noqa: ANN202 - local fact lookup
        matching = [item for item in self.builder.result.classes if item.anchor.start_line <= line <= item.anchor.end_line]
        return min(matching, key=lambda item: item.anchor.end_line - item.anchor.start_line, default=None)

    def _collect_routes(self) -> None:
        self._collect_laravel_routes()
        self._collect_symfony_attributes()
        self._collect_symfony_annotations()
        self._collect_wordpress_routes()

    def _collect_laravel_routes(self) -> None:
        route_pattern = re.compile(
            r"(?P<driver>\bRoute\s*::|\$(?P<receiver>router|app)\s*->\s*)"
            r"(?P<method>get|post|put|patch|delete|options|any|match|map)\s*\((?P<args>.*)",
            re.IGNORECASE | re.DOTALL,
        )
        for line_number, statement in self.statements:
            match = route_pattern.search(statement)
            if not match:
                continue
            method_name = match.group("method").lower()
            args = match.group("args")
            strings = re.findall(r"['\"]([^'\"]+)['\"]", args)
            if method_name in {"match", "map"}:
                path = next((value for value in strings if value.startswith("/")), "")
                methods = [
                    value.upper()
                    for value in strings
                    if value.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
                ]
                method = ",".join(dedupe_strings(methods)) or "ANY"
            else:
                path = strings[0] if strings else ""
                method = "ANY" if method_name == "any" else method_name.upper()
            if not path:
                continue
            handler_name = _route_handler_name(args)
            self._add_route(
                method,
                path,
                line_number,
                "slim-like" if (match.group("receiver") or "").lower() == "app" else "laravel-like",
                handler=self._function_named(handler_name),
            )

    def _collect_symfony_attributes(self) -> None:
        content = "\n".join(self.lines)
        pattern = re.compile(r"#\[\s*(?:\\?[A-Za-z_][\w\\]*\\)?Route\s*\((?P<args>.*?)\)\s*]", re.DOTALL)
        for match in pattern.finditer(content):
            line_number = content.count("\n", 0, match.start()) + 1
            path = _named_route_path(match.group("args"))
            if not path:
                continue
            methods = _named_route_methods(match.group("args"))
            handler = self._next_function(line_number, max_distance=12)
            self._add_route(
                ",".join(methods) or "ANY",
                path,
                line_number,
                "symfony-like",
                handler=handler,
            )

    def _collect_symfony_annotations(self) -> None:
        content = "\n".join(self.lines)
        pattern = re.compile(r"@Route\s*\((?P<args>.*?)\)\s*(?:\*/)?", re.IGNORECASE | re.DOTALL)
        for match in pattern.finditer(content):
            line_number = content.count("\n", 0, match.start()) + 1
            path = _named_route_path(match.group("args"))
            if not path:
                continue
            handler = self._next_function(line_number, max_distance=12)
            self._add_route(
                ",".join(_named_route_methods(match.group("args"))) or "ANY",
                path,
                line_number,
                "symfony-like",
                handler=handler,
            )

    def _collect_wordpress_routes(self) -> None:
        rest_pattern = re.compile(r"\bregister_rest_route\s*\((?P<args>.*)\)", re.IGNORECASE | re.DOTALL)
        ajax_pattern = re.compile(
            r"\badd_action\s*\(\s*['\"]wp_ajax_(?:nopriv_)?(?P<action>[A-Za-z0-9_-]+)['\"]\s*,\s*(?P<handler>[^,)]+)",
            re.IGNORECASE,
        )
        for line_number, statement in self.statements:
            rest = rest_pattern.search(statement)
            if rest:
                arguments = split_arguments(rest.group("args"))
                namespace = _first_quoted(arguments[0]) if arguments else ""
                route_path = _first_quoted(arguments[1]) if len(arguments) > 1 else ""
                if namespace and route_path:
                    options = ",".join(arguments[2:])
                    methods = _wordpress_route_methods(options)
                    handler_name = _route_handler_name(options)
                    path = f"/{namespace.strip('/')}/{route_path.lstrip('/')}"
                    self._add_route(
                        ",".join(methods) or "ANY",
                        path,
                        line_number,
                        "wordpress",
                        handler=self._function_named(handler_name),
                    )
            ajax = ajax_pattern.search(statement)
            if ajax:
                handler_name = _callback_name(ajax.group("handler"))
                self._add_route(
                    "POST",
                    f"/wp-admin/admin-ajax.php?action={ajax.group('action')}",
                    line_number,
                    "wordpress",
                    handler=self._function_named(handler_name),
                )

    def _add_route(self, method: str, path: str, line: int, framework: str, *, handler=None):  # noqa: ANN001, ANN202
        route = self.builder.add_route(method, path, line, framework, handler=handler)
        if not handler:
            return route
        placeholders = dedupe_strings(
            re.findall(r"\{([A-Za-z_]\w*)[^}]*}", path)
            + re.findall(r"(?<=/):([A-Za-z_]\w*)", path)
            + re.findall(r"\?P<([A-Za-z_]\w*)>", path)
            + [left or right for left, right in re.findall(r"<(?:(?:[^>:]+):)?([^>]+)>|\{([^}:]+)(?::[^}]+)?}", path)]
        )
        for name in placeholders:
            variable = f"${name}"
            if variable not in handler.params:
                continue
            self.builder.add_source(
                "http_path",
                f"route parameter {name}",
                handler.anchor.start_line,
                [variable],
                confidence="high",
                function=handler,
            )
        return route

    def _function_named(self, name: str | None):  # noqa: ANN202 - local fact lookup
        if not name:
            return None
        matches = [item for item in self.builder.result.functions if item.name.lower() == name.lower()]
        return matches[0] if len(matches) == 1 else None

    def _next_function(self, line: int, *, max_distance: int):  # noqa: ANN202 - local fact lookup
        matches = [
            item
            for item in self.builder.result.functions
            if item.anchor.start_line > line and item.anchor.start_line - line <= max_distance
        ]
        return min(matches, key=lambda item: item.anchor.start_line, default=None)

    def _analyze_line(self, line_number: int, raw_line: str) -> None:
        line = raw_line.strip()
        if not line:
            return
        code = _php_code_mask(line)
        if not code.strip():
            return
        assigned_target, assigned_value, assignment_operator = _assignment_parts(code)
        self._add_sources(line_number, code, assigned_target, raw_line=line)
        self._add_contextual_sql_sanitizer(line_number, line, assigned_target, assigned_value)
        sql_escape_assignment = bool(
            assigned_target
            and re.search(r"(?:->\s*quote|\b(?:mysqli_real_escape_string|pg_escape_string))\s*\(", code, re.IGNORECASE)
        )
        self._add_sanitizers(line_number, code, assigned_target, raw_line=line)
        self._add_guard_sanitizers(line_number, code)
        if assigned_target and assigned_value is not None:
            assignment_sources = php_extract_variables(assigned_value)
            if assignment_operator == ".=":
                assignment_sources = dedupe_strings([assigned_target, *assignment_sources])
            self.builder.add_assignment(
                assigned_target,
                assignment_sources,
                assigned_value.rstrip(";"),
                line_number,
            )
            if sql_escape_assignment:
                self.sql_escaped_variables.add(assigned_target)
            elif assigned_target in self.sql_escaped_variables and re.search(
                r"\b(?:htmlspecialchars|htmlentities|strip_tags|trim)\s*\(", code, re.IGNORECASE
            ):
                pass
            else:
                self.sql_escaped_variables.discard(assigned_target)
        self._add_curl_flow(line_number, code)
        self._add_sinks(line_number, code, raw_line=line)
        self._add_calls(line_number, code)
        self._add_return_and_control(line_number, code, code)

    def _add_sources(self, line_number: int, line: str, assigned_target: str | None, *, raw_line: str) -> None:
        seen: set[tuple[str, str]] = set()
        for pattern, kind, confidence in SUPERGLOBAL_SOURCES:
            for match in pattern.finditer(line):
                expression = _compact_php_path(match.group(0))
                key = (kind, expression)
                if key in seen:
                    continue
                seen.add(key)
                variables = [assigned_target] if assigned_target else [expression]
                self.builder.add_source(kind, expression, line_number, variables, confidence=confidence)
        if assigned_target and PHP_INPUT_SOURCE.search(raw_line):
            self.builder.add_source(
                "http_body",
                "php://input",
                line_number,
                [assigned_target],
                confidence="high",
            )
        if assigned_target and DATABASE_RESULT_CALL.search(line):
            self.builder.add_source(
                "database_result",
                "database fetch result",
                line_number,
                [assigned_target],
                confidence="medium",
            )
        for pattern, kind, confidence in REQUEST_SOURCE_PATTERNS:
            for match in pattern.finditer(line):
                expression = re.sub(r"\s+", "", match.group(0))
                lower_expression = expression.lower()
                source_kind = kind
                if re.match(r"(?:request|input)::(?:query|get)\(", lower_expression):
                    source_kind = "http_query"
                elif "::cookie(" in lower_expression:
                    source_kind = "cookie"
                elif "::file(" in lower_expression:
                    source_kind = "file_upload"
                elif "::header(" in lower_expression:
                    source_kind = "http_header"
                elif "->get_query_params(" in lower_expression:
                    source_kind = "http_query"
                elif "->get_file_params(" in lower_expression:
                    source_kind = "file_upload"
                elif "->get_header(" in lower_expression:
                    source_kind = "http_header"
                key = (source_kind, expression)
                if key in seen:
                    continue
                seen.add(key)
                variables = [assigned_target] if assigned_target else php_extract_variables(expression)
                self.builder.add_source(source_kind, expression, line_number, variables, confidence=confidence)

    def _add_sanitizers(self, line_number: int, line: str, assigned_target: str | None, *, raw_line: str) -> None:
        for pattern, kind, applies_to, confidence in SANITIZER_CALLS:
            match = pattern.search(line)
            if not match:
                continue
            arguments = _call_arguments(line, match.end() - 1)
            inputs = php_extract_variables(arguments)
            outputs = [assigned_target] if assigned_target else inputs
            self.builder.add_sanitizer(
                kind,
                match.group(0).rstrip("("),
                line_number,
                outputs,
                inputs,
                applies_to,
                confidence=confidence,
            )
        wp_prepare = re.search(r"\$wpdb\s*->\s*prepare\s*\(", line, re.IGNORECASE)
        if wp_prepare:
            arguments = split_arguments(_call_arguments(line, wp_prepare.end() - 1))
            sql_variables = php_extract_variables(arguments[0] if arguments else "")
            bound_variables = php_extract_variables(",".join(arguments[1:]))
            outputs = bound_variables if sql_variables else ([assigned_target] if assigned_target else bound_variables)
            if outputs:
                self.builder.add_sanitizer(
                    "wordpress_parameterized_query",
                    "$wpdb->prepare",
                    line_number,
                    outputs,
                    bound_variables,
                    ["raw_sql"],
                    confidence="high",
                )
        for match in re.finditer(r"{{\s*(?![!])(?P<value>.+?)\s*}}", raw_line):
            variables = php_extract_variables(match.group("value"))
            self.builder.add_sanitizer(
                "blade_html_encoding",
                match.group(0),
                line_number,
                variables,
                variables,
                ["html_output"],
                confidence="high",
            )

    def _add_guard_sanitizers(self, line_number: int, line: str) -> None:
        match = re.search(r"\bif\s*\((?P<condition>.*)\)\s*\{?\s*$", line, re.IGNORECASE | re.DOTALL)
        if not match:
            return
        condition = match.group("condition")
        validation_calls = list(
            re.finditer(r"\b(?:is_numeric|ctype_digit|ctype_xdigit)\s*\((?P<value>[^)]*)\)", condition, re.IGNORECASE)
        )
        filter_validation = re.search(
            r"\bfilter_var\s*\((?P<value>[^,]+),\s*FILTER_VALIDATE_(?:INT|FLOAT|IP)\b",
            condition,
            re.IGNORECASE,
        )
        inputs = [
            variable
            for item in validation_calls
            for variable in php_extract_variables(item.group("value"))
        ]
        if filter_validation:
            inputs.extend(php_extract_variables(filter_validation.group("value")))
        inputs = dedupe_strings(inputs)
        if not inputs:
            return
        end_line = _php_block_end(self.lines, line_number)
        if end_line <= line_number:
            return
        self.builder.add_sanitizer(
            "type_validation",
            condition,
            line_number,
            inputs,
            inputs,
            ["raw_sql", "command_execution", "file_path"],
            confidence="high",
            end_line=end_line,
            symbol="guard:type_validation",
        )

    def _add_contextual_sql_sanitizer(
        self,
        line_number: int,
        raw_line: str,
        assigned_target: str | None,
        assigned_value: str | None,
    ) -> None:
        if not assigned_target or assigned_value is None:
            return
        variables = php_extract_variables(assigned_value)
        protected = [
            variable
            for variable in variables
            if variable in self.sql_escaped_variables and _sql_variable_is_quoted(raw_line, variable)
        ]
        if not protected:
            return
        self.builder.add_sanitizer(
            "quoted_sql_escaping",
            "SQL-escaped value used in a quoted SQL value position",
            line_number,
            [assigned_target],
            protected,
            ["raw_sql"],
            confidence="medium",
        )

    def _add_curl_flow(self, line_number: int, line: str) -> None:
        match = CURL_SETOPT.search(line)
        if not match:
            return
        arguments = split_arguments(_call_arguments(line, match.end() - 1))
        if len(arguments) < 3 or "CURLOPT_URL" not in arguments[1].upper():
            return
        handles = php_extract_variables(arguments[0])
        if handles:
            self.builder.add_assignment(
                handles[0],
                php_extract_variables(arguments[2]),
                f"curl_setopt({arguments[1]})",
                line_number,
            )

    def _add_sinks(self, line_number: int, line: str, *, raw_line: str) -> None:
        for match in SQL_CALL.finditer(line):
            if _is_request_method_callee(match.group("callee")):
                continue
            arguments = split_arguments(_call_arguments(line, match.end() - 1))
            variables = php_extract_variables(arguments[0] if arguments else "")
            self.builder.add_sink("raw_sql", match.group("callee"), line_number, variables)
        for match in DOCTRINE_CLAUSE_CALL.finditer(line):
            arguments = split_arguments(_call_arguments(line, match.end() - 1))
            variables = php_extract_variables(arguments[0] if arguments else "")
            if variables:
                self.builder.add_sink("raw_sql", _compact_php_path(match.group("callee")), line_number, variables, confidence="medium")
        for match in MYSQL_CALL.finditer(line):
            arguments = split_arguments(_call_arguments(line, match.end() - 1))
            query = arguments[1] if len(arguments) > 1 else (arguments[0] if arguments else "")
            self.builder.add_sink("raw_sql", match.group("callee"), line_number, php_extract_variables(query))
        for match in COMMAND_CALL.finditer(line):
            arguments = _call_arguments(line, match.end() - 1)
            self.builder.add_sink("command_execution", match.group("callee"), line_number, php_extract_variables(arguments))
        for match in re.finditer(r"`(?P<command>[^`]+)`", line):
            self.builder.add_sink(
                "command_execution",
                "backtick command",
                line_number,
                php_extract_variables(match.group("command")),
            )
        include_match = re.search(
            r"\b(?P<callee>include|include_once|require|require_once)\b\s*(?:\(\s*)?(?P<value>[^;)]+)", line, re.IGNORECASE
        )
        if include_match:
            self.builder.add_sink(
                "file_path",
                include_match.group("callee"),
                line_number,
                php_extract_variables(include_match.group("value")),
            )
        for match in FILE_CALL.finditer(line):
            arguments = split_arguments(_call_arguments(line, match.end() - 1))
            self.builder.add_sink("file_path", match.group("callee"), line_number, php_extract_variables(arguments[0] if arguments else ""))
        for match in UNSERIALIZE_CALL.finditer(line):
            self.builder.add_sink(
                "deserialization",
                match.group("callee"),
                line_number,
                php_extract_variables(_call_arguments(line, match.end() - 1)),
            )
        for match in CODE_EVALUATION_CALL.finditer(line):
            self.builder.add_sink(
                "code_evaluation",
                match.group("callee"),
                line_number,
                php_extract_variables(_call_arguments(line, match.end() - 1)),
            )
        for match in PROCESS_CONSTRUCTOR.finditer(line):
            variables = _process_command_variables(_call_arguments(line, match.end() - 1))
            if variables:
                self.builder.add_sink(
                    "command_execution",
                    "new Process",
                    line_number,
                    variables,
                    confidence="medium",
                )
        for match in PROCESS_CALL.finditer(line):
            callee = _compact_php_path(match.group("callee"))
            arguments = _call_arguments(line, match.end() - 1)
            variables = php_extract_variables(arguments)
            self.builder.add_sink("command_execution", callee, line_number, variables, confidence="medium")
        for match in TEMPLATE_COMPILATION_CALL.finditer(line):
            self.builder.add_sink(
                "template_compilation",
                _compact_php_path(match.group("callee")),
                line_number,
                php_extract_variables(_call_arguments(line, match.end() - 1)),
            )
        self._add_framework_file_sinks(line_number, line)
        self._add_http_sinks(line_number, line)
        self._add_html_sinks(line_number, line, raw_line=raw_line)

    def _add_framework_file_sinks(self, line_number: int, line: str) -> None:
        pattern = re.compile(
            r"(?P<callee>(?:Storage|File)\s*::\s*(?:get|put|download|delete|copy|move)|"
            r"\$[A-Za-z_]\w*\s*->\s*(?:extractTo|readFile|dumpFile))\s*\(",
            re.IGNORECASE,
        )
        for match in pattern.finditer(line):
            arguments = split_arguments(_call_arguments(line, match.end() - 1))
            self.builder.add_sink(
                "file_path",
                _compact_php_path(match.group("callee")),
                line_number,
                php_extract_variables(arguments[0] if arguments else ""),
                confidence="medium",
            )

    def _add_http_sinks(self, line_number: int, line: str) -> None:
        for match in CURL_INIT.finditer(line):
            variables = php_extract_variables(_call_arguments(line, match.end() - 1))
            if variables:
                self.builder.add_sink("external_request", "curl_init", line_number, variables)
        for match in CURL_EXEC.finditer(line):
            self.builder.add_sink(
                "external_request",
                "curl_exec",
                line_number,
                php_extract_variables(_call_arguments(line, match.end() - 1)),
            )
        for match in FILE_GET_CONTENTS.finditer(line):
            arguments = split_arguments(_call_arguments(line, match.end() - 1))
            variables = php_extract_variables(arguments[0] if arguments else "")
            self.builder.add_sink("external_request", "file_get_contents", line_number, variables, confidence="medium")
            self.builder.add_sink("file_path", "file_get_contents", line_number, variables, confidence="medium")
        for match in HTTP_CLIENT_CALL.finditer(line):
            arguments = split_arguments(_call_arguments(line, match.end() - 1))
            callee = _compact_php_path(match.group("callee"))
            method = callee.rsplit("->", 1)[-1].rsplit("::", 1)[-1].lower()
            if method in {"send", "sendasync"} and callee.startswith("$"):
                continue
            url_index = 1 if method in {"request", "requestasync", "send"} else 0
            url = arguments[url_index] if len(arguments) > url_index else ""
            variables = php_extract_variables(url)
            if variables:
                self.builder.add_sink(
                    "external_request",
                    callee,
                    line_number,
                    variables,
                    confidence="medium" if callee.startswith("$") else "high",
                )

    def _add_html_sinks(self, line_number: int, line: str, *, raw_line: str) -> None:
        patterns = (
            re.compile(r"\becho\s+(?P<value>.+?)(?:;|$)", re.IGNORECASE),
            re.compile(r"\bprint\s*(?:\(\s*(?P<paren>.*?)\s*\)|(?P<value>.+?))(?:;|$)", re.IGNORECASE),
            re.compile(r"\b(?:printf|vprintf)\s*\(\s*(?P<value>.*?)\s*\)(?:;|$)", re.IGNORECASE),
            re.compile(r"<\?=\s*(?P<value>.*?)\s*\?>", re.IGNORECASE),
        )
        for pattern in patterns:
            for match in pattern.finditer(line):
                value = match.groupdict().get("paren") or match.groupdict().get("value") or ""
                self.builder.add_sink("html_output", match.group(0), line_number, php_extract_variables(value))
        for match in re.finditer(r"{!!\s*(?P<value>.*?)\s*!!}", raw_line):
            self.builder.add_sink("html_output", match.group(0), line_number, php_extract_variables(match.group("value")))
        response_write = re.search(r"\$[A-Za-z_]*response[A-Za-z_]*\s*->\s*getBody\s*\(\s*\)\s*->\s*write\s*\(", line, re.IGNORECASE)
        if response_write:
            self.builder.add_sink(
                "html_output",
                "PSR-7 response body write",
                line_number,
                php_extract_variables(_call_arguments(line, response_write.end() - 1)),
                confidence="medium",
            )
        buffer_assignment = re.search(
            r"(?P<target>\$[A-Za-z_]\w*(?:(?:\s*->\s*[A-Za-z_]\w*)|(?:\s*\[[^\]]+\]))*)"
            r"\s*(?P<operator>\.?=)\s*(?P<value>.+?);?\s*$",
            raw_line,
            re.DOTALL,
        )
        if not buffer_assignment:
            return
        target = _compact_php_path(buffer_assignment.group("target"))
        value = buffer_assignment.group("value")
        root = target.split("->", 1)[0].split("[", 1)[0].lstrip("$").lower()
        buffer_names = {"body", "content", "guestbook", "html", "markup", "output", "responsebody"}
        body_slot = bool(re.search(r"\[\s*['\"](?:body|content|html)['\"]\s*]", target, re.IGNORECASE))
        if root not in buffer_names and not body_slot:
            return
        variables = php_extract_variables(value)
        if buffer_assignment.group("operator") == ".=":
            variables = dedupe_strings([target, *variables])
        if variables:
            self.builder.add_sink(
                "html_output",
                f"HTML response buffer {target}",
                line_number,
                variables,
                confidence="medium",
            )

    def _add_calls(self, line_number: int, line: str) -> None:
        call_pattern = re.compile(
            r"(?P<callee>"
            r"\$[A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*)+|"
            r"\\?[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*(?:\s*::\s*[A-Za-z_]\w*)?"
            r")\s*\("
        )
        for match in call_pattern.finditer(line):
            callee = re.sub(r"\s+", "", match.group("callee"))
            prefix = line[max(0, match.start() - 24) : match.start()]
            if re.search(r"\bfunction\s+&?\s*$", prefix, re.IGNORECASE):
                continue
            if callee.lower() in {
                "if",
                "for",
                "foreach",
                "while",
                "switch",
                "isset",
                "empty",
                "array",
                "list",
                "echo",
                "print",
                "include",
                "require",
            }:
                continue
            arguments = split_arguments(_call_arguments(line, match.end() - 1))
            self.builder.add_call(callee, line_number, [php_extract_variables(argument) for argument in arguments])

    def _add_return_and_control(self, line_number: int, code: str, line: str) -> None:
        return_match = re.search(r"\breturn\s+(?P<value>.+?);?\s*$", line, re.IGNORECASE)
        if return_match:
            value = return_match.group("value").rstrip(";")
            self.builder.add_return(value, php_extract_variables(value), line_number)
        control_match = re.search(r"\b(?P<kind>if|elseif|while|foreach|switch)\s*\((?P<condition>.*)\)", code, re.IGNORECASE)
        if control_match:
            kind = control_match.group("kind").lower()
            mapped = {"elseif": "elif", "foreach": "for"}.get(kind, kind)
            condition = control_match.group("condition")
            self.builder.add_control(mapped, condition, line_number, php_extract_variables(condition))


def php_extract_variables(expression: str) -> list[str]:
    values = [_compact_php_path(match.group(0)) for match in PHP_VARIABLE.finditer(expression)]
    return dedupe_strings(values)


def _compact_php_path(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _sql_variable_is_quoted(expression: str, variable: str) -> bool:
    token = re.escape(variable)
    interpolated = rf"['\"]\s*\{{?\s*{token}\s*\}}?\s*['\"]"
    concatenated = rf"['\"]\s*\.\s*{token}\s*\.\s*['\"]"
    return bool(re.search(interpolated, expression) or re.search(concatenated, expression))


def _is_request_method_callee(value: str) -> bool:
    compact = _compact_php_path(value)
    root = compact.split("->", 1)[0].lstrip("$").lower()
    return "request" in root or root in {"req", "request"}


def _assignment_parts(line: str) -> tuple[str | None, str | None, str | None]:
    match = ASSIGNMENT.search(line.strip())
    if not match:
        return None, None, None
    return (
        _compact_php_path(match.group("target")),
        match.group("value").rstrip(";").strip(),
        match.group("operator"),
    )


def _php_block_end(lines: list[str], start_line: int) -> int:
    for index in range(start_line - 1, min(len(lines), start_line + 32)):
        code = strip_literals_and_comments(lines[index])
        if "{" in code:
            return find_brace_block_end(lines, start_line)
        if ";" in code:
            return start_line
    return start_line


def _call_arguments(line: str, opening_index: int) -> str:
    if opening_index < 0 or opening_index >= len(line) or line[opening_index] != "(":
        opening_index = line.find("(", max(0, opening_index))
    if opening_index < 0:
        return ""
    quote: str | None = None
    escaped = False
    depth = 0
    for index in range(opening_index, len(line)):
        char = line[index]
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
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return line[opening_index + 1 : index]
    return line[opening_index + 1 :]


def _route_handler_name(arguments: str) -> str | None:
    array_handler = re.search(r"::class\s*,\s*['\"](?P<name>[A-Za-z_]\w*)['\"]", arguments)
    if array_handler:
        return array_handler.group("name")
    action = re.search(r"['\"][A-Za-z_\\][\w\\]*@(?P<name>[A-Za-z_]\w*)['\"]", arguments)
    if action:
        return action.group("name")
    callback = re.search(r"['\"]callback['\"]\s*=>\s*(?P<value>.+?)(?:,|])", arguments, re.IGNORECASE | re.DOTALL)
    if callback:
        return _callback_name(callback.group("value"))
    parts = split_arguments(arguments)
    return _callback_name(parts[-1]) if len(parts) >= 2 else None


def _callback_name(value: str) -> str | None:
    method = re.search(r"::class\s*,\s*['\"](?P<name>[A-Za-z_]\w*)['\"]", value)
    if method:
        return method.group("name")
    static = re.search(r"::\s*(?P<name>[A-Za-z_]\w*)", value)
    if static:
        return static.group("name")
    quoted = re.search(r"['\"](?P<name>[A-Za-z_]\w*)['\"]", value)
    return quoted.group("name") if quoted else None


def _first_quoted(value: str) -> str:
    match = re.search(r"['\"](?P<value>[^'\"]+)['\"]", value)
    return match.group("value") if match else ""


def _named_route_path(value: str) -> str:
    named = re.search(r"\b(?:path|value)\s*[:=]>?\s*['\"](?P<path>[^'\"]+)['\"]", value, re.IGNORECASE)
    return named.group("path") if named else _first_quoted(value)


def _named_route_methods(value: str) -> list[str]:
    match = re.search(r"methods?\s*[:=]>?\s*[\[{](?P<methods>.*?)[\]}]", value, re.IGNORECASE | re.DOTALL)
    if not match:
        return []
    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
    return dedupe_strings(
        [item.upper() for item in re.findall(r"['\"]([A-Za-z]+)['\"]", match.group("methods")) if item.upper() in allowed]
    )


def _wordpress_route_methods(value: str) -> list[str]:
    named = re.search(r"['\"]methods['\"]\s*=>\s*(?P<methods>.+?)(?:,\s*['\"]|]\s*$)", value, re.IGNORECASE | re.DOTALL)
    raw = named.group("methods") if named else value
    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
    methods = [item.upper() for item in re.findall(r"['\"]([A-Za-z]+)['\"]", raw) if item.upper() in allowed]
    constants = {
        "READABLE": ["GET"],
        "CREATABLE": ["POST"],
        "EDITABLE": ["POST", "PUT", "PATCH"],
        "DELETABLE": ["DELETE"],
        "ALLMETHODS": ["ANY"],
    }
    for name in re.findall(r"WP_REST_Server\s*::\s*([A-Za-z_]+)", raw, re.IGNORECASE):
        methods.extend(constants.get(name.upper(), []))
    return dedupe_strings(methods)


def _process_command_variables(arguments: str) -> list[str]:
    values = split_arguments(arguments)
    if not values:
        return []
    command = values[0].strip()
    if not (command.startswith("[") and command.endswith("]")):
        return php_extract_variables(command)
    parts = split_arguments(command[1:-1])
    if not parts:
        return []
    executable_variables = php_extract_variables(parts[0])
    if executable_variables:
        return executable_variables
    executable = _first_quoted(parts[0]).replace("\\", "/").rsplit("/", 1)[-1].lower()
    shell_flags = {"-c", "/c", "-command", "-encodedcommand"}
    if executable in {"bash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "sh", "zsh"}:
        for index, item in enumerate(parts[1:], start=1):
            if _first_quoted(item).lower() in shell_flags:
                return php_extract_variables(",".join(parts[index + 1 :]))
    return []


def _php_code_mask(value: str) -> str:
    """Mask comments and literals while preserving interpolated PHP variables."""

    output = list(value)
    quote: str | None = None
    escaped = False
    block_comment = False
    line_comment = False
    index = 0
    while index < len(value):
        char = value[index]
        following = value[index + 1] if index + 1 < len(value) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            else:
                output[index] = " "
            index += 1
            continue
        if block_comment:
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                block_comment = False
                index += 2
            else:
                if char != "\n":
                    output[index] = " "
                index += 1
            continue
        if quote:
            variable = PHP_VARIABLE.match(value, index) if quote == '"' and char == "$" else None
            if variable:
                index = variable.end()
                continue
            if char != "\n":
                output[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char == "/" and following == "*":
            output[index] = output[index + 1] = " "
            block_comment = True
            index += 2
            continue
        if char == "/" and following == "/" or char == "#" and following != "[":
            output[index] = " "
            line_comment = True
            index += 1
            continue
        if char in {"'", '"'}:
            output[index] = " "
            quote = char
        index += 1
    return "".join(output)


def _embedded_script_lines(lines: list[str]) -> list[str]:
    """Return only JavaScript inside script tags while preserving line count."""

    output = ["" for _ in lines]
    in_script = False
    for index, raw_line in enumerate(lines):
        remaining = raw_line
        fragments: list[str] = []
        while remaining:
            if not in_script:
                opening = re.search(r"<script\b[^>]*>", remaining, re.IGNORECASE)
                if not opening:
                    break
                remaining = remaining[opening.end() :]
                in_script = True
            closing = re.search(r"</script\s*>", remaining, re.IGNORECASE)
            if closing:
                fragments.append(remaining[: closing.start()])
                remaining = remaining[closing.end() :]
                in_script = False
                continue
            fragments.append(remaining)
            break
        output[index] = " ".join(fragment for fragment in fragments if fragment)
    return output


def _split_embedded_closure(start_line: int, statement: str) -> list[tuple[int, str]] | None:
    mask = _php_code_mask(statement)
    closure = re.search(r"\bfunction\s*\([^)]*\)[^{};]*\{", mask, re.IGNORECASE | re.DOTALL)
    if not closure or "(" not in mask[: closure.start()]:
        return None
    opening = mask.find("{", closure.start())
    depth = 0
    closing = -1
    for index in range(opening, len(mask)):
        if mask[index] == "{":
            depth += 1
        elif mask[index] == "}":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0:
        return None

    header = statement[: opening + 1].strip()
    body = statement[opening + 1 : closing]
    body_line = start_line + statement[: opening + 1].count("\n")
    leading = len(body) - len(body.lstrip("\r\n"))
    body_line += body[:leading].count("\n")
    body = body[leading:]
    output = [(start_line, header)] if header else []
    output.extend((body_line + local_line - 1, text) for local_line, text in _logical_php_statements(body.splitlines()))
    return output


def _logical_php_statements(lines: list[str]) -> list[tuple[int, str]]:
    """Join multiline PHP expressions while preserving their first source line."""

    output: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 1
    paren_depth = 0
    bracket_depth = 0
    quote: str | None = None
    escaped = False
    block_comment = False
    heredoc_end: str | None = None
    buffer_bytes = 0

    def flush() -> None:
        nonlocal buffer, buffer_bytes
        joined = "\n".join(buffer)
        masked_lines = _php_code_mask(joined).splitlines()
        leading = next((index for index, value in enumerate(masked_lines) if value.strip()), len(buffer))
        statement = "\n".join(buffer[leading:]).strip()
        if statement:
            output.append((start_line + leading, statement))
        buffer = []
        buffer_bytes = 0

    for line_number, raw_line in enumerate(lines, start=1):
        if not buffer:
            start_line = line_number
        buffer.append(raw_line)
        buffer_bytes += len(raw_line)
        stripped = raw_line.strip()
        boundary = stripped in {"<?php", "<?", "?>"} or stripped.startswith(("<?=", "{{", "{!!"))

        if heredoc_end:
            if re.match(rf"^{re.escape(heredoc_end)};?\s*$", stripped):
                heredoc_end = None
                boundary = True
            if boundary and quote is None and not block_comment and paren_depth == 0 and bracket_depth == 0:
                flush()
            continue

        index = 0
        while index < len(raw_line):
            char = raw_line[index]
            following = raw_line[index + 1] if index + 1 < len(raw_line) else ""
            if block_comment:
                if char == "*" and following == "/":
                    block_comment = False
                    index += 2
                    continue
                index += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if char == "/" and following == "*":
                block_comment = True
                index += 2
                continue
            if char == "/" and following == "/":
                break
            if char == "#" and following != "[":
                break
            if char in {"'", '"', "`"}:
                quote = char
                index += 1
                continue
            if raw_line.startswith("<<<", index):
                marker = re.match(r"<<<\s*['\"]?(?P<name>[A-Za-z_]\w*)", raw_line[index:])
                if marker:
                    heredoc_end = marker.group("name")
                    break
            if char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth = max(0, paren_depth - 1)
            elif char == "[":
                bracket_depth += 1
            elif char == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif char in ";{}" and paren_depth == 0 and bracket_depth == 0:
                boundary = True
            index += 1

        if stripped.startswith("<") and not stripped.startswith(("<?php", "<?")):
            boundary = True
        if (
            paren_depth == 0
            and bracket_depth == 0
            and re.match(r"^(?:if|elseif|else\s+if|while|for|foreach|switch)\s*\(.*\)\s*$", stripped, re.IGNORECASE)
        ):
            boundary = True
        if boundary and quote is None and not block_comment and heredoc_end is None and paren_depth == 0 and bracket_depth == 0:
            flush()
        elif len(buffer) >= 128 or buffer_bytes >= 128 * 1024:
            flush()
            paren_depth = 0
            bracket_depth = 0
            quote = None
            escaped = False
            block_comment = False
            heredoc_end = None

    if buffer:
        flush()
    expanded: list[tuple[int, str]] = []
    for start, statement in output:
        expanded.extend(_split_embedded_closure(start, statement) or [(start, statement)])
    return expanded
