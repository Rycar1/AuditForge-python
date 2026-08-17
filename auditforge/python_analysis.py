from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

from .models import (
    CallSiteFact,
    ClassFact,
    CodeAnchor,
    ControlFlowFact,
    DataFlowFact,
    FunctionFact,
    RouteFact,
    SanitizerFact,
    SinkFact,
    SourceFact,
)
from .utils import sha256_text, stable_id


@dataclass
class PythonAnalysisResult:
    functions: list[FunctionFact] = field(default_factory=list)
    classes: list[ClassFact] = field(default_factory=list)
    routes: list[RouteFact] = field(default_factory=list)
    call_sites: list[CallSiteFact] = field(default_factory=list)
    data_flows: list[DataFlowFact] = field(default_factory=list)
    control_flows: list[ControlFlowFact] = field(default_factory=list)
    sources: list[SourceFact] = field(default_factory=list)
    sinks: list[SinkFact] = field(default_factory=list)
    sanitizers: list[SanitizerFact] = field(default_factory=list)


TAXONOMY_BY_SINK: dict[str, tuple[str, list[str]]] = {
    "raw_sql": ("sql_injection", ["CWE-89"]),
    "command_execution": ("command_injection", ["CWE-78"]),
    "file_path": ("path_traversal", ["CWE-22"]),
    "deserialization": ("unsafe_deserialization", ["CWE-502"]),
    "html_output": ("cross_site_scripting", ["CWE-79"]),
    "external_request": ("server_side_request_forgery", ["CWE-918"]),
    "auth_primitive": ("authentication_failure", ["CWE-287"]),
    "authorization_decision": ("authorization_failure", ["CWE-862"]),
}


def analyze_python(source_file: Any) -> PythonAnalysisResult:
    """Parse one Python file and extract syntax-aware, scope-aware security facts.

    ``SyntaxError`` is deliberately allowed to escape. The repository scanner records
    it and falls back to explicitly labelled heuristic analysis for that file.
    """

    tree = ast.parse(source_file.content, filename=source_file.file.path, type_comments=True)
    parents = _parent_map(tree)
    import_aliases = _collect_import_aliases(tree, source_file.file.path)
    collector = _DefinitionCollector(source_file)
    collector.visit(tree)
    analyzer = _SemanticAnalyzer(source_file, parents, collector, import_aliases)
    analyzer.visit(tree)
    analyzer.add_route_parameter_sources()
    return analyzer.result


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _module_name(file_path: str) -> str:
    parts = file_path.replace("\\", "/").split("/")
    if not parts or not parts[-1].endswith(".py"):
        return ""
    parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(part for part in parts if part)


def _collect_import_aliases(tree: ast.AST, file_path: str) -> dict[str, str]:
    """Return import aliases resolved to repository-style dotted module names.

    The facts model intentionally stays language-neutral, so Python import resolution
    is encoded in the call-site callee name.  This is sufficient for the repository
    level call graph to distinguish ``a.load`` from ``b.load`` without persisting a
    second Python-only fact type.
    """

    aliases: dict[str, str] = {}
    module = _module_name(file_path)
    package_parts = module.split(".")[:-1] if module else []
    if file_path.replace("\\", "/").endswith("/__init__.py") or file_path == "__init__.py":
        package_parts = module.split(".") if module else []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".", 1)[0]
                aliases[local] = item.name if item.asname else local
        elif isinstance(node, ast.ImportFrom):
            base_parts = list(package_parts)
            if node.level:
                trim = max(0, node.level - 1)
                if trim:
                    base_parts = base_parts[:-trim] if trim <= len(base_parts) else []
            else:
                base_parts = []
            if node.module:
                base_parts.extend(node.module.split("."))
            base = ".".join(base_parts)
            for item in node.names:
                if item.name == "*":
                    continue
                local = item.asname or item.name
                aliases[local] = ".".join(part for part in (base, item.name) if part)
    return aliases


def _access_path(node: ast.AST | None) -> str | None:
    """Return a stable, compact access path for names, fields and subscriptions."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _access_path(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Subscript):
        base = _access_path(node.value)
        if not base:
            return None
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            suffix = f"[{key.value!r}]"
        elif isinstance(key, ast.Constant) and isinstance(key.value, (int, float)):
            suffix = f"[{key.value}]"
        else:
            suffix = "[*]"
        return f"{base}{suffix}"
    return None


def _loaded_names(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    names: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_Attribute(self, item: ast.Attribute) -> Any:
            if isinstance(item.ctx, ast.Load):
                path = _access_path(item)
                if path:
                    names.append(path)
                    return
            self.generic_visit(item)

        def visit_Subscript(self, item: ast.Subscript) -> Any:
            if isinstance(item.ctx, ast.Load):
                path = _access_path(item)
                if path:
                    names.append(path)
                    if not isinstance(item.slice, ast.Constant):
                        self.visit(item.slice)
                    return
            self.generic_visit(item)

        def visit_Name(self, item: ast.Name) -> Any:
            if isinstance(item.ctx, ast.Load):
                names.append(item.id)

    Visitor().visit(node)
    return list(dict.fromkeys(names))


def _target_names(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        path = _access_path(node)
        return [path] if path else []
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _target_names(item)]
    return []


def _node_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)[:240]
    except (AttributeError, ValueError):
        return type(node).__name__


def _anchor(source_file: Any, node: ast.AST, symbol: str | None = None) -> CodeAnchor:
    start = max(1, int(getattr(node, "lineno", 1)))
    end = max(start, int(getattr(node, "end_lineno", start)))
    snippet = "\n".join(source_file.lines[start - 1 : end])
    return CodeAnchor(
        file=source_file.file.path,
        start_line=start,
        end_line=end,
        snippet_hash=sha256_text(snippet)[:16],
        symbol=symbol,
        start_col=getattr(node, "col_offset", None),
        end_col=getattr(node, "end_col_offset", None),
    )


def _range_anchor(source_file: Any, start: int, end: int, symbol: str) -> CodeAnchor:
    start = max(1, start)
    end = max(start, end)
    snippet = "\n".join(source_file.lines[start - 1 : end])
    return CodeAnchor(
        file=source_file.file.path,
        start_line=start,
        end_line=end,
        snippet_hash=sha256_text(snippet)[:16],
        symbol=symbol,
        start_col=0,
        end_col=None,
    )


def _function_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    out = [arg.arg for arg in args]
    if node.args.vararg:
        out.append(node.args.vararg.arg)
    if node.args.kwarg:
        out.append(node.args.kwarg.arg)
    return out


class _DefinitionCollector(ast.NodeVisitor):
    def __init__(self, source_file: Any) -> None:
        self.source_file = source_file
        self.functions: list[FunctionFact] = []
        self.classes: list[ClassFact] = []
        self.function_nodes: dict[ast.AST, FunctionFact] = {}
        self.class_nodes: dict[ast.AST, ClassFact] = {}
        self._function_stack: list[FunctionFact] = []
        self._class_stack: list[ClassFact] = []
        self._qualifier_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        qualified = ".".join([*self._qualifier_stack, node.name])
        fact = ClassFact(
            id=stable_id("class", self.source_file.file.path, node.lineno, qualified),
            name=node.name,
            anchor=_anchor(self.source_file, node, qualified),
            qualified_name=qualified,
            analysis_method="ast",
        )
        self.classes.append(fact)
        self.class_nodes[node] = fact
        self._class_stack.append(fact)
        self._qualifier_stack.append(node.name)
        self.generic_visit(node)
        self._qualifier_stack.pop()
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = ".".join([*self._qualifier_stack, node.name])
        fact = FunctionFact(
            id=stable_id("function", self.source_file.file.path, node.lineno, qualified),
            name=node.name,
            anchor=_anchor(self.source_file, node, qualified),
            params=_function_params(node),
            qualified_name=qualified,
            parent_function_id=self._function_stack[-1].id if self._function_stack else None,
            class_id=self._class_stack[-1].id if self._class_stack else None,
            analysis_method="ast",
        )
        self.functions.append(fact)
        self.function_nodes[node] = fact
        self._function_stack.append(fact)
        self._qualifier_stack.append(node.name)
        self.generic_visit(node)
        self._qualifier_stack.pop()
        self._function_stack.pop()


class _SemanticAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        source_file: Any,
        parents: dict[ast.AST, ast.AST],
        definitions: _DefinitionCollector,
        import_aliases: dict[str, str],
    ) -> None:
        self.source_file = source_file
        self.parents = parents
        self.definitions = definitions
        self.import_aliases = import_aliases
        self.result = PythonAnalysisResult(
            functions=list(definitions.functions),
            classes=list(definitions.classes),
        )
        self._function_stack: list[FunctionFact] = []
        self._function_node_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self._class_stack: list[ClassFact] = []
        self._route_functions: list[tuple[FunctionFact, RouteFact]] = []

    @property
    def scope_id(self) -> str | None:
        return self._function_stack[-1].id if self._function_stack else None

    def _resolved_name(self, node: ast.AST) -> str:
        raw = _qualified_name(node)
        if not raw:
            return ""
        root, separator, remainder = raw.partition(".")
        resolved = self.import_aliases.get(root)
        if not resolved:
            return raw
        return f"{resolved}.{remainder}" if separator else resolved

    def _call_result(self, node: ast.Call) -> str:
        callee = self._resolved_name(node.func) or _node_text(node.func)
        return f"@call:{callee}:{node.lineno}:{node.col_offset}"

    def _value_sources(self, node: ast.AST | None) -> list[str]:
        """Extract value dependencies while preserving function return identity.

        A call contributes a synthetic result path as well as its inputs.  The
        repository-level propagator removes the argument shortcut for calls it can
        resolve and therefore follows the callee's real return summary.  Keeping the
        arguments here provides a conservative fallback for unknown library calls.
        """

        if node is None:
            return []
        names: list[str] = []

        class Visitor(ast.NodeVisitor):
            def __init__(self, analyzer: _SemanticAnalyzer) -> None:
                self.analyzer = analyzer

            def visit_Call(self, item: ast.Call) -> Any:
                names.append(self.analyzer._call_result(item))
                for argument in item.args:
                    self.visit(argument)
                for keyword in item.keywords:
                    self.visit(keyword.value)

            def visit_Attribute(self, item: ast.Attribute) -> Any:
                if isinstance(item.ctx, ast.Load):
                    path = _access_path(item)
                    if path:
                        names.append(path)
                        return
                self.generic_visit(item)

            def visit_Subscript(self, item: ast.Subscript) -> Any:
                if isinstance(item.ctx, ast.Load):
                    path = _access_path(item)
                    if path:
                        names.append(path)
                        if not isinstance(item.slice, ast.Constant):
                            self.visit(item.slice)
                        return
                self.generic_visit(item)

            def visit_Name(self, item: ast.Name) -> Any:
                if isinstance(item.ctx, ast.Load):
                    names.append(item.id)

        Visitor(self).visit(node)
        return list(dict.fromkeys(names))

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._class_stack.append(self.definitions.class_nodes[node])
        for statement in node.body:
            self.visit(statement)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        fact = self.definitions.function_nodes[node]
        for route in self._routes_for_function(node, fact):
            self.result.routes.append(route)
            self._route_functions.append((fact, route))
        self._function_stack.append(fact)
        self._function_node_stack.append(node)
        for statement in node.body:
            self.visit(statement)
        self._function_node_stack.pop()
        self._function_stack.pop()

    def _routes_for_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        function: FunctionFact,
    ) -> list[RouteFact]:
        routes: list[RouteFact] = []
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            name = _qualified_name(decorator.func)
            method_name = name.rsplit(".", 1)[-1].lower()
            if method_name not in {"route", "get", "post", "put", "patch", "delete", "options", "head", "api_route"}:
                continue
            if not decorator.args or not isinstance(decorator.args[0], ast.Constant) or not isinstance(decorator.args[0].value, str):
                continue
            route_path = decorator.args[0].value
            methods: list[str] = []
            if method_name in {"route", "api_route"}:
                for keyword in decorator.keywords:
                    if keyword.arg != "methods" or not isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                        continue
                    methods = [
                        str(item.value).upper()
                        for item in keyword.value.elts
                        if isinstance(item, ast.Constant) and isinstance(item.value, str)
                    ]
            else:
                methods = [method_name.upper()]
            method = ",".join(methods) if methods else "GET"
            framework = "flask-like" if method_name == "route" else "fastapi-like"
            routes.append(
                RouteFact(
                    id=stable_id("route", self.source_file.file.path, decorator.lineno, f"{method}:{route_path}"),
                    method=method,
                    path=route_path,
                    framework=framework,
                    anchor=_anchor(self.source_file, decorator, f"{method} {route_path}"),
                    handler_function_id=function.id,
                    analysis_method="ast",
                )
            )
        return routes

    def add_route_parameter_sources(self) -> None:
        for function, route in self._route_functions:
            placeholders = set(re.findall(r"<(?:(?:[^>:]+):)?([^>]+)>|\{([^}:]+)(?::[^}]+)?}", route.path))
            names = {left or right for left, right in placeholders}
            function_node = next(
                (node for node, fact in self.definitions.function_nodes.items() if fact.id == function.id),
                None,
            )
            for param in function.params:
                kind = "http_path" if param in names else None
                if kind is None and route.framework == "fastapi-like" and function_node is not None:
                    kind = self._fastapi_parameter_source_kind(function_node, param)
                if kind is None:
                    continue
                anchor = CodeAnchor(
                    file=function.anchor.file,
                    start_line=function.anchor.start_line,
                    end_line=function.anchor.start_line,
                    snippet_hash=function.anchor.snippet_hash,
                    symbol=param,
                    start_col=function.anchor.start_col,
                    end_col=function.anchor.end_col,
                )
                self.result.sources.append(
                    SourceFact(
                        id=stable_id("source", anchor.file, anchor.start_line, f"{kind}:{function.id}:{param}"),
                        kind=kind,
                        expression=f"route parameter {param}",
                        anchor=anchor,
                        confidence="high",
                        variables=[param],
                        input_variables=[param],
                        enclosing_function_id=function.id,
                        analysis_method="ast",
                    )
                )

    def _fastapi_parameter_source_kind(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        param: str,
    ) -> str | None:
        positional = [*node.args.posonlyargs, *node.args.args]
        defaults: dict[str, ast.AST | None] = {argument.arg: None for argument in positional}
        offset = len(positional) - len(node.args.defaults)
        for index, default in enumerate(node.args.defaults):
            defaults[positional[offset + index].arg] = default
        defaults.update({argument.arg: default for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=False)})
        arguments = {argument.arg: argument for argument in [*positional, *node.args.kwonlyargs]}
        argument = arguments.get(param)
        if argument is None or param in {"self", "cls"}:
            return None
        default = defaults.get(param)
        annotation_text = _node_text(argument.annotation).lower() if argument.annotation is not None else ""
        default_name = ""
        if isinstance(default, ast.Call):
            default_name = _qualified_name(default.func).rsplit(".", 1)[-1].lower()
        combined = f"{annotation_text} {default_name}"
        if any(marker in combined for marker in ("depends", "security")):
            return None
        if default_name == "path":
            return "http_path"
        if default_name == "header":
            return "http_header"
        if default_name == "cookie":
            return "cookie"
        if default_name in {"body", "form"}:
            return "http_body"
        if default_name == "file" or "uploadfile" in annotation_text:
            return "file_upload"
        if default_name == "query":
            return "http_query"
        if any(marker in annotation_text for marker in ("request", "response", "backgroundtasks", "websocket")):
            return None
        primitive_markers = ("str", "int", "float", "bool", "bytes", "uuid", "date", "decimal", "literal")
        if not annotation_text or any(marker in annotation_text for marker in primitive_markers):
            return "http_query"
        return "http_body"

    def visit_Assign(self, node: ast.Assign) -> Any:
        sources = self._value_sources(node.value)
        expression = _node_text(node.value)
        for target_node in node.targets:
            for target in _target_names(target_node):
                self._add_assignment(node, target, sources, expression)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            for target in _target_names(node.target):
                self._add_assignment(node, target, self._value_sources(node.value), _node_text(node.value))
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        for target in _target_names(node.target):
            self._add_assignment(node, target, self._value_sources(node.value), _node_text(node.value))
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        for target in _target_names(node.target):
            sources = list(dict.fromkeys([target, *self._value_sources(node.value)]))
            self._add_assignment(node, target, sources, _node_text(node))
        self.generic_visit(node)

    def _add_assignment(self, node: ast.AST, target: str, sources: list[str], expression: str) -> None:
        self.result.data_flows.append(
            DataFlowFact(
                id=stable_id("dfg", self.source_file.file.path, node.lineno, f"assignment:{self.scope_id}:{target}:{expression}"),
                kind="assignment",
                target=target,
                sources=sources,
                expression=expression,
                anchor=_anchor(self.source_file, node, target),
                enclosing_function_id=self.scope_id,
                ssa_safe_overwrite=self._is_unconditional_literal_overwrite(node),
                analysis_method="ast",
            )
        )

    def _is_unconditional_literal_overwrite(self, node: ast.AST) -> bool:
        value = getattr(node, "value", None)
        if not isinstance(value, ast.Constant):
            return False
        parent = self.parents.get(node)
        return isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module))

    def visit_Return(self, node: ast.Return) -> Any:
        if node.value is not None:
            expression = _node_text(node.value)
            self.result.data_flows.append(
                DataFlowFact(
                    id=stable_id("dfg", self.source_file.file.path, node.lineno, f"return:{self.scope_id}:{expression}"),
                    kind="return",
                    target=None,
                    sources=self._value_sources(node.value),
                    expression=expression,
                    anchor=_anchor(self.source_file, node, "return"),
                    enclosing_function_id=self.scope_id,
                    analysis_method="ast",
                )
            )
            if self._is_html_expression(node.value):
                self._add_sink(node.value, "html_output", "xss", self._value_sources(node.value), "high")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        callee = self._resolved_name(node.func) or _node_text(node.func)
        argument_sources = [self._value_sources(arg) for arg in node.args]
        keyword_sources = {kw.arg or "**": self._value_sources(kw.value) for kw in node.keywords}
        self.result.call_sites.append(
            CallSiteFact(
                id=stable_id("callsite", self.source_file.file.path, node.lineno, f"{self.scope_id}:{callee}:{node.col_offset}"),
                callee=callee,
                anchor=_anchor(self.source_file, node, callee),
                enclosing_function_id=self.scope_id,
                argument_sources=argument_sources,
                keyword_sources=keyword_sources,
                analysis_method="ast",
            )
        )
        self.result.data_flows.append(
            DataFlowFact(
                id=stable_id("dfg", self.source_file.file.path, node.lineno, f"call:{self.scope_id}:{callee}:{node.col_offset}"),
                kind="call_argument",
                target=callee,
                sources=list(dict.fromkeys(name for names in [*argument_sources, *keyword_sources.values()] for name in names)),
                expression=_node_text(node),
                anchor=_anchor(self.source_file, node, callee),
                enclosing_function_id=self.scope_id,
                argument_sources=argument_sources,
                keyword_sources=keyword_sources,
                analysis_method="ast",
            )
        )
        source_kind = self._source_kind(node)
        if source_kind:
            self._add_source(node, source_kind)
        sink = self._sink_kind(node)
        if sink:
            kind, vuln_class, variables, confidence = sink
            self._add_sink(node, kind, vuln_class, variables, confidence)
        sanitizer = self._sanitizer_kind(node)
        if sanitizer:
            kind, applies_to = sanitizer
            self.result.sanitizers.append(
                SanitizerFact(
                    id=stable_id("sanitizer", self.source_file.file.path, node.lineno, f"{kind}:{node.col_offset}:{_node_text(node)}"),
                    kind=kind,
                    expression=_node_text(node),
                    anchor=_anchor(self.source_file, node, kind),
                    confidence="high" if kind in {"html_encoding", "parameterized_query"} else "medium",
                    variables=self._assigned_targets(node),
                    input_variables=list(dict.fromkeys(name for names in argument_sources for name in names)),
                    enclosing_function_id=self.scope_id,
                    analysis_method="ast",
                    applies_to_sink_kinds=applies_to,
                )
            )
        self._add_container_mutation(node, argument_sources, keyword_sources)
        self.generic_visit(node)

    def _add_container_mutation(
        self,
        node: ast.Call,
        argument_sources: list[list[str]],
        keyword_sources: dict[str, list[str]],
    ) -> None:
        if not isinstance(node.func, ast.Attribute):
            return
        container = _access_path(node.func.value)
        if not container:
            return
        method = node.func.attr.lower()
        flattened = list(dict.fromkeys(name for values in [*argument_sources, *keyword_sources.values()] for name in values))
        if method in {"append", "extend", "add", "insert"} and flattened:
            self._add_assignment(node, f"{container}[*]", flattened, _node_text(node))
            return
        if method not in {"update", "setdefault", "__setitem__"}:
            return
        added = False
        if node.args and isinstance(node.args[0], ast.Dict):
            for key, value in zip(node.args[0].keys, node.args[0].values, strict=False):
                if isinstance(key, ast.Constant) and isinstance(key.value, (str, int, float)):
                    suffix = f"[{key.value!r}]" if isinstance(key.value, str) else f"[{key.value}]"
                    self._add_assignment(node, f"{container}{suffix}", self._value_sources(value), _node_text(node))
                    added = True
        elif method in {"setdefault", "__setitem__"} and len(node.args) >= 2:
            key = node.args[0]
            if isinstance(key, ast.Constant) and isinstance(key.value, (str, int, float)):
                suffix = f"[{key.value!r}]" if isinstance(key.value, str) else f"[{key.value}]"
                self._add_assignment(node, f"{container}{suffix}", self._value_sources(node.args[1]), _node_text(node))
                added = True
        for keyword in node.keywords:
            if keyword.arg:
                self._add_assignment(
                    node,
                    f"{container}[{keyword.arg!r}]",
                    self._value_sources(keyword.value),
                    _node_text(node),
                )
                added = True
        if not added and flattened:
            self._add_assignment(node, f"{container}[*]", flattened, _node_text(node))

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        if not isinstance(self.parents.get(node), ast.Call):
            source_kind = self._source_kind(node)
            if source_kind:
                self._add_source(node, source_kind)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> Any:
        source_kind = self._source_kind(node)
        if source_kind:
            self._add_source(node, source_kind)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> Any:
        kind = "elif" if isinstance(self.parents.get(node), ast.If) and node in self.parents[node].orelse else "if"
        self._add_control(node.test, kind)
        self._add_guard_region(node)
        if self._is_authorization_decision(node.test):
            self._add_sink(node.test, "authorization_decision", "authz", _loaded_names(node.test), "medium")
        self.generic_visit(node)

    def _add_guard_region(self, node: ast.If) -> None:
        condition = node.test
        validation_passes = True
        if isinstance(condition, ast.UnaryOp) and isinstance(condition.op, ast.Not):
            validation_passes = False
            condition = condition.operand
        if not isinstance(condition, ast.Call):
            return
        sanitizer = self._sanitizer_kind(condition)
        if sanitizer is None:
            return
        sanitizer_kind, applies_to = sanitizer
        if sanitizer_kind not in {"url_validation", "type_validation", "authorization_guard"}:
            return
        inputs = list(
            dict.fromkeys(
                name
                for value in [*condition.args, *(keyword.value for keyword in condition.keywords)]
                for name in self._value_sources(value)
            )
        )
        if not inputs:
            return

        protected: tuple[int, int] | None = None
        if validation_passes and node.body:
            protected = (node.body[0].lineno, int(getattr(node.body[-1], "end_lineno", node.body[-1].lineno)))
        elif not validation_passes and self._block_terminates(node.body):
            protected = self._guard_continuation(node)
        if protected is None:
            return
        start, end = protected
        anchor = _range_anchor(self.source_file, start, end, f"guard:{sanitizer_kind}")
        expression = _node_text(node.test)
        self.result.sanitizers.append(
            SanitizerFact(
                id=stable_id(
                    "sanitizer",
                    self.source_file.file.path,
                    node.lineno,
                    f"guard:{sanitizer_kind}:{self.scope_id}:{start}:{end}:{expression}",
                ),
                kind=sanitizer_kind,
                expression=f"guarded-region: {expression}",
                anchor=anchor,
                confidence="high" if sanitizer_kind in {"html_encoding", "url_validation"} else "medium",
                variables=inputs,
                input_variables=inputs,
                enclosing_function_id=self.scope_id,
                analysis_method="ast",
                applies_to_sink_kinds=applies_to,
            )
        )

    @staticmethod
    def _block_terminates(statements: list[ast.stmt]) -> bool:
        return bool(statements) and isinstance(statements[-1], (ast.Return, ast.Raise))

    def _guard_continuation(self, node: ast.If) -> tuple[int, int] | None:
        if not self._function_node_stack:
            return None
        function_node = self._function_node_stack[-1]
        if self.parents.get(node) is not function_node:
            return None
        try:
            index = function_node.body.index(node)
        except ValueError:
            return None
        following = function_node.body[index + 1 :]
        if not following:
            return None
        return following[0].lineno, int(getattr(following[-1], "end_lineno", following[-1].lineno))

    def visit_For(self, node: ast.For) -> Any:
        self._add_control(node.iter, "for", region_node=node)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self._add_control(node.iter, "for", region_node=node)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> Any:
        self._add_control(node.test, "while", region_node=node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> Any:
        anchor_node = node.type or node
        self._add_control(anchor_node, "catch")
        self.generic_visit(node)

    def _add_control(self, node: ast.AST, kind: str, *, region_node: ast.AST | None = None) -> None:
        expression = _node_text(node)
        self.result.control_flows.append(
            ControlFlowFact(
                id=stable_id("cfg", self.source_file.file.path, node.lineno, f"{kind}:{self.scope_id}:{expression}"),
                kind=kind,  # type: ignore[arg-type]
                condition=expression,
                variables=_loaded_names(node),
                anchor=_anchor(self.source_file, region_node or node, kind),
                enclosing_function_id=self.scope_id,
                analysis_method="ast",
            )
        )

    def _add_source(self, node: ast.AST, kind: str) -> None:
        expression = _node_text(node)
        variables = self._assigned_targets(node)
        if not variables:
            if isinstance(node, ast.Call):
                variables = [self._call_result(node)]
            else:
                path = _access_path(node)
                variables = [path] if path else []
        self.result.sources.append(
            SourceFact(
                id=stable_id("source", self.source_file.file.path, node.lineno, f"{kind}:{node.col_offset}:{expression}"),
                kind=kind,
                expression=expression,
                anchor=_anchor(self.source_file, node, kind),
                confidence="high" if kind in {"http_query", "http_body", "http_path"} else "medium",
                variables=variables,
                input_variables=_loaded_names(node),
                enclosing_function_id=self.scope_id,
                analysis_method="ast",
            )
        )

    def _add_sink(
        self,
        node: ast.AST,
        kind: str,
        vuln_class: str,
        variables: list[str],
        confidence: str,
    ) -> None:
        taxonomy_id, cwe_ids = TAXONOMY_BY_SINK[kind]
        expression = _node_text(node)
        self.result.sinks.append(
            SinkFact(
                id=stable_id("sink", self.source_file.file.path, node.lineno, f"{kind}:{node.col_offset}:{expression}"),
                kind=kind,
                vuln_class=vuln_class,  # type: ignore[arg-type]
                expression=expression,
                anchor=_anchor(self.source_file, node, kind),
                confidence=confidence,  # type: ignore[arg-type]
                variables=variables,
                enclosing_function_id=self.scope_id,
                analysis_method="ast",
                taxonomy_id=taxonomy_id,
                cwe_ids=cwe_ids,
            )
        )

    def _assigned_targets(self, node: ast.AST) -> list[str]:
        origin = node
        current = node
        while current in self.parents:
            parent = self.parents[current]
            if isinstance(parent, ast.Assign) and current is parent.value:
                if (
                    len(parent.targets) == 1
                    and isinstance(parent.value, (ast.Tuple, ast.List))
                    and isinstance(parent.targets[0], (ast.Tuple, ast.List))
                ):
                    for index, value_item in enumerate(parent.value.elts):
                        if index >= len(parent.targets[0].elts):
                            break
                        if any(descendant is origin for descendant in ast.walk(value_item)):
                            return _target_names(parent.targets[0].elts[index])
                return list(dict.fromkeys(name for target in parent.targets for name in _target_names(target)))
            if isinstance(parent, ast.AnnAssign) and current is parent.value:
                return _target_names(parent.target)
            if isinstance(parent, ast.NamedExpr) and current is parent.value:
                return _target_names(parent.target)
            if isinstance(parent, ast.stmt):
                break
            current = parent
        return []

    def _source_kind(self, node: ast.AST) -> str | None:
        text = _node_text(node)
        lowered = text.lower()
        if re.search(r"\b(?:request|req|ctx|c)\.(?:args|query|values)(?:\.|\[|$)", lowered):
            return "http_query"
        if re.search(r"\b(?:request|req|ctx|c)\.(?:form|json|data|post)(?:\.|\[|$)", lowered) or any(
            marker in lowered for marker in ("request.get_json(", "request.get_data(", "req.get_json(", "req.get_data(")
        ):
            return "http_body"
        if re.search(r"\b(?:request|req|ctx|c)\.(?:view_args|path_params|params)(?:\.|\[|$)", lowered):
            return "http_path"
        if re.search(r"\b(?:request|req|ctx|c)\.(?:headers|header)(?:\.|\[|$)", lowered):
            return "http_header"
        if "request.cookies" in lowered or "req.cookies" in lowered or re.search(r"\bsession(?:\.|\[)", lowered):
            return "cookie"
        if "request.files" in lowered or "uploadedfile" in lowered:
            return "file_upload"
        if any(marker in lowered for marker in ("websocket.receive", "websocket.recv", "ws.receive", "ws.recv")):
            return "websocket_message"
        return None

    def _sink_kind(self, node: ast.Call) -> tuple[str, str, list[str], str] | None:
        name = _qualified_name(node.func)
        lowered = name.lower()
        last = lowered.rsplit(".", 1)[-1]
        positional = [self._value_sources(arg) for arg in node.args]
        keywords = {keyword.arg: self._value_sources(keyword.value) for keyword in node.keywords if keyword.arg}

        def argument(index: int = 0, *keyword_names: str) -> list[str]:
            if index < len(positional):
                return positional[index]
            for keyword_name in keyword_names:
                if keyword_name in keywords:
                    return keywords[keyword_name]
            return []

        if last in {"execute", "executequery", "execsql", "raw", "createquery", "queryrow"}:
            return "raw_sql", "injection", argument(0, "statement", "query", "sql"), "high"
        if lowered in {
            "os.system",
            "os.popen",
            "subprocess.run",
            "subprocess.popen",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.check_call",
        }:
            return "command_execution", "injection", argument(0, "args", "command", "cmd"), "high"
        if last in {"open", "send_file"} or lowered in {"pathlib.path", "os.open"}:
            return "file_path", "injection", argument(0, "file", "filename", "path"), "medium"
        if lowered in {"pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "dill.loads", "cloudpickle.loads"} or last in {
            "deserialize",
            "unserialize",
        }:
            return "deserialization", "injection", argument(0, "data", "payload", "stream"), "high"
        if lowered in {"render_template_string", "flask.render_template_string", "markupsafe.markup"}:
            return "html_output", "xss", argument(0, "source", "html", "string"), "high"
        if lowered in {"urllib.request.urlopen", "requests.request", "httpx.request", "aiohttp.request"}:
            url_index = 1 if lowered.endswith(".request") and len(positional) > 1 else 0
            return "external_request", "ssrf", argument(url_index, "url"), "high"
        if any(lowered.startswith(prefix) for prefix in ("requests.", "httpx.", "aiohttp.")) and last in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
        }:
            return "external_request", "ssrf", argument(0, "url"), "high"
        if last in {"authenticate", "login_user", "verify_password", "decode_token", "verify_token"}:
            variables = list(dict.fromkeys(name for names in [*positional, *keywords.values()] for name in names))
            return "auth_primitive", "auth", variables, "medium"
        return None

    def _sanitizer_kind(self, node: ast.Call) -> tuple[str, list[str]] | None:
        lowered = _qualified_name(node.func).lower()
        resolved = self._resolved_name(node.func).lower()
        last = lowered.rsplit(".", 1)[-1]
        if last in {"escape", "escapehtml", "htmlspecialchars", "encodeforhtml", "sanitizehtml"} or resolved in {
            "bleach.clean",
            "nh3.clean",
        }:
            return "html_encoding", ["html_output"]
        if last in {"int", "float", "uuid", "parseint"} or lowered in {"uuid.uuid", "uuid.uuid4"}:
            return "type_validation", ["raw_sql", "command_execution", "file_path", "external_request"]
        if last in {"isallowedhost", "validate_url", "validateurl", "is_safe_url", "issafeurl"}:
            return "url_validation", ["external_request"]
        if last in {"requireauth", "requireuser", "requireadmin", "authorize", "haspermission"}:
            return "authorization_guard", ["authorization_decision"]
        return None

    def _is_authorization_decision(self, node: ast.AST) -> bool:
        text = _node_text(node).lower()
        markers = ("is_admin", "isadmin", "role", "permission", "owner", "tenant", "user_id", "account_id", "authorize")
        return any(marker in text for marker in markers)

    def _is_html_expression(self, node: ast.AST) -> bool:
        if not isinstance(node, (ast.JoinedStr, ast.BinOp)):
            return False
        return "<" in _node_text(node) and bool(_loaded_names(node))
