"""Versionable framework facts layered on top of the generic Python AST facts.

The core scanner deliberately knows only the Python language.  This module adds
small, conservative models for framework conventions that do not appear as
ordinary function calls: Django/DRF request containers, FastAPI dependencies,
and framework-specific SQL/XSS APIs.  Keeping them here makes the models
auditable and lets new framework packs be added without making the generic AST
visitor increasingly heuristic.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import CodeAnchor, CodeFacts, FunctionFact, SanitizerFact, SinkFact, SourceFact
from .utils import normalize_path, sha256_text, stable_id


@dataclass(frozen=True)
class FrameworkModel:
    """A named, versioned semantic model pack exposed in scan diagnostics."""

    id: str
    description: str


FRAMEWORK_MODELS: tuple[FrameworkModel, ...] = (
    FrameworkModel("django-drf-v1", "Django/DRF request containers, raw SQL, HTML-safe APIs and permission decorators."),
    FrameworkModel("fastapi-v1", "FastAPI dependency/security guards and request container aliases."),
)


RAW_SQL_TAXONOMY = ("sql_injection", ["CWE-89"])
HTML_TAXONOMY = ("cross_site_scripting", ["CWE-79"])


def augment_framework_facts(repo_path: Path, facts: CodeFacts) -> None:
    """Append conservative framework facts to AST-parsed Python files.

    Facts are only added when the AST provides a concrete call/attribute anchor.
    Parse failures are diagnosed but never make a scan fail.  The generic scanner
    performs its normal stable-ID de-duplication immediately after this function.
    """

    diagnostics = facts.analysis_diagnostics.setdefault(
        "framework_models",
        {
            "enabled": True,
            "models": [model.id for model in FRAMEWORK_MODELS],
            "files": 0,
            "sources": 0,
            "sinks": 0,
            "guards": 0,
            "errors": [],
        },
    )
    functions = {(normalize_path(item.anchor.file), item.anchor.start_line, item.name): item for item in facts.functions}
    known_classes = {
        name
        for item in facts.classes
        if normalize_path(item.anchor.file).endswith(".py")
        for name in (item.name, item.qualified_name)
        if name
    }
    for indexed in facts.files:
        if indexed.language != "python" or indexed.skipped_reason or indexed.parsed_by != "ast":
            continue
        path = (repo_path / indexed.path).resolve()
        try:
            path.relative_to(repo_path)
            content = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=indexed.path, type_comments=True)
        except (OSError, SyntaxError, ValueError) as exc:
            diagnostics["errors"].append({"path": indexed.path, "error": f"{type(exc).__name__}: {exc}"})
            continue
        collector = _FrameworkFactCollector(
            file=normalize_path(indexed.path),
            content=content,
            functions=functions,
            known_classes=known_classes,
        )
        collector.visit(tree)
        facts.sources.extend(collector.sources)
        facts.sinks.extend(collector.sinks)
        facts.sanitizers.extend(collector.sanitizers)
        if collector.receiver_types:
            python_symbols = facts.analysis_diagnostics.setdefault("python_symbols", {"receiver_types": []})
            receivers = python_symbols.setdefault("receiver_types", [])
            if isinstance(receivers, list):
                receivers.extend(collector.receiver_types)
        diagnostics["files"] += 1
        diagnostics["sources"] += len(collector.sources)
        diagnostics["sinks"] += len(collector.sinks)
        diagnostics["guards"] += len(collector.sanitizers)


class _FrameworkFactCollector(ast.NodeVisitor):
    def __init__(
        self,
        *,
        file: str,
        content: str,
        functions: dict[tuple[str, int, str], FunctionFact],
        known_classes: set[str] | None = None,
    ) -> None:
        self.file = file
        self.lines = content.splitlines()
        self.functions = functions
        self.known_classes = known_classes or set()
        self.parents: dict[ast.AST, ast.AST] = {}
        self.aliases: dict[str, str] = {}
        self.sources: list[SourceFact] = []
        self.sinks: list[SinkFact] = []
        self.sanitizers: list[SanitizerFact] = []
        self.receiver_types: list[dict[str, Any]] = []
        self._function_stack: list[FunctionFact | None] = []
        self._class_guard_stack: list[bool] = []
        self._local_types_stack: list[dict[str, list[str]]] = []
        self._fastapi_dependency_profiles: dict[str, set[str]] = {}

    @property
    def function(self) -> FunctionFact | None:
        return self._function_stack[-1] if self._function_stack else None

    def visit_Module(self, node: ast.Module) -> None:
        self.parents = {child: parent for parent in ast.walk(node) for child in ast.iter_child_nodes(parent)}
        self.aliases = _collect_import_aliases(node)
        self._fastapi_dependency_profiles = _build_fastapi_dependency_profiles(node, self.aliases)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        inherited_guard = any(_looks_like_guard(_resolved_name(base, self.aliases)) for base in node.bases)
        local_guard = any(
            isinstance(statement, ast.Assign)
            and any(_target_name(target) == "permission_classes" for target in statement.targets)
            and _contains_permission_marker(statement.value)
            for statement in node.body
        )
        self._class_guard_stack.append(inherited_guard or local_guard)
        self.generic_visit(node)
        self._class_guard_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        function = self.functions.get((self.file, node.lineno, node.name))
        self._function_stack.append(function)
        local_types: dict[str, list[str]] = {}
        for parameter, _default, annotation in _function_parameters(node):
            if annotation is not None and (type_name := _annotation_type_name(annotation, self.aliases)):
                local_types[parameter.arg] = [type_name]
        self._local_types_stack.append(local_types)
        if function and (self._class_guard_stack[-1] if self._class_guard_stack else False):
            self._add_guard(node, "class permission policy")
        if function and (
            any(_decorator_is_guard(decorator, self.aliases) for decorator in node.decorator_list)
            or _parameters_have_authorization_dependency(node, self.aliases)
        ):
            self._add_guard(node, "decorator/dependency permission guard")
        if function:
            self._add_fastapi_dependency_sources(node, function)
        self.generic_visit(node)
        popped_types = self._local_types_stack.pop()
        if function and popped_types:
            for receiver, types in popped_types.items():
                self.receiver_types.append(
                    {
                        "file": self.file,
                        "function_id": function.id,
                        "receiver": receiver,
                        "types": types,
                        "language": "python",
                    }
                )
        self._function_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._local_types_stack and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Call) and (ctor := _constructor_type_name(node.value, self.aliases, self.known_classes)):
                self._local_types_stack[-1][node.targets[0].id] = [ctor]
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if self._local_types_stack and isinstance(node.target, ast.Name):
            type_name = _annotation_type_name(node.annotation, self.aliases)
            if not type_name and isinstance(node.value, ast.Call):
                type_name = _constructor_type_name(node.value, self.aliases, self.known_classes)
            if type_name:
                self._local_types_stack[-1][node.target.id] = [type_name]
        self.generic_visit(node)

    def _add_fastapi_dependency_sources(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        function: FunctionFact,
    ) -> None:
        for parameter, default, annotation in _function_parameters(node):
            dependency_names = _fastapi_dependency_names(default, annotation, self.aliases)
            if not dependency_names:
                continue
            kinds = {kind for dependency_name in dependency_names for kind in self._fastapi_dependency_profiles.get(dependency_name, set())}
            for kind in sorted(kinds):
                anchor = self._anchor(parameter, parameter.arg)
                dependency_label = ", ".join(sorted(dependency_names))
                self.sources.append(
                    SourceFact(
                        id=stable_id(
                            "framework-dependency-source",
                            self.file,
                            parameter.lineno,
                            f"{kind}:{function.id}:{parameter.arg}:{dependency_label}",
                        ),
                        kind=kind,
                        expression=(f"FastAPI dependency parameter {parameter.arg} receives {kind} from {dependency_label}"),
                        anchor=anchor,
                        confidence="medium",
                        variables=[parameter.arg],
                        input_variables=[parameter.arg],
                        enclosing_function_id=function.id,
                        analysis_method="ast",
                    )
                )

    def visit_Call(self, node: ast.Call) -> None:
        source_kind = _request_source_kind(node, self.aliases)
        if source_kind:
            self._add_source(node, source_kind)
        sink = _framework_sink(node, self.aliases)
        if sink:
            kind, vuln_class, taxonomy_id, cwe_ids, variables = sink
            self._add_sink(node, kind, vuln_class, taxonomy_id, cwe_ids, variables)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        parent = self.parents.get(node)
        if not (isinstance(parent, ast.Call) and parent.func is node) and not self._inside_more_specific_source_call(node):
            source_kind = _request_source_kind(node, self.aliases)
            if source_kind:
                self._add_source(node, source_kind)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        source_kind = _request_source_kind(node, self.aliases)
        if source_kind:
            self._add_source(node, source_kind)
        self.generic_visit(node)

    def _add_source(self, node: ast.AST, kind: str) -> None:
        function = self.function
        if not function:
            return
        variables = _assigned_targets(node, self.parents)
        if not variables:
            variables = [_call_token(node, self.aliases)] if isinstance(node, ast.Call) else [_access_path(node)]
        variables = [value for value in variables if value]
        if not variables:
            return
        anchor = self._anchor(node, variables[0])
        self.sources.append(
            SourceFact(
                id=stable_id(
                    "framework-source", self.file, node.lineno, f"{kind}:{function.id}:{ast.dump(node, include_attributes=False)}"
                ),
                kind=kind,
                expression=_node_text(node),
                anchor=anchor,
                confidence="high" if kind in {"http_query", "http_body", "http_path"} else "medium",
                variables=variables,
                input_variables=variables,
                enclosing_function_id=function.id,
                analysis_method="ast",
            )
        )

    def _add_sink(
        self,
        node: ast.Call,
        kind: str,
        vuln_class: str,
        taxonomy_id: str,
        cwe_ids: list[str],
        variables: list[str],
    ) -> None:
        function = self.function
        if not function or not variables:
            return
        self.sinks.append(
            SinkFact(
                id=stable_id("framework-sink", self.file, node.lineno, f"{kind}:{function.id}:{ast.dump(node, include_attributes=False)}"),
                kind=kind,
                vuln_class=vuln_class,  # type: ignore[arg-type]
                expression=_node_text(node),
                anchor=self._anchor(node, kind),
                confidence="high",
                variables=variables,
                enclosing_function_id=function.id,
                analysis_method="ast",
                taxonomy_id=taxonomy_id,
                cwe_ids=cwe_ids,
            )
        )

    def _add_guard(self, node: ast.AST, reason: str) -> None:
        function = self.function
        if not function:
            return
        self.sanitizers.append(
            SanitizerFact(
                id=stable_id(
                    "framework-guard", self.file, node.lineno, f"{function.id}:{reason}:{ast.dump(node, include_attributes=False)}"
                ),
                kind="authorization_guard",
                expression=reason,
                anchor=self._anchor(node, "authorization_guard"),
                confidence="high",
                variables=[],
                input_variables=[],
                enclosing_function_id=function.id,
                analysis_method="ast",
                applies_to_sink_kinds=["authorization_decision"],
            )
        )

    def _anchor(self, node: ast.AST, symbol: str) -> CodeAnchor:
        line = max(1, int(getattr(node, "lineno", 1) or 1))
        end_line = max(line, int(getattr(node, "end_lineno", line) or line))
        snippet = "\n".join(self.lines[line - 1 : end_line])
        return CodeAnchor(
            file=self.file,
            start_line=line,
            end_line=end_line,
            snippet_hash=sha256_text(snippet),
            symbol=symbol,
            start_col=getattr(node, "col_offset", None),
            end_col=getattr(node, "end_col_offset", None),
        )

    def _inside_more_specific_source_call(self, node: ast.AST) -> bool:
        """Avoid recording both ``request.GET`` and ``request.GET.get(...)``."""

        current = node
        while current in self.parents:
            parent = self.parents[current]
            if isinstance(parent, ast.Call) and _request_source_kind(parent, self.aliases):
                return True
            if isinstance(parent, ast.stmt):
                return False
            current = parent
        return False


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _resolved_name(node: ast.AST, aliases: dict[str, str]) -> str:
    raw = _qualified_name(node)
    root, dot, rest = raw.partition(".")
    resolved = aliases.get(root)
    if not resolved:
        return raw
    return f"{resolved}.{rest}" if dot else resolved


_BUILTIN_TYPE_NAMES = {
    "str",
    "int",
    "float",
    "bool",
    "bytes",
    "bytearray",
    "list",
    "dict",
    "set",
    "frozenset",
    "tuple",
    "object",
    "none",
    "any",
    "optional",
    "union",
    "callable",
    "sequence",
    "mapping",
    "iterable",
    "iterator",
    "generator",
    "coroutine",
}


def _constructor_type_name(call: ast.Call, aliases: dict[str, str], known_classes: set[str] | None = None) -> str:
    name = _resolved_name(call.func, aliases)
    tail = name.rsplit(".", 1)[-1]
    if not tail or tail.lower() in _BUILTIN_TYPE_NAMES:
        return ""
    if tail[0].isupper() or (known_classes and (tail in known_classes or name in known_classes)):
        return name
    return ""


def _annotation_type_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Subscript):
        base = _resolved_name(node.value, aliases).rsplit(".", 1)[-1]
        if base in {"Optional", "Annotated"}:
            inner = node.slice.elts[0] if isinstance(node.slice, ast.Tuple) and node.slice.elts else node.slice
            return _annotation_type_name(inner, aliases)
        return ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        tail = node.value.strip().rsplit(".", 1)[-1]
        return node.value.strip() if tail and tail.lower() not in _BUILTIN_TYPE_NAMES else ""
    name = _resolved_name(node, aliases)
    tail = name.rsplit(".", 1)[-1]
    if not name or not tail or tail.lower() in _BUILTIN_TYPE_NAMES:
        return ""
    return name


def _access_path(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _access_path(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    if isinstance(node, ast.Subscript):
        parent = _access_path(node.value)
        if not parent:
            return ""
        if isinstance(node.slice, ast.Constant):
            return f"{parent}[{node.slice.value!r}]"
        return f"{parent}[*]"
    return ""


def _node_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001 - a source expression is diagnostic-only
        return node.__class__.__name__


def _call_token(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Call):
        return f"@call:{_resolved_name(node.func, aliases)}:{node.lineno}:{node.col_offset}"
    return ""


def _assigned_targets(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> list[str]:
    current = node
    while current in parents:
        parent = parents[current]
        if isinstance(parent, ast.Assign) and current is parent.value:
            return [name for target in parent.targets for name in _target_names(target)]
        if isinstance(parent, ast.AnnAssign) and current is parent.value:
            return _target_names(parent.target)
        if isinstance(parent, ast.NamedExpr) and current is parent.value:
            return _target_names(parent.target)
        if isinstance(parent, ast.stmt):
            break
        current = parent
    return []


def _target_names(node: ast.AST) -> list[str]:
    path = _access_path(node)
    if path:
        return [path]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _target_names(item)]
    return []


def _target_name(node: ast.AST) -> str:
    names = _target_names(node)
    return names[0] if names else ""


@dataclass(frozen=True)
class _FastAPIDependencyFunction:
    direct_parameter_kinds: dict[str, set[str]]
    parameter_dependencies: dict[str, set[str]]
    output_parameters: set[str]


def _function_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.arg, ast.AST | None, ast.AST | None]]:
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults: list[ast.AST | None] = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
    parameters = [
        (argument, default, argument.annotation)
        for argument, default in zip(positional, defaults, strict=True)
        if argument.arg not in {"self", "cls"}
    ]
    parameters.extend(
        (argument, default, argument.annotation) for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
    )
    return parameters


def _fastapi_parameter_input_kind(
    default: ast.AST | None,
    annotation: ast.AST | None,
    aliases: dict[str, str],
) -> str | None:
    kinds = {
        "query": "http_query",
        "path": "http_path",
        "header": "http_header",
        "cookie": "cookie",
        "body": "http_body",
        "form": "http_body",
    }
    for container in (default, annotation):
        if container is None:
            continue
        for item in ast.walk(container):
            if not isinstance(item, ast.Call):
                continue
            marker = _resolved_name(item.func, aliases).rsplit(".", 1)[-1].lower()
            if marker in kinds:
                return kinds[marker]
    return None


def _fastapi_dependency_names(
    default: ast.AST | None,
    annotation: ast.AST | None,
    aliases: dict[str, str],
) -> set[str]:
    names: set[str] = set()
    for container in (default, annotation):
        if container is None:
            continue
        for item in ast.walk(container):
            if not isinstance(item, ast.Call):
                continue
            marker = _resolved_name(item.func, aliases).rsplit(".", 1)[-1].lower()
            if marker not in {"depends", "security"}:
                continue
            dependency = (
                item.args[0]
                if item.args
                else next(
                    (keyword.value for keyword in item.keywords if keyword.arg in {"dependency", "call"}),
                    None,
                )
            )
            # Only direct local names are bridged. Attribute calls and dynamic
            # factories may refer to another module or runtime callable and are
            # intentionally left for later inter-file resolution.
            if isinstance(dependency, ast.Name):
                names.add(dependency.id)
    return names


def _build_fastapi_dependency_profiles(tree: ast.Module, aliases: dict[str, str]) -> dict[str, set[str]]:
    definitions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    models: dict[str, _FastAPIDependencyFunction] = {}
    for name, node in definitions.items():
        direct: dict[str, set[str]] = {}
        dependencies: dict[str, set[str]] = {}
        parameter_names: set[str] = set()
        for parameter, default, annotation in _function_parameters(node):
            parameter_names.add(parameter.arg)
            kind = _fastapi_parameter_input_kind(default, annotation, aliases)
            if kind:
                direct.setdefault(parameter.arg, set()).add(kind)
            dependency_names = _fastapi_dependency_names(default, annotation, aliases)
            if dependency_names:
                dependencies[parameter.arg] = dependency_names & definitions.keys()
        models[name] = _FastAPIDependencyFunction(
            direct_parameter_kinds=direct,
            parameter_dependencies=dependencies,
            output_parameters=_function_output_parameters(node, parameter_names),
        )

    profiles: dict[str, set[str]] = {name: set() for name in models}
    # Dependency chains are usually shallow, but a fixed point also handles
    # wrappers declared before/after their input dependency.
    for _ in range(max(1, len(models) + 1)):
        changed = False
        for name, model in models.items():
            kinds: set[str] = set()
            for parameter in model.output_parameters:
                kinds.update(model.direct_parameter_kinds.get(parameter, set()))
                for dependency_name in model.parameter_dependencies.get(parameter, set()):
                    kinds.update(profiles.get(dependency_name, set()))
            if not kinds.issubset(profiles[name]):
                profiles[name].update(kinds)
                changed = True
        if not changed:
            break
    return {name: kinds for name, kinds in profiles.items() if kinds}


def _function_output_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parameter_names: set[str],
) -> set[str]:
    nodes = list(_walk_function_body(node))
    influences: dict[str, set[str]] = {name: {name} for name in parameter_names}
    for _ in range(max(1, len(nodes) + 1)):
        changed = False
        for item in nodes:
            targets: list[str] = []
            value: ast.AST | None = None
            if isinstance(item, ast.Assign):
                targets = [name for target in item.targets for name in _target_names(target)]
                value = item.value
            elif isinstance(item, ast.AnnAssign) and item.value is not None:
                targets = _target_names(item.target)
                value = item.value
            elif isinstance(item, ast.NamedExpr):
                targets = _target_names(item.target)
                value = item.value
            elif isinstance(item, ast.AugAssign):
                targets = _target_names(item.target)
                value = item.value
            if not targets or value is None:
                continue
            source_parameters = _expression_parameter_influences(value, influences)
            for target in targets:
                target_root = _variable_root(target)
                before = set(influences.get(target_root, set()))
                influences.setdefault(target_root, set()).update(source_parameters)
                changed = changed or before != influences[target_root]
        if not changed:
            break

    returned: set[str] = set()
    parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    for item in nodes:
        value: ast.AST | None = None
        if isinstance(item, (ast.Return, ast.Yield, ast.YieldFrom)):
            value = item.value
        if value is None:
            continue
        returned.update(_expression_parameter_influences(value, influences))
        current: ast.AST = item
        while current in parents:
            current = parents[current]
            if isinstance(current, ast.If):
                returned.update(_expression_parameter_influences(current.test, influences))
            elif isinstance(current, (ast.For, ast.AsyncFor, ast.comprehension)):
                returned.update(_expression_parameter_influences(current.iter, influences))
            elif isinstance(current, ast.While):
                returned.update(_expression_parameter_influences(current.test, influences))
            elif isinstance(current, ast.Match):
                returned.update(_expression_parameter_influences(current.subject, influences))
            if current is node:
                break
    return returned


def _walk_function_body(node: ast.FunctionDef | ast.AsyncFunctionDef):  # noqa: ANN202 - internal AST iterator
    stack: list[ast.AST] = list(reversed(node.body))
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(current))))


def _expression_parameter_influences(node: ast.AST, influences: dict[str, set[str]]) -> set[str]:
    result: set[str] = set()
    for variable in _variables(node):
        result.update(influences.get(_variable_root(variable), set()))
    return result


def _variable_root(value: str) -> str:
    return value.split(".", 1)[0].split("[", 1)[0]


def _variables(node: ast.AST) -> list[str]:
    values: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_Name(self, item: ast.Name) -> None:
            if isinstance(item.ctx, ast.Load):
                values.append(item.id)

        def visit_Attribute(self, item: ast.Attribute) -> None:
            path = _access_path(item)
            if path:
                values.append(path)
                return
            self.generic_visit(item)

        def visit_Subscript(self, item: ast.Subscript) -> None:
            path = _access_path(item)
            if path:
                values.append(path)
                return
            self.generic_visit(item)

    Visitor().visit(node)
    return list(dict.fromkeys(values))


def _request_source_kind(node: ast.AST, aliases: dict[str, str]) -> str | None:
    expression = _resolved_name(node.func, aliases) if isinstance(node, ast.Call) else _resolved_name(node, aliases)
    if not expression:
        expression = _access_path(node)
    lowered = expression.lower()
    if any(marker in lowered for marker in ("request.get", "request.query_params", "request.getlist", "kwargs.get", "kwargs[")):
        return "http_query" if "kwargs" not in lowered else "http_path"
    if any(marker in lowered for marker in ("request.post", "request.data", "request.json", "request.initial_data", "validated_data")):
        return "http_body"
    if any(marker in lowered for marker in ("request.files", "request.file", "uploadedfile")):
        return "file_upload"
    if any(marker in lowered for marker in ("request.headers", "request.meta.get('http_", 'request.meta.get("http_')):
        return "http_header"
    if any(marker in lowered for marker in ("request.cookies", "request.session", "request.auth")):
        return "cookie"
    if "request.path_params" in lowered or "request.resolver_match.kwargs" in lowered:
        return "http_path"
    if any(marker in lowered for marker in ("websocket.receive_json", "websocket.receive_text")):
        return "websocket_message"
    return None


def _framework_sink(node: ast.Call, aliases: dict[str, str]) -> tuple[str, str, str, list[str], list[str]] | None:
    name = _resolved_name(node.func, aliases).lower()
    last = name.rsplit(".", 1)[-1]
    first_argument = _variables(node.args[0]) if node.args else []
    if last in {"rawsql", "extra"} or name.endswith(".extra"):
        return "raw_sql", "injection", RAW_SQL_TAXONOMY[0], list(RAW_SQL_TAXONOMY[1]), first_argument
    if last in {"mark_safe", "safestring"} or name.endswith(".mark_safe"):
        return "html_output", "xss", HTML_TAXONOMY[0], list(HTML_TAXONOMY[1]), first_argument
    if last == "template" and first_argument:
        return "html_output", "xss", HTML_TAXONOMY[0], list(HTML_TAXONOMY[1]), first_argument
    return None


def _looks_like_guard(name: str) -> bool:
    compact = "".join(char for char in name.lower() if char.isalnum())
    # Authentication alone does not prove object-level authorization.  Only model
    # names which explicitly express a permission/role/tenant/owner decision are
    # allowed to suppress an IDOR-style candidate.
    return any(
        marker in compact
        for marker in (
            "permission",
            "admin",
            "role",
            "authorize",
            "policy",
            "owner",
            "tenant",
        )
    )


def _contains_permission_marker(node: ast.AST) -> bool:
    return any(_looks_like_guard(_qualified_name(item)) for item in ast.walk(node) if isinstance(item, (ast.Name, ast.Attribute)))


def _decorator_is_guard(node: ast.AST, aliases: dict[str, str]) -> bool:
    if _looks_like_guard(_resolved_name(node.func, aliases) if isinstance(node, ast.Call) else _resolved_name(node, aliases)):
        return True
    if not isinstance(node, ast.Call):
        return False
    decorator_name = _resolved_name(node.func, aliases).lower()
    if decorator_name.rsplit(".", 1)[-1] not in {"get", "post", "put", "patch", "delete", "route", "api_route"}:
        return False
    for keyword in node.keywords:
        if keyword.arg == "dependencies" and any(
            isinstance(item, ast.Call) and _looks_like_guard(_resolved_name(item.args[0], aliases) if item.args else "")
            for item in getattr(keyword.value, "elts", [])
        ):
            return True
    return False


def _parameters_have_authorization_dependency(node: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]) -> bool:
    defaults = [*node.args.defaults, *[default for default in node.args.kw_defaults if default is not None]]
    for default in defaults:
        if not isinstance(default, ast.Call):
            continue
        dependency = _resolved_name(default.func, aliases).rsplit(".", 1)[-1].lower()
        if dependency not in {"depends", "security"} or not default.args:
            continue
        if _looks_like_guard(_resolved_name(default.args[0], aliases)):
            return True
    return False
