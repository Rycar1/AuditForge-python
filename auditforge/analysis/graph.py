from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from .call_resolution import CallResolver, resolution_models_from_diagnostics
from .models import CodeAnchor, CodeEdge, CodeFacts, CodeGraph, CodeNode, FunctionFact, SinkFact
from .utils import stable_id


def build_graph(
    facts: CodeFacts,
    progress_callback: Callable[[int, str], None] | None = None,
) -> CodeGraph:
    graph = CodeGraph()
    file_nodes: dict[str, str] = {}
    functions_by_file: dict[str, list[FunctionFact]] = defaultdict(list)
    for function in facts.functions:
        functions_by_file[function.anchor.file].append(function)
    resolver = CallResolver(facts.functions, facts.imports, resolution_models_from_diagnostics(facts.analysis_diagnostics))

    def report(percent: int, detail: str) -> None:
        if progress_callback:
            progress_callback(percent, detail)

    for file in facts.files:
        graph.nodes.append(
            CodeNode(
                id=file.id,
                kind="File",
                label=file.path,
                language=file.language,
                metadata={
                    "bytes": file.bytes,
                    "lines": file.lines,
                    "parsed_by": file.parsed_by,
                    "skipped_reason": file.skipped_reason,
                    "analysis_error": file.analysis_error,
                },
            )
        )
        file_nodes[file.path] = file.id

    def add_anchored(kind: str, ident: str, label: str, anchor: CodeAnchor, metadata: dict) -> None:
        graph.nodes.append(CodeNode(id=ident, kind=kind, label=label, anchor=anchor, metadata=metadata))  # type: ignore[arg-type]
        graph.edges.append(
            CodeEdge(
                from_id=file_nodes.get(anchor.file, stable_id("file", anchor.file, 1, Path(anchor.file).name)),
                to_id=ident,
                kind="DEFINES",
                confidence="high",
                evidence=f"{anchor.file}:{anchor.start_line}",
            )
        )

    for fact in facts.functions:
        add_anchored(
            "Function",
            fact.id,
            fact.qualified_name or fact.name,
            fact.anchor,
            {
                "params": fact.params,
                "qualified_name": fact.qualified_name,
                "parent_function_id": fact.parent_function_id,
                "class_id": fact.class_id,
                "analysis_method": fact.analysis_method,
            },
        )
    for fact in facts.classes:
        add_anchored(
            "Class",
            fact.id,
            fact.qualified_name or fact.name,
            fact.anchor,
            {"qualified_name": fact.qualified_name, "analysis_method": fact.analysis_method},
        )
    for fact in facts.routes:
        add_anchored(
            "Route",
            fact.id,
            f"{fact.method} {fact.path}",
            fact.anchor,
            {
                "method": fact.method,
                "path": fact.path,
                "framework": fact.framework,
                "handler_function_id": fact.handler_function_id,
                "analysis_method": fact.analysis_method,
            },
        )
    for fact in facts.sources:
        add_anchored(
            "Source",
            fact.id,
            fact.kind,
            fact.anchor,
            {
                "expression": fact.expression,
                "variables": fact.variables,
                "input_variables": fact.input_variables,
                "enclosing_function_id": fact.enclosing_function_id,
                "analysis_method": fact.analysis_method,
            },
        )
    for fact in facts.sinks:
        add_anchored(
            "Sink",
            fact.id,
            fact.kind,
            fact.anchor,
            {
                "expression": fact.expression,
                "vuln_class": fact.vuln_class,
                "variables": fact.variables,
                "enclosing_function_id": fact.enclosing_function_id,
                "analysis_method": fact.analysis_method,
                "taxonomy_id": fact.taxonomy_id,
                "cwe_ids": fact.cwe_ids,
            },
        )
    for fact in facts.sanitizers:
        add_anchored(
            "Sanitizer",
            fact.id,
            fact.kind,
            fact.anchor,
            {
                "expression": fact.expression,
                "variables": fact.variables,
                "input_variables": fact.input_variables,
                "enclosing_function_id": fact.enclosing_function_id,
                "analysis_method": fact.analysis_method,
                "applies_to_sink_kinds": fact.applies_to_sink_kinds,
            },
        )
    for fact in facts.call_sites:
        add_anchored(
            "CallSite",
            fact.id,
            fact.callee,
            fact.anchor,
            {
                "callee": fact.callee,
                "enclosing_function_id": fact.enclosing_function_id,
                "argument_sources": fact.argument_sources,
                "keyword_sources": fact.keyword_sources,
                "analysis_method": fact.analysis_method,
            },
        )
    for fact in facts.data_flows:
        add_anchored(
            "DataFlow",
            fact.id,
            fact.target or fact.kind,
            fact.anchor,
            {
                "kind": fact.kind,
                "target": fact.target,
                "sources": fact.sources,
                "expression": fact.expression,
                "enclosing_function_id": fact.enclosing_function_id,
                "argument_sources": fact.argument_sources,
                "keyword_sources": fact.keyword_sources,
                "analysis_method": fact.analysis_method,
            },
        )
    for fact in facts.control_flows:
        add_anchored(
            "ControlFlow",
            fact.id,
            fact.kind,
            fact.anchor,
            {
                "kind": fact.kind,
                "condition": fact.condition,
                "variables": fact.variables,
                "enclosing_function_id": fact.enclosing_function_id,
                "analysis_method": fact.analysis_method,
            },
        )

    report(12, "图节点已建立，正在关联变量读写关系")

    variable_nodes: dict[tuple[str, str | None, str], str] = {}

    def ensure_variable(file: str, scope_id: str | None, name: str) -> str:
        key = (file, scope_id, name)
        existing = variable_nodes.get(key)
        if existing:
            return existing
        ident = stable_id("variable", file, 1, f"{scope_id or '<module>'}:{name}")
        variable_nodes[key] = ident
        graph.nodes.append(
            CodeNode(
                id=ident,
                kind="Variable",
                label=name,
                metadata={"name": name, "file": file, "scope_id": scope_id},
            )
        )
        owner = scope_id or file_nodes.get(file)
        if owner:
            graph.edges.append(
                CodeEdge(
                    from_id=owner,
                    to_id=ident,
                    kind="DEFINES",
                    confidence="high",
                    evidence=f"scoped variable {name}",
                )
            )
        return ident

    for flow in facts.data_flows:
        scope_id = flow.enclosing_function_id or _infer_scope(flow.anchor, functions_by_file)
        for name in flow.sources:
            graph.edges.append(
                CodeEdge(
                    from_id=ensure_variable(flow.anchor.file, scope_id, name),
                    to_id=flow.id,
                    kind="READS",
                    confidence="high" if flow.analysis_method == "ast" else "medium",
                    evidence=f"{flow.anchor.file}:{flow.anchor.start_line} reads {name}",
                    metadata={"variable": name, "scope_id": scope_id, "analysis_method": flow.analysis_method},
                )
            )

        if flow.target and flow.kind == "assignment":
            graph.edges.append(
                CodeEdge(
                    from_id=flow.id,
                    to_id=ensure_variable(flow.anchor.file, scope_id, flow.target),
                    kind="WRITES",
                    confidence="high" if flow.analysis_method == "ast" else "medium",
                    evidence=f"{flow.anchor.file}:{flow.anchor.start_line} writes {flow.target}",
                    metadata={"variable": flow.target, "scope_id": scope_id, "analysis_method": flow.analysis_method},
                )
            )
        elif flow.kind == "return":
            graph.edges.append(
                CodeEdge(
                    from_id=flow.id,
                    to_id=ensure_variable(flow.anchor.file, scope_id, "@return"),
                    kind="WRITES",
                    confidence="high" if flow.analysis_method == "ast" else "medium",
                    evidence=f"{flow.anchor.file}:{flow.anchor.start_line} writes function return value",
                    metadata={"variable": "@return", "scope_id": scope_id, "analysis_method": flow.analysis_method},
                )
            )

    report(48, "变量数据流已关联，正在建立安全防护关系")

    for control in facts.control_flows:
        scope_id = control.enclosing_function_id or _infer_scope(control.anchor, functions_by_file)
        for variable in control.variables:
            graph.edges.append(
                CodeEdge(
                    from_id=ensure_variable(control.anchor.file, scope_id, variable),
                    to_id=control.id,
                    kind="READS",
                    confidence="high" if control.analysis_method == "ast" else "medium",
                    evidence=f"{control.anchor.file}:{control.anchor.start_line} branch reads {variable}",
                    metadata={"variable": variable, "scope_id": scope_id, "analysis_method": control.analysis_method},
                )
            )

    for call in facts.call_sites:
        scope_id = call.enclosing_function_id or _infer_scope(call.anchor, functions_by_file)
        argument_variables = list(
            dict.fromkeys(name for names in [*call.argument_sources, *call.keyword_sources.values()] for name in names)
        )
        for variable in argument_variables:
            graph.edges.append(
                CodeEdge(
                    from_id=ensure_variable(call.anchor.file, scope_id, variable),
                    to_id=call.id,
                    kind="READS",
                    confidence="high" if call.analysis_method == "ast" else "medium",
                    evidence=f"{call.anchor.file}:{call.anchor.start_line} call reads {variable}",
                    metadata={"variable": variable, "scope_id": scope_id, "analysis_method": call.analysis_method},
                )
            )

    for source in facts.sources:
        scope_id = source.enclosing_function_id or _infer_scope(source.anchor, functions_by_file)
        for variable in source.variables:
            graph.edges.append(
                CodeEdge(
                    from_id=source.id,
                    to_id=ensure_variable(source.anchor.file, scope_id, variable),
                    kind="WRITES",
                    confidence=source.confidence,
                    evidence=f"{source.kind} produces {variable}",
                    metadata={"variable": variable, "scope_id": scope_id},
                )
            )

    for sink in facts.sinks:
        scope_id = sink.enclosing_function_id or _infer_scope(sink.anchor, functions_by_file)
        for variable in sink.variables:
            graph.edges.append(
                CodeEdge(
                    from_id=ensure_variable(sink.anchor.file, scope_id, variable),
                    to_id=sink.id,
                    kind="READS",
                    confidence=sink.confidence,
                    evidence=f"{sink.kind} consumes {variable}",
                    metadata={"variable": variable, "scope_id": scope_id},
                )
            )

    sinks_by_scope: dict[tuple[str, str | None], list[SinkFact]] = defaultdict(list)
    sink_positions_by_scope_root: dict[tuple[str, str | None, str], set[int]] = defaultdict(set)
    for sink in facts.sinks:
        sink_scope = sink.enclosing_function_id or _infer_scope(sink.anchor, functions_by_file)
        scope_key = (sink.anchor.file, sink_scope)
        sink_position = len(sinks_by_scope[scope_key])
        sinks_by_scope[scope_key].append(sink)
        for variable in sink.variables:
            sink_positions_by_scope_root[(*scope_key, _access_path_root(variable))].add(sink_position)

    for sanitizer in facts.sanitizers:
        scope_id = sanitizer.enclosing_function_id or _infer_scope(sanitizer.anchor, functions_by_file)
        for variable in sanitizer.input_variables:
            graph.edges.append(
                CodeEdge(
                    from_id=ensure_variable(sanitizer.anchor.file, scope_id, variable),
                    to_id=sanitizer.id,
                    kind="READS",
                    confidence=sanitizer.confidence,
                    evidence=f"{sanitizer.kind} reads {variable}",
                    metadata={"variable": variable, "scope_id": scope_id},
                )
            )
        for variable in sanitizer.variables:
            graph.edges.append(
                CodeEdge(
                    from_id=sanitizer.id,
                    to_id=ensure_variable(sanitizer.anchor.file, scope_id, variable),
                    kind="WRITES",
                    confidence=sanitizer.confidence,
                    evidence=f"{sanitizer.kind} writes sanitized {variable}",
                    metadata={"variable": variable, "scope_id": scope_id},
                )
            )
        scope_key = (sanitizer.anchor.file, scope_id)
        scope_sinks = sinks_by_scope.get(scope_key, [])
        candidate_sink_positions: set[int] = set()
        for variable in sanitizer.variables:
            root = _access_path_root(variable)
            if root == "*":
                # An unknown root may overlap every access path in this scope.
                # Keep the full-scope fallback conservative so the index cannot
                # suppress a potentially protected sink.
                candidate_sink_positions = set(range(len(scope_sinks)))
                break
            candidate_sink_positions.update(sink_positions_by_scope_root.get((*scope_key, root), set()))
            if not root.startswith("@"):
                # A sink such as ``*.query`` can overlap a sanitizer rooted at
                # any concrete variable.  Special paths (for example
                # ``@return``) intentionally do not intersect wildcard paths.
                candidate_sink_positions.update(sink_positions_by_scope_root.get((*scope_key, "*"), set()))

        # Retain the original scope order while using the root index to avoid a
        # sanitizer x every-sink join.  `_paths_intersect` remains the final,
        # exact predicate for nested paths and wildcards.
        for sink_position in sorted(candidate_sink_positions):
            sink = scope_sinks[sink_position]
            shared = {
                variable
                for variable in sanitizer.variables
                if any(_paths_intersect(variable, sink_variable) for sink_variable in sink.variables)
            }
            if (
                shared
                and sanitizer.anchor.start_line <= sink.anchor.start_line
                and _sanitizer_applies(sanitizer.kind, sanitizer.applies_to_sink_kinds, sink.kind, sink.vuln_class)
            ):
                graph.edges.append(
                    CodeEdge(
                        from_id=sanitizer.id,
                        to_id=sink.id,
                        kind="GUARDED_BY",
                        confidence=sanitizer.confidence,
                        evidence=f"{sanitizer.kind} sanitizes {', '.join(sorted(shared))} for {sink.kind}",
                        metadata={"variables": sorted(shared), "scope_id": scope_id, "sink_kind": sink.kind},
                    )
                )

    report(70, "安全防护关系已关联，正在解析跨文件调用")

    call_total = len(facts.call_sites)
    progress_interval = max(1, call_total // 5)
    for index, call in enumerate(facts.call_sites, start=1):
        resolved = resolver.resolve_with_reason(call)
        if resolved is None:
            if index % progress_interval == 0 or index == call_total:
                report(70 + round(index / max(call_total, 1) * 24), f"正在解析跨文件调用：{index:,}/{call_total:,}")
            continue
        target, resolution_reason = resolved
        graph.edges.append(
            CodeEdge(
                from_id=call.id,
                to_id=target.id,
                kind="CALLS",
                confidence="high" if call.analysis_method == target.analysis_method == "ast" else "medium",
                evidence=f"{call.anchor.file}:{call.anchor.start_line} calls {target.qualified_name or target.name}",
                metadata={
                    "resolved_by": "import_or_scoped_name",
                    "resolution_reason": resolution_reason,
                    "analysis_method": call.analysis_method,
                    "cross_file": call.anchor.file != target.anchor.file,
                },
            )
        )
        if index % progress_interval == 0 or index == call_total:
            report(70 + round(index / max(call_total, 1) * 24), f"正在解析跨文件调用：{index:,}/{call_total:,}")

    graph.nodes = _dedupe_nodes(graph.nodes)
    graph.edges = _dedupe_edges(graph.edges)
    report(100, "统一图模型构建完成")
    return graph


def _infer_scope(anchor: CodeAnchor, functions_by_file: dict[str, list[FunctionFact]]) -> str | None:
    matches = [
        function
        for function in functions_by_file.get(anchor.file, [])
        if function.anchor.start_line <= anchor.start_line and anchor.end_line <= function.anchor.end_line
    ]
    if not matches:
        return None
    return min(matches, key=lambda function: function.anchor.end_line - function.anchor.start_line).id


def _path_segments(path: str) -> list[str]:
    if path.startswith("@"):
        return [path]
    normalized = path.replace("['", ".").replace("']", "").replace('["', ".").replace('"]', "")
    normalized = normalized.replace("[*]", ".*")
    return [part for part in normalized.split(".") if part]


def _access_path_root(path: str) -> str:
    """Return the first access-path segment used for conservative bucketing."""

    segments = _path_segments(path)
    # `_paths_intersect` considers an empty path compatible with every path;
    # use the wildcard bucket to preserve that behavior for malformed or
    # incomplete facts emitted by fallback parsers.
    return segments[0] if segments else "*"


def _paths_intersect(left: str, right: str) -> bool:
    if left == right:
        return True
    if left.startswith("@") or right.startswith("@"):
        return False
    for left_part, right_part in zip(_path_segments(left), _path_segments(right), strict=False):
        if left_part != right_part and left_part != "*" and right_part != "*":
            return False
    return True


def _sanitizer_applies(kind: str, sink_kinds: list[str], sink_kind: str, vuln_class: str) -> bool:
    del kind, vuln_class
    return bool(sink_kinds) and sink_kind in sink_kinds


def _dedupe_nodes(nodes: list[CodeNode]) -> list[CodeNode]:
    seen: set[str] = set()
    output: list[CodeNode] = []
    for node in nodes:
        if node.id not in seen:
            seen.add(node.id)
            output.append(node)
    return output


def _dedupe_edges(edges: list[CodeEdge]) -> list[CodeEdge]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[CodeEdge] = []
    for edge in edges:
        key = (edge.from_id, edge.to_id, edge.kind, edge.evidence)
        if key not in seen:
            seen.add(key)
            output.append(edge)
    return output
