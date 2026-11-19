from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, replace

from ..core.models import (
    CallSiteFact,
    CodeAnchor,
    CodeEdge,
    CodeFacts,
    CodeGraph,
    Confidence,
    ControlFlowFact,
    DataFlowFact,
    FunctionFact,
    SanitizerFact,
    SinkFact,
    SourceFact,
    TraceCandidate,
    TraceStep,
    VulnClass,
)
from .call_resolution import CallResolver, resolution_models_from_diagnostics


@dataclass
class _Propagation:
    reached: set[str]
    anchors: dict[str, CodeAnchor]
    steps: list[TraceStep]
    related_sanitizers: list[SanitizerFact]


_RETURN_VALUE = "@return"


@dataclass(frozen=True)
class _FlowState:
    scope: tuple[str, str | None]
    variable: str


@dataclass(frozen=True)
class _FlowEdge:
    source: _FlowState
    target: _FlowState
    # The scope in which this transition executes.  Local assignment/return
    # edges execute in their state scope; call-boundary edges execute at the
    # caller's call site.  Keeping this separately lets the solver compare
    # source order only when both positions are meaningful in one function.
    execution_scope: tuple[str, str | None]
    kind: str
    anchor: CodeAnchor
    explanation: str
    confidence: Confidence
    flow: DataFlowFact | None = None
    call_id: str | None = None
    call_direction: str = ""


@dataclass(frozen=True)
class _SinkState:
    sink: SinkFact
    state: _FlowState


@dataclass(frozen=True)
class _AliasBinding:
    target_root: str
    source_root: str
    anchor: CodeAnchor


_AliasesByScope = dict[tuple[str, str | None], list[_AliasBinding]]


@dataclass
class _TraceRecord:
    anchor: CodeAnchor
    order_scope: tuple[str, str | None]
    steps: list[TraceStep]
    related_sanitizers: list[SanitizerFact]


class _SparseFlowIndex:
    """Sparse access-path indexes used by interprocedural propagation.

    Access paths are matched conservatively (``payload`` intersects
    ``payload.query``), so a root-path bucket narrows each lookup before the
    exact conservative intersection test.  The reverse worklist records the
    subset of states that can reach at least one sink, allowing per-source
    propagation to skip disconnected graph regions.
    """

    def __init__(self, edges: list[_FlowEdge], sinks: list[_SinkState]) -> None:
        self._edges_by_source: dict[tuple[tuple[str, str | None], str], list[_FlowEdge]] = defaultdict(list)
        self._edges_by_target: dict[tuple[tuple[str, str | None], str], list[_FlowEdge]] = defaultdict(list)
        self._sinks_by_state: dict[tuple[tuple[str, str | None], str], list[_SinkState]] = defaultdict(list)
        self._sinks_by_kind_and_state: dict[str, dict[tuple[tuple[str, str | None], str], list[_SinkState]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._live_by_kind_and_state: dict[str, dict[tuple[tuple[str, str | None], str], set[str]]] = defaultdict(lambda: defaultdict(set))

        for edge in edges:
            self._edges_by_source[_flow_index_key(edge.source)].append(edge)
            self._edges_by_target[_flow_index_key(edge.target)].append(edge)
        for sink in sinks:
            self._sinks_by_state[_flow_index_key(sink.state)].append(sink)
            self._sinks_by_kind_and_state[sink.sink.kind][_flow_index_key(sink.state)].append(sink)

        def edge_key(edge: _FlowEdge) -> tuple[tuple[str, int, int, int, int], str, str, str]:
            return (
                _anchor_order(edge.anchor),
                edge.kind,
                edge.source.variable,
                edge.target.variable,
            )

        def sink_key(item: _SinkState) -> tuple[tuple[str, int, int, int, int], str, str]:
            return _anchor_order(item.sink.anchor), item.sink.id, item.state.variable

        for bucket in [*self._edges_by_source.values(), *self._edges_by_target.values()]:
            bucket.sort(key=edge_key)
        for bucket in self._sinks_by_state.values():
            bucket.sort(key=sink_key)
        for buckets in self._sinks_by_kind_and_state.values():
            for bucket in buckets.values():
                bucket.sort(key=sink_key)

        self._build_reverse_liveness(sinks)

    def edges_from(self, state: _FlowState) -> list[_FlowEdge]:
        return [
            edge for edge in self._edges_by_source.get(_flow_index_key(state), []) if _paths_intersect(state.variable, edge.source.variable)
        ]

    def edges_to(self, state: _FlowState) -> list[_FlowEdge]:
        return [
            edge for edge in self._edges_by_target.get(_flow_index_key(state), []) if _paths_intersect(state.variable, edge.target.variable)
        ]

    @property
    def sink_kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self._sinks_by_kind_and_state))

    def sinks_for(self, state: _FlowState, sink_kind: str | None = None) -> list[_SinkState]:
        buckets = self._sinks_by_state if sink_kind is None else self._sinks_by_kind_and_state.get(sink_kind, {})
        return [sink for sink in buckets.get(_flow_index_key(state), []) if _paths_intersect(state.variable, sink.state.variable)]

    def can_reach_sink_kind(self, state: _FlowState, sink_kind: str) -> bool:
        return any(
            _paths_intersect(state.variable, live_variable)
            for live_variable in self._live_by_kind_and_state.get(sink_kind, {}).get(_flow_index_key(state), set())
        )

    def _build_reverse_liveness(self, sinks: list[_SinkState]) -> None:
        sinks_by_kind: dict[str, list[_SinkState]] = defaultdict(list)
        for sink in sinks:
            sinks_by_kind[sink.sink.kind].append(sink)
        for sink_kind in sorted(sinks_by_kind):
            self._build_reverse_liveness_for_kind(sink_kind, sinks_by_kind[sink_kind])

    def _build_reverse_liveness_for_kind(self, sink_kind: str, sinks: list[_SinkState]) -> None:
        queue: deque[_FlowState] = deque()
        seen: set[_FlowState] = set()

        def add(state: _FlowState) -> None:
            self._live_by_kind_and_state[sink_kind][_flow_index_key(state)].add(state.variable)
            if state not in seen:
                seen.add(state)
                queue.append(state)

        for sink in sinks:
            add(sink.state)
        while queue:
            state = queue.popleft()
            for edge in self.edges_to(state):
                # Keep the concrete target as a live state as well as its
                # predecessor.  It may be a parent/child access path of the
                # state that first made this edge relevant.
                add(edge.target)
                add(edge.source)


def _flow_index_key(state: _FlowState) -> tuple[tuple[str, str | None], str]:
    root, _suffix = _split_access_path(state.variable)
    return state.scope, root


def build_trace_candidates(
    facts: CodeFacts,
    graph: CodeGraph,
    progress_callback: Callable[[int, str], None] | None = None,
) -> list[TraceCandidate]:
    """Create candidates only when an explicit variable or expression flow exists.

    The previous implementation connected any source appearing before any sink in the
    same function. That line-order fallback was intentionally removed: candidates now
    require a scoped variable propagation chain, a source nested in the sink expression,
    or an argument-to-parameter chain across a resolved call.
    """

    candidates: list[TraceCandidate] = []
    seen: set[tuple[VulnClass, str, str, int, str, int]] = set()
    functions_by_file: dict[str, list[FunctionFact]] = defaultdict(list)
    functions_by_id: dict[str, FunctionFact] = {}
    for function in facts.functions:
        functions_by_file[function.anchor.file].append(function)
        functions_by_id[function.id] = function

    scope_sources: dict[tuple[str, str | None], list[SourceFact]] = defaultdict(list)
    scope_flows: dict[tuple[str, str | None], list[DataFlowFact]] = defaultdict(list)
    scope_sanitizers: dict[tuple[str, str | None], list[SanitizerFact]] = defaultdict(list)
    for source in facts.sources:
        scope_sources[_fact_scope(source, functions_by_file, functions_by_id)].append(source)
    for flow in facts.data_flows:
        scope_flows[_fact_scope(flow, functions_by_file, functions_by_id)].append(flow)
    for sanitizer in facts.sanitizers:
        scope_sanitizers[_fact_scope(sanitizer, functions_by_file, functions_by_id)].append(sanitizer)
    calls = _effective_calls(facts)
    resolver = CallResolver(facts.functions, facts.imports, resolution_models_from_diagnostics(facts.analysis_diagnostics))
    resolved = {call.id: item for call in calls if (item := resolver.resolve_with_reason(call)) is not None}
    resolved_calls = {call_id: item[0] for call_id, item in resolved.items()}
    callees_with_returns = {flow.enclosing_function_id for flow in facts.data_flows if flow.kind == "return" and flow.enclosing_function_id}
    internal_calls_by_scope: dict[tuple[str, str | None], list[CallSiteFact]] = defaultdict(list)
    for call in calls:
        callee = resolved_calls.get(call.id)
        if callee is not None and callee.id in callees_with_returns:
            internal_calls_by_scope[_fact_scope(call, functions_by_file, functions_by_id)].append(call)
    aliases_by_scope = _build_aliases(facts, functions_by_file)

    def report(percent: int, detail: str) -> None:
        if progress_callback:
            progress_callback(percent, detail)

    ordered_sinks = sorted(facts.sinks, key=lambda item: _anchor_order(item.anchor))
    local_interval = max(1, len(ordered_sinks) // 5)
    for sink_index, sink in enumerate(ordered_sinks, start=1):
        scope = _fact_scope(sink, functions_by_file, functions_by_id)
        sources = sorted(scope_sources.get(scope, []), key=lambda item: _anchor_order(item.anchor))
        flows = [
            replace(flow, sources=_effective_flow_sources(flow, scope, internal_calls_by_scope, resolved_calls, keep_call_tokens=False))
            for flow in scope_flows.get(scope, [])
        ]
        sanitizers = scope_sanitizers.get(scope, [])
        for source in sources:
            if _after(source.anchor, sink.anchor):
                continue
            propagation = _trace_source_to_sink(source, sink, flows, sanitizers, scope, aliases_by_scope)
            if not propagation:
                continue
            candidate = _make_candidate(
                len(candidates) + 1,
                source,
                sink,
                propagation.steps,
                propagation.related_sanitizers,
                nearest_route_id(facts, sink.anchor, scope[1]),
            )
            _append_candidate(candidate, candidates, seen)
        if sink_index % local_interval == 0 or sink_index == len(ordered_sinks):
            report(
                round(sink_index / max(len(ordered_sinks), 1) * 35),
                f"正在匹配函数内污点路径：{sink_index:,}/{len(ordered_sinks):,} 个 sink",
            )

    report(38, "函数内污点路径已匹配，正在分析跨文件调用链")
    _build_interprocedural_candidates(
        facts,
        functions_by_file,
        functions_by_id,
        scope_sources,
        scope_flows,
        scope_sanitizers,
        candidates,
        seen,
        progress_callback=lambda percent, detail: report(38 + round(percent * 0.58), detail),
    )

    candidates = sorted(candidates, key=lambda item: (-_confidence_rank(item.confidence), _anchor_order(item.sink), item.id))
    candidates = [replace(item, id=f"{item.vuln_class.upper()}-TRACE-{index:03d}") for index, item in enumerate(candidates, 1)]

    source_by_anchor = {_anchor_key(source.anchor): source for source in facts.sources}
    sink_by_anchor = {_anchor_key(sink.anchor): sink for sink in facts.sinks}
    for candidate in candidates:
        source = source_by_anchor.get(_anchor_key(candidate.source))
        sink = sink_by_anchor.get(_anchor_key(candidate.sink))
        if source and sink:
            graph.edges.append(
                CodeEdge(
                    from_id=source.id,
                    to_id=sink.id,
                    kind="FLOWS_TO_CANDIDATE",
                    confidence=candidate.confidence,
                    evidence=candidate.id,
                    metadata={
                        "candidate_id": candidate.id,
                        "vuln_class": candidate.vuln_class,
                        "taxonomy_id": candidate.taxonomy_id,
                    },
                )
            )
    graph.edges = _dedupe_graph_edges(graph.edges)
    report(100, "source-to-sink 候选路径匹配完成")
    return candidates


def _trace_source_to_sink(
    source: SourceFact,
    sink: SinkFact,
    flows: list[DataFlowFact],
    sanitizers: list[SanitizerFact],
    scope: tuple[str, str | None],
    aliases_by_scope: _AliasesByScope,
) -> _Propagation | None:
    if _same_expression_flow(source, sink):
        effective = [item for item in sanitizers if _inline_sanitizes_source(item, source, sink)]
        if effective:
            return None
        confidence: Confidence = "high" if source.analysis_method == sink.analysis_method == "ast" else "medium"
        return _Propagation(
            reached=set(),
            anchors={},
            steps=[
                TraceStep(
                    kind="call",
                    from_anchor=source.anchor,
                    to_anchor=sink.anchor,
                    explanation=f"Untrusted {source.kind} expression is passed directly to {sink.kind}.",
                    confidence=confidence,
                )
            ],
            related_sanitizers=[],
        )

    if not source.variables or not sink.variables:
        return None
    propagation = _propagate(
        {_canonical_path(scope, variable, aliases_by_scope, source.anchor) for variable in source.variables},
        source.anchor,
        sink.anchor,
        flows,
        sanitizers,
        sink,
        scope,
        aliases_by_scope,
    )
    sink_variables = {_canonical_path(scope, variable, aliases_by_scope, sink.anchor) for variable in sink.variables}
    consumed = {
        reached_name
        for reached_name in propagation.reached
        if any(_paths_intersect(reached_name, sink_name) for sink_name in sink_variables)
    }
    if not consumed:
        return None
    unsanitized = {
        variable
        for variable in consumed
        if not any(_canonical_sanitizes_variable(item, variable, sink, scope, aliases_by_scope, source.anchor) for item in sanitizers)
    }
    if not unsanitized:
        return None
    last_variable = sorted(unsanitized)[0]
    last_anchor = propagation.anchors.get(last_variable, source.anchor)
    if not propagation.steps or propagation.steps[-1].to_anchor != sink.anchor:
        propagation.steps.append(
            TraceStep(
                kind="branch" if sink.kind == "authorization_decision" else "call",
                from_anchor=last_anchor,
                to_anchor=sink.anchor,
                explanation=(
                    f"Tainted variable {last_variable} controls the authorization branch."
                    if sink.kind == "authorization_decision"
                    else f"Tainted variable {last_variable} is consumed by {sink.kind}."
                ),
                confidence="high" if sink.analysis_method == "ast" else "medium",
            )
        )
    propagation.related_sanitizers.extend(
        item
        for item in sanitizers
        if item not in propagation.related_sanitizers
        and _sanitizer_applies(item, sink)
        and any(
            _paths_intersect(
                _canonical_path(scope, input_name, aliases_by_scope, item.anchor),
                reached_name,
            )
            for input_name in item.input_variables
            for reached_name in propagation.reached
        )
    )
    return propagation


def _propagate(
    seed_variables: set[str],
    seed_anchor: CodeAnchor,
    endpoint: CodeAnchor,
    flows: list[DataFlowFact],
    sanitizers: list[SanitizerFact],
    sink: SinkFact,
    scope: tuple[str, str | None],
    aliases_by_scope: _AliasesByScope,
) -> _Propagation:
    reached = set(seed_variables)
    anchors = {name: seed_anchor for name in seed_variables}
    steps: list[TraceStep] = []
    related: list[SanitizerFact] = []
    ordered = sorted(flows, key=lambda item: _anchor_order(item.anchor))
    for flow in ordered:
        if flow.anchor.file != endpoint.file:
            continue
        if seed_anchor.file == flow.anchor.file and _after(seed_anchor, flow.anchor) and not _contains(flow.anchor, seed_anchor):
            continue
        if _after(flow.anchor, endpoint):
            continue
        if flow.kind != "assignment" or not flow.target:
            continue
        target = _canonical_write_path(scope, flow.target, aliases_by_scope, flow.anchor)
        sources = [_canonical_path(scope, variable, aliases_by_scope, flow.anchor) for variable in flow.sources]
        if flow.anchor.start_line == seed_anchor.start_line and target in seed_variables:
            # The source expression itself initializes this variable. Its RHS does
            # not need to contain an already-tainted variable.
            initial_sanitizers = [
                sanitizer
                for sanitizer in sanitizers
                if not _is_guard_region(sanitizer)
                and any(
                    _paths_intersect(
                        target,
                        _canonical_write_path(scope, variable, aliases_by_scope, sanitizer.anchor),
                    )
                    for variable in sanitizer.variables
                )
                and (_contains(flow.anchor, sanitizer.anchor) or sanitizer.anchor.start_line == flow.anchor.start_line)
                and _sanitizer_applies(sanitizer, sink)
            ]
            if initial_sanitizers:
                reached.discard(target)
                anchors.pop(target, None)
                related.extend(item for item in initial_sanitizers if item not in related)
            continue
        tainted_inputs = {
            reached_name for reached_name in reached if any(_paths_intersect(reached_name, source_name) for source_name in sources)
        }
        if not tainted_inputs:
            # SSA-lite: Python AST marks only a direct function/module literal
            # assignment as an unconditional overwrite. Branch/loop/try writes
            # deliberately remain monotone because they may not dominate the sink.
            if flow.ssa_safe_overwrite:
                overwritten = {name for name in reached if _paths_intersect(name, target)}
                for name in overwritten:
                    reached.discard(name)
                    anchors.pop(name, None)
            continue
        effective = [
            sanitizer
            for sanitizer in sanitizers
            if (
                (
                    not _is_guard_region(sanitizer)
                    and any(
                        _paths_intersect(
                            target,
                            _canonical_write_path(scope, variable, aliases_by_scope, sanitizer.anchor),
                        )
                        for variable in sanitizer.variables
                    )
                    and (_contains(flow.anchor, sanitizer.anchor) or sanitizer.anchor.start_line == flow.anchor.start_line)
                )
                or (
                    _is_guard_region(sanitizer)
                    and seed_anchor.start_line < sanitizer.anchor.start_line
                    and _contains(sanitizer.anchor, flow.anchor)
                )
            )
            and any(
                _paths_intersect(
                    _canonical_path(scope, input_name, aliases_by_scope, sanitizer.anchor),
                    tainted_name,
                )
                for input_name in sanitizer.input_variables
                for tainted_name in tainted_inputs
            )
            and _sanitizer_applies(sanitizer, sink)
        ]
        if effective:
            unsanitized_inputs = {
                tainted_name
                for tainted_name in tainted_inputs
                if not any(
                    _paths_intersect(
                        _canonical_path(scope, input_name, aliases_by_scope, item.anchor),
                        tainted_name,
                    )
                    for item in effective
                    for input_name in item.input_variables
                )
            }
            related.extend(item for item in effective if item not in related)
            if not unsanitized_inputs:
                reached.discard(target)
                anchors.pop(target, None)
                continue
            tainted_inputs = unsanitized_inputs
        source_variable = sorted(tainted_inputs)[0]
        from_anchor = anchors.get(source_variable, seed_anchor)
        reached.add(target)
        anchors[target] = flow.anchor
        steps.append(
            TraceStep(
                kind="assignment",
                from_anchor=from_anchor,
                to_anchor=flow.anchor,
                explanation=f"Taint propagates from {source_variable} to {flow.target}.",
                confidence="high" if flow.analysis_method == "ast" else "medium",
            )
        )
    return _Propagation(reached, anchors, steps, related)


def _build_interprocedural_candidates(
    facts: CodeFacts,
    functions_by_file: dict[str, list[FunctionFact]],
    functions_by_id: dict[str, FunctionFact],
    scope_sources: dict[tuple[str, str | None], list[SourceFact]],
    scope_flows: dict[tuple[str, str | None], list[DataFlowFact]],
    scope_sanitizers: dict[tuple[str, str | None], list[SanitizerFact]],
    candidates: list[TraceCandidate],
    seen: set[tuple[VulnClass, str, str, int, str, int]],
    progress_callback: Callable[[int, str], None] | None = None,
) -> None:
    del scope_sources, scope_flows  # Interprocedural edges consume repository facts directly.
    calls = _effective_calls(facts)
    resolver = CallResolver(facts.functions, facts.imports, resolution_models_from_diagnostics(facts.analysis_diagnostics))
    resolved = {call.id: item for call in calls if (item := resolver.resolve_with_reason(call)) is not None}
    resolved_calls = {call_id: item[0] for call_id, item in resolved.items()}
    framework_bound_calls = {
        call_id for call_id, (_target, reason) in resolved.items() if reason in {"framework_injection", "typed_receiver"}
    }
    aliases_by_scope = _build_aliases(facts, functions_by_file)
    parameter_effects = _build_parameter_effects(
        facts,
        functions_by_file,
        calls,
        resolved_calls,
        aliases_by_scope,
    )
    edges = _interprocedural_edges(
        facts,
        functions_by_file,
        calls,
        resolved_calls,
        aliases_by_scope,
        parameter_effects,
        framework_bound_calls,
    )
    safe_overwrites_by_scope: dict[tuple[str, str | None], list[DataFlowFact]] = defaultdict(list)
    for flow in facts.data_flows:
        if flow.kind == "assignment" and flow.target and flow.ssa_safe_overwrite:
            safe_overwrites_by_scope[_fact_scope(flow, functions_by_file, functions_by_id)].append(flow)

    ordered_sinks = sorted(facts.sinks, key=lambda item: _anchor_order(item.anchor))
    all_sources = sorted(facts.sources, key=lambda item: _anchor_order(item.anchor))
    sources_by_id = {source.id: source for source in all_sources}
    sink_states = [
        _SinkState(
            sink=sink,
            state=_FlowState(
                _fact_scope(sink, functions_by_file, functions_by_id),
                _canonical_path(
                    _fact_scope(sink, functions_by_file, functions_by_id),
                    variable,
                    aliases_by_scope,
                    sink.anchor,
                ),
            ),
        )
        for sink in ordered_sinks
        for variable in sink.variables
    ]
    flow_index = _SparseFlowIndex(edges, sink_states)
    loop_regions_by_scope: dict[tuple[str, str | None], list[CodeAnchor]] = defaultdict(list)
    for control in facts.control_flows:
        if control.kind in {"for", "while"}:
            loop_regions_by_scope[_fact_scope(control, functions_by_file, functions_by_id)].append(control.anchor)

    traces_by_sink: dict[str, dict[str, tuple[list[TraceStep], list[SanitizerFact]]]] = defaultdict(dict)
    source_interval = max(1, len(all_sources) // 5)
    for source_index, source in enumerate(all_sources, start=1):
        if source.variables:
            source_scope = _fact_scope(source, functions_by_file, functions_by_id)
            for sink_kind in flow_index.sink_kinds:
                traces = _trace_source_to_sink_kind(
                    source,
                    source_scope,
                    sink_kind,
                    flow_index,
                    scope_sanitizers,
                    aliases_by_scope,
                    safe_overwrites_by_scope,
                    loop_regions_by_scope,
                )
                for sink_id, trace in traces.items():
                    traces_by_sink[sink_id][source.id] = trace
        if progress_callback and (source_index % source_interval == 0 or source_index == len(all_sources)):
            progress_callback(
                round(source_index / max(len(all_sources), 1) * 80),
                f"Propagating sparse source paths: {source_index:,}/{len(all_sources):,} sources",
            )

    sink_interval = max(1, len(ordered_sinks) // 5)
    for sink_index, sink in enumerate(ordered_sinks, start=1):
        sink_scope = _fact_scope(sink, functions_by_file, functions_by_id)
        matching_sources = sorted(
            (
                (sources_by_id[source_id], trace)
                for source_id, trace in traces_by_sink.get(sink.id, {}).items()
                if source_id in sources_by_id
            ),
            key=lambda item: _anchor_order(item[0].anchor),
        )
        for source, (steps, related) in matching_sources:
            source_scope = _fact_scope(source, functions_by_file, functions_by_id)
            crossed_scope = any(step.kind in {"call", "return", "framework_binding"} for step in steps[:-1])
            used_loop_back_edge = any(
                _after(step.from_anchor, step.to_anchor)
                and _anchors_share_loop_region(
                    source_scope,
                    step.from_anchor,
                    step.to_anchor,
                    loop_regions_by_scope,
                )
                for step in steps
            )
            if source_scope == sink_scope and not crossed_scope and not used_loop_back_edge:
                # Same-scope paths were already evaluated by the ordered local
                # solver above. Only a trace that actually traversed a loop back
                # edge needs sparse same-scope ordering; all other local paths
                # remain suppressed to avoid resurrecting an older variable version.
                continue
            route_id = nearest_route_id(facts, source.anchor, source_scope[1]) or nearest_route_id(facts, sink.anchor, sink_scope[1])
            _append_candidate(
                _make_candidate(len(candidates) + 1, source, sink, steps, related, route_id),
                candidates,
                seen,
            )
        if progress_callback and (sink_index % sink_interval == 0 or sink_index == len(ordered_sinks)):
            progress_callback(
                80 + round(sink_index / max(len(ordered_sinks), 1) * 20),
                f"正在分析跨文件污点链：{sink_index:,}/{len(ordered_sinks):,} 个 sink",
            )


def _effective_calls(facts: CodeFacts) -> list[CallSiteFact]:
    """Return call sites, recovering them from call_argument facts when needed."""

    calls = list(facts.call_sites)
    known = {(call.anchor.file, call.anchor.start_line, call.anchor.start_col, call.enclosing_function_id, call.callee) for call in calls}
    for flow in facts.data_flows:
        if flow.kind != "call_argument" or not flow.target:
            continue
        key = (flow.anchor.file, flow.anchor.start_line, flow.anchor.start_col, flow.enclosing_function_id, flow.target)
        if key in known:
            continue
        calls.append(
            CallSiteFact(
                id=f"callsite-{flow.id}",
                callee=flow.target,
                anchor=flow.anchor,
                enclosing_function_id=flow.enclosing_function_id,
                argument_sources=flow.argument_sources or ([flow.sources] if flow.sources else []),
                keyword_sources=flow.keyword_sources,
                analysis_method=flow.analysis_method,
            )
        )
        known.add(key)
    return calls


def _split_access_path(path: str) -> tuple[str, str]:
    if not path or path.startswith("@"):
        return path, ""
    dot = path.find(".")
    bracket = path.find("[")
    indexes = [index for index in (dot, bracket) if index >= 0]
    if not indexes:
        return path, ""
    boundary = min(indexes)
    return path[:boundary], path[boundary:]


def _build_aliases(
    facts: CodeFacts,
    functions_by_file: dict[str, list[FunctionFact]],
) -> _AliasesByScope:
    """Build conservative object aliases from direct ``a = b`` facts.

    Scalar copies remain ordinary forward data-flow edges. Treating every copy
    as a timeless alias lets a later ``query = raw`` make ``raw`` appear at an
    earlier ``execute(query)`` sink. Object-root aliases are retained because
    they are needed to connect writes such as ``alias.query = value`` to reads
    through the original object.
    """

    object_roots_by_scope: dict[tuple[str, str | None], set[str]] = defaultdict(set)
    bindings_by_scope: _AliasesByScope = defaultdict(list)

    for flow in facts.data_flows:
        scope = _fact_scope(flow, functions_by_file)
        for path in [flow.target, *flow.sources]:
            if not path:
                continue
            root, suffix = _split_access_path(path)
            if root and suffix:
                object_roots_by_scope[scope].add(root)

    for flow in facts.data_flows:
        if flow.kind != "assignment" or not flow.target or len(flow.sources) != 1:
            continue
        source = flow.sources[0]
        target_root, target_suffix = _split_access_path(flow.target)
        source_root, source_suffix = _split_access_path(source)
        if (
            target_suffix
            or source_suffix
            or not target_root.isidentifier()
            or not source_root.isidentifier()
            or flow.expression.strip() != source_root
        ):
            continue
        scope = _fact_scope(flow, functions_by_file)
        if target_root not in object_roots_by_scope[scope] and source_root not in object_roots_by_scope[scope]:
            continue
        bindings_by_scope[scope].append(_AliasBinding(target_root, source_root, flow.anchor))

    for bindings in bindings_by_scope.values():
        bindings.sort(key=lambda item: _anchor_order(item.anchor))
    return dict(bindings_by_scope)


def _canonical_path(
    scope: tuple[str, str | None],
    path: str,
    aliases_by_scope: _AliasesByScope,
    anchor: CodeAnchor | None = None,
) -> str:
    root, suffix = _split_access_path(path)
    if not root or root.startswith("@"):
        return path
    seen = {root}
    while True:
        matching = [
            binding
            for binding in aliases_by_scope.get(scope, [])
            if binding.target_root == root and (anchor is None or not _after(binding.anchor, anchor))
        ]
        if not matching:
            break
        source_root = matching[-1].source_root
        if source_root in seen:
            break
        seen.add(source_root)
        root = source_root
    return f"{root}{suffix}"


def _canonical_write_path(
    scope: tuple[str, str | None],
    path: str,
    aliases_by_scope: _AliasesByScope,
    anchor: CodeAnchor,
) -> str:
    """Canonicalize member writes while preserving bare-name rebinding."""

    _root, suffix = _split_access_path(path)
    if not suffix:
        return path
    return _canonical_path(scope, path, aliases_by_scope, anchor)


def _call_bindings(call: CallSiteFact, callee: FunctionFact) -> list[tuple[int, str]]:
    bindings: list[tuple[int, str]] = []
    has_implicit_receiver = bool(callee.class_id and callee.params and callee.params[0] in {"self", "cls"})
    offset = 1 if has_implicit_receiver else 0
    if has_implicit_receiver and callee.params[0] == "self" and "." in call.callee and len(call.argument_sources) < len(callee.params):
        receiver = call.callee.rsplit(".", 1)[0]
        if receiver and not receiver.startswith("@") and receiver not in {"self", "cls"}:
            bindings.append((0, receiver))
    for index, variables in enumerate(call.argument_sources):
        param_index = index + offset
        if param_index >= len(callee.params):
            break
        bindings.extend((param_index, variable) for variable in variables)
    for keyword, variables in call.keyword_sources.items():
        if keyword not in callee.params:
            continue
        param_index = callee.params.index(keyword)
        bindings.extend((param_index, variable) for variable in variables)
    return bindings


def _merge_effect_suffix(actual_suffix: str, effect_suffix: str) -> str:
    combined = f"{actual_suffix}{effect_suffix}"
    if "*" in combined or combined.count(".") + combined.count("[") > 4:
        # Recursive object traversal can otherwise generate an unbounded family
        # such as .child.child....query. A wildcard is a conservative fixed point.
        return "[*]"
    return combined


def _build_parameter_effects(
    facts: CodeFacts,
    functions_by_file: dict[str, list[FunctionFact]],
    calls: list[CallSiteFact],
    resolved_calls: dict[str, FunctionFact],
    aliases_by_scope: _AliasesByScope,
) -> dict[str, set[tuple[int, str]]]:
    """Summarize fields written through parameters, including nested callees."""

    functions_by_id = {function.id: function for function in facts.functions}
    effects: dict[str, set[tuple[int, str]]] = defaultdict(set)
    for flow in facts.data_flows:
        if flow.kind != "assignment" or not flow.target or not flow.enclosing_function_id:
            continue
        function = functions_by_id.get(flow.enclosing_function_id)
        if function is None:
            continue
        scope = (function.anchor.file, function.id)
        target = _canonical_write_path(scope, flow.target, aliases_by_scope, flow.anchor)
        target_root, target_suffix = _split_access_path(target)
        if not target_suffix:
            continue
        for index, param in enumerate(function.params):
            param_root, _ = _split_access_path(_canonical_path(scope, param, aliases_by_scope, function.anchor))
            if target_root == param_root:
                effects[function.id].add((index, target_suffix))

    changed = True
    while changed:
        changed = False
        for call in calls:
            callee = resolved_calls.get(call.id)
            caller = functions_by_id.get(call.enclosing_function_id or "")
            if callee is None or caller is None:
                continue
            caller_scope = (caller.anchor.file, caller.id)
            bindings = _call_bindings(call, callee)
            for effect_param_index, effect_suffix in tuple(effects.get(callee.id, set())):
                for binding_index, variable in bindings:
                    if binding_index != effect_param_index or variable.startswith("@"):
                        continue
                    actual = _canonical_path(caller_scope, variable, aliases_by_scope, call.anchor)
                    actual_root, actual_suffix = _split_access_path(actual)
                    for caller_param_index, caller_param in enumerate(caller.params):
                        caller_param_root, _ = _split_access_path(
                            _canonical_path(caller_scope, caller_param, aliases_by_scope, caller.anchor)
                        )
                        if actual_root != caller_param_root:
                            continue
                        effect = (caller_param_index, _merge_effect_suffix(actual_suffix, effect_suffix))
                        if effect not in effects[caller.id]:
                            effects[caller.id].add(effect)
                            changed = True
    return effects


def _effective_flow_sources(
    flow: DataFlowFact,
    scope: tuple[str, str | None],
    internal_calls_by_scope: dict[tuple[str, str | None], list[CallSiteFact]],
    resolved_calls: dict[str, FunctionFact],
    *,
    keep_call_tokens: bool = True,
) -> list[str]:
    """Strip argument-shortcut fallback variables for calls resolved in the repository."""

    sources = list(flow.sources)
    has_synthetic_tokens = any(name.startswith("@call:") for name in sources)
    for call in internal_calls_by_scope.get(scope, []):
        token = _call_token(call)
        if not _contains(flow.anchor, call.anchor):
            continue
        if token not in sources:
            if has_synthetic_tokens:
                continue
            method_name = call.callee.rsplit(".", 1)[-1]
            if flow.expression and f"{method_name}(" not in flow.expression and call.callee not in flow.expression:
                continue
            if keep_call_tokens:
                sources.append(token)
        arguments = {name for values in [*call.argument_sources, *call.keyword_sources.values()] for name in values}
        callee = resolved_calls[call.id]
        if (
            callee.class_id
            and callee.params
            and callee.params[0] == "self"
            and "." in call.callee
            and len(call.argument_sources) < len(callee.params)
        ):
            receiver = call.callee.rsplit(".", 1)[0]
            if receiver and not receiver.startswith("@"):
                arguments.add(receiver)
        sources = [name for name in sources if name == token or name not in arguments]
    return sources


def _interprocedural_edges(
    facts: CodeFacts,
    functions_by_file: dict[str, list[FunctionFact]],
    calls: list[CallSiteFact],
    resolved_calls: dict[str, FunctionFact],
    aliases_by_scope: _AliasesByScope,
    parameter_effects: dict[str, set[tuple[int, str]]],
    framework_bound_call_ids: set[str],
) -> list[_FlowEdge]:
    edges: list[_FlowEdge] = []
    internal_calls_by_scope: dict[tuple[str, str | None], list[CallSiteFact]] = defaultdict(list)
    for call in calls:
        if call.id in resolved_calls:
            internal_calls_by_scope[_fact_scope(call, functions_by_file)].append(call)

    for flow in facts.data_flows:
        if flow.kind == "call_argument":
            continue
        scope = _fact_scope(flow, functions_by_file)
        sources = _effective_flow_sources(flow, scope, internal_calls_by_scope, resolved_calls, keep_call_tokens=True)
        if flow.kind == "assignment" and flow.target:
            target = _FlowState(scope, _canonical_write_path(scope, flow.target, aliases_by_scope, flow.anchor))
        elif flow.kind == "return" and scope[1]:
            target = _FlowState(scope, _RETURN_VALUE)
        else:
            continue
        for variable in sources:
            edges.append(
                _FlowEdge(
                    source=_FlowState(scope, _canonical_path(scope, variable, aliases_by_scope, flow.anchor)),
                    target=target,
                    execution_scope=scope,
                    kind="return" if flow.kind == "return" else "assignment",
                    anchor=flow.anchor,
                    explanation=(
                        f"Tainted {variable} reaches the function return value."
                        if flow.kind == "return"
                        else f"Taint propagates from {variable} to {flow.target}."
                    ),
                    confidence="high" if flow.analysis_method == "ast" else "medium",
                    flow=flow,
                )
            )

    for call in calls:
        callee = resolved_calls.get(call.id)
        if callee is None:
            continue
        caller_scope = _fact_scope(call, functions_by_file)
        callee_scope = (callee.anchor.file, callee.id)
        bindings = _call_bindings(call, callee)
        for param_index, variable in bindings:
            param = callee.params[param_index]
            framework_bound = call.id in framework_bound_call_ids
            edges.append(
                _FlowEdge(
                    source=_FlowState(caller_scope, _canonical_path(caller_scope, variable, aliases_by_scope, call.anchor)),
                    target=_FlowState(callee_scope, _canonical_path(callee_scope, param, aliases_by_scope, callee.anchor)),
                    execution_scope=caller_scope,
                    kind="framework_binding" if framework_bound else "call",
                    anchor=call.anchor,
                    explanation=(
                        f"Spring dependency injection resolves {call.callee} to {callee.qualified_name or callee.name}; "
                        f"tainted {variable} is passed as {param}."
                        if framework_bound
                        else f"Tainted {variable} is passed to {callee.qualified_name or callee.name} as {param}."
                    ),
                    confidence="high" if call.analysis_method == callee.analysis_method == "ast" else "medium",
                    call_id=call.id,
                    call_direction="enter",
                )
            )
        for param_index, suffix in parameter_effects.get(callee.id, set()):
            param = callee.params[param_index]
            for binding_index, variable in bindings:
                if binding_index != param_index or variable.startswith("@"):
                    continue
                callee_path = _canonical_path(callee_scope, f"{param}{suffix}", aliases_by_scope, callee.anchor)
                caller_path = _canonical_path(caller_scope, f"{variable}{suffix}", aliases_by_scope, call.anchor)
                edges.append(
                    _FlowEdge(
                        source=_FlowState(callee_scope, callee_path),
                        target=_FlowState(caller_scope, caller_path),
                        execution_scope=caller_scope,
                        kind="call",
                        anchor=call.anchor,
                        explanation=(
                            f"Side effect from {callee.qualified_name or callee.name} writes tainted data "
                            f"through parameter {param} into {caller_path}."
                        ),
                        confidence="high" if call.analysis_method == callee.analysis_method == "ast" else "medium",
                        call_id=call.id,
                        call_direction="exit",
                    )
                )
        edges.append(
            _FlowEdge(
                source=_FlowState(callee_scope, _RETURN_VALUE),
                target=_FlowState(caller_scope, _call_token(call)),
                execution_scope=caller_scope,
                kind="return",
                anchor=call.anchor,
                explanation=f"Tainted return value from {callee.qualified_name or callee.name} flows back to its caller.",
                confidence="high" if call.analysis_method == callee.analysis_method == "ast" else "medium",
                call_id=call.id,
                call_direction="exit",
            )
        )
    return edges


def _trace_source_to_sink_kind(
    source: SourceFact,
    source_scope: tuple[str, str | None],
    sink_kind: str,
    flow_index: _SparseFlowIndex,
    sanitizers_by_scope: dict[tuple[str, str | None], list[SanitizerFact]],
    aliases_by_scope: _AliasesByScope,
    safe_overwrites_by_scope: dict[tuple[str, str | None], list[DataFlowFact]],
    loop_regions_by_scope: dict[tuple[str, str | None], list[CodeAnchor]],
) -> dict[str, tuple[list[TraceStep], list[SanitizerFact]]]:
    """Propagate one source once for every sink kind it can reach.

    Sanitizer applicability is keyed by sink kind, while guard-region and
    endpoint ordering checks remain per sink when a reached state is emitted.
    This avoids repeating the graph fixed point for every individual sink.
    """

    traces: dict[str, tuple[list[TraceStep], list[SanitizerFact]]] = {}
    records: dict[tuple[_FlowState, tuple[str, ...]], _TraceRecord] = {}
    queue: deque[tuple[_FlowState, tuple[str, ...]]] = deque()
    for variable in source.variables:
        state = _FlowState(source_scope, _canonical_path(source_scope, variable, aliases_by_scope, source.anchor))
        if not flow_index.can_reach_sink_kind(state, sink_kind):
            continue
        record = _TraceRecord(source.anchor, source_scope, [], [])
        stack: tuple[str, ...] = ()
        existing = records.get((state, stack))
        if existing is None or _record_is_earlier(record, existing, state):
            records[(state, stack)] = record
            queue.append((state, stack))

    while queue:
        state, call_stack = queue.popleft()
        record = records[(state, call_stack)]
        for sink_state in flow_index.sinks_for(state, sink_kind):
            sink = sink_state.sink
            if sink.id in traces:
                continue
            if not _state_precedes_sink(record, state, sink.anchor, loop_regions_by_scope):
                continue
            if _ssa_overwritten_between(
                state,
                record.anchor,
                record.order_scope,
                sink.anchor,
                safe_overwrites_by_scope,
                aliases_by_scope,
            ):
                continue
            if any(
                _canonical_sanitizes_variable(item, state.variable, sink, state.scope, aliases_by_scope, source.anchor)
                for item in sanitizers_by_scope.get(state.scope, [])
            ):
                continue
            final_kind = "branch" if sink.kind == "authorization_decision" else "call"
            traces[sink.id] = (
                [
                    *record.steps,
                    TraceStep(
                        kind=final_kind,
                        from_anchor=record.anchor,
                        to_anchor=sink.anchor,
                        explanation=f"Tainted {state.variable} is consumed by {sink.kind}.",
                        confidence="high" if sink.analysis_method == "ast" else "medium",
                    ),
                ],
                record.related_sanitizers,
            )
        for edge in flow_index.edges_from(state):
            if not flow_index.can_reach_sink_kind(edge.target, sink_kind):
                continue
            if edge.call_direction == "enter" and edge.call_id:
                next_stack = (*call_stack[-5:], edge.call_id)
            elif edge.call_direction == "exit" and edge.call_id:
                if call_stack:
                    if edge.call_id != call_stack[-1]:
                        continue
                    next_stack = call_stack[:-1]
                else:
                    next_stack = ()
            else:
                next_stack = call_stack
            if not _edge_is_forward(state, record, edge, loop_regions_by_scope):
                continue
            if edge.execution_scope == state.scope and _ssa_overwritten_between(
                state,
                record.anchor,
                record.order_scope,
                edge.anchor,
                safe_overwrites_by_scope,
                aliases_by_scope,
            ):
                continue
            effective = _edge_sanitizers(
                edge,
                state.variable,
                sink_kind,
                sanitizers_by_scope.get(edge.target.scope, []),
                aliases_by_scope,
            )
            if effective:
                continue
            next_record = _TraceRecord(
                anchor=edge.anchor,
                order_scope=edge.execution_scope,
                steps=[
                    *record.steps,
                    TraceStep(
                        kind=edge.kind,  # type: ignore[arg-type]
                        from_anchor=record.anchor,
                        to_anchor=edge.anchor,
                        explanation=edge.explanation,
                        confidence=edge.confidence,
                    ),
                ],
                related_sanitizers=record.related_sanitizers,
            )
            key = (edge.target, next_stack)
            existing = records.get(key)
            if existing is not None and not _record_is_earlier(next_record, existing, edge.target):
                continue
            records[key] = next_record
            queue.append(key)
    return traces


def _edge_is_forward(
    state: _FlowState,
    record: _TraceRecord,
    edge: _FlowEdge,
    loop_regions_by_scope: dict[tuple[str, str | None], list[CodeAnchor]],
) -> bool:
    """Whether an edge may execute after the state was produced.

    Lexical order is sound only for transitions whose two positions are in the
    same non-loop scope. A callee can be declared above its caller, and a loop
    body may run again after a later statement, so those cases intentionally
    remain conservative.
    """

    if record.order_scope != state.scope or edge.execution_scope != state.scope:
        return True
    if record.anchor.file != state.scope[0] or edge.anchor.file != state.scope[0]:
        return True
    # A call/source nested in an assignment or return is evaluated as part of
    # that enclosing statement even though its expression anchor starts later.
    if _contains(edge.anchor, record.anchor):
        return True
    return not _after(record.anchor, edge.anchor) or _anchors_share_loop_region(
        state.scope,
        record.anchor,
        edge.anchor,
        loop_regions_by_scope,
    )


def _state_precedes_sink(
    record: _TraceRecord,
    state: _FlowState,
    sink_anchor: CodeAnchor,
    loop_regions_by_scope: dict[tuple[str, str | None], list[CodeAnchor]],
) -> bool:
    if record.order_scope != state.scope:
        return True
    if record.anchor.file != state.scope[0] or sink_anchor.file != state.scope[0]:
        return True
    return not _after(record.anchor, sink_anchor) or _anchors_share_loop_region(
        state.scope,
        record.anchor,
        sink_anchor,
        loop_regions_by_scope,
    )


def _anchors_share_loop_region(
    scope: tuple[str, str | None],
    left: CodeAnchor,
    right: CodeAnchor,
    loop_regions_by_scope: dict[tuple[str, str | None], list[CodeAnchor]],
) -> bool:
    return any(_contains(region, left) and _contains(region, right) for region in loop_regions_by_scope.get(scope, []))


def _record_is_earlier(candidate: _TraceRecord, existing: _TraceRecord, state: _FlowState) -> bool:
    """Prefer the earliest local path, or a cross-scope function-entry path."""

    def local(record: _TraceRecord) -> bool:
        return record.order_scope == state.scope and record.anchor.file == state.scope[0]

    candidate_is_local = local(candidate)
    existing_is_local = local(existing)
    if candidate_is_local != existing_is_local:
        return not candidate_is_local
    if not candidate_is_local:
        return False
    return _anchor_order(candidate.anchor) < _anchor_order(existing.anchor)


def _ssa_overwritten_between(
    state: _FlowState,
    from_anchor: CodeAnchor,
    from_scope: tuple[str, str | None],
    to_anchor: CodeAnchor,
    safe_overwrites_by_scope: dict[tuple[str, str | None], list[DataFlowFact]],
    aliases_by_scope: _AliasesByScope,
) -> bool:
    """Return whether a proven straight-line literal assignment kills ``state``.

    The solver keeps the scope in which the previous anchor has execution-order
    meaning. A call into a different scope is treated as callee entry, while a
    local transition must have an overwrite strictly between its two anchors.
    """

    if to_anchor.file != state.scope[0]:
        return False
    for overwrite in safe_overwrites_by_scope.get(state.scope, []):
        if not overwrite.target:
            continue
        overwrite_target = _canonical_write_path(state.scope, overwrite.target, aliases_by_scope, overwrite.anchor)
        if not _paths_intersect(state.variable, overwrite_target):
            continue
        if _after(overwrite.anchor, to_anchor) or overwrite.anchor == to_anchor:
            continue
        if from_scope == state.scope and from_anchor.file == state.scope[0] and not _after(overwrite.anchor, from_anchor):
            continue
        return True
    return False


def _call_token_matches_sanitizer(input_variable: str, sanitizer: SanitizerFact) -> bool:
    if not input_variable.startswith("@call:"):
        return False
    parts = input_variable.rsplit(":", 2)
    if len(parts) != 3:
        return False
    callee = parts[0][len("@call:") :]
    try:
        call_line = int(parts[1])
        call_col = int(parts[2])
    except ValueError:
        return False
    anchor = sanitizer.anchor
    if anchor.start_col is not None and anchor.end_col is not None:
        return (anchor.start_line, anchor.start_col) <= (call_line, call_col) <= (anchor.end_line, anchor.end_col)
    if not (anchor.start_line <= call_line <= anchor.end_line):
        return False
    callee_leaf = callee.rsplit(".", 1)[-1].lower()
    return bool(callee_leaf and callee_leaf in sanitizer.expression.lower())


def _edge_sanitizers(
    edge: _FlowEdge,
    input_variable: str,
    sink_kind: str,
    sanitizers: list[SanitizerFact],
    aliases_by_scope: _AliasesByScope,
) -> list[SanitizerFact]:
    if edge.flow is None or edge.flow.kind not in {"assignment", "return"}:
        return []
    return [
        sanitizer
        for sanitizer in sanitizers
        if (
            (
                (sanitizer.anchor.start_line == edge.anchor.start_line or _contains(edge.anchor, sanitizer.anchor))
                and (
                    edge.flow.kind == "return"
                    or any(
                        _paths_intersect(
                            edge.target.variable,
                            _canonical_path(edge.target.scope, variable, aliases_by_scope, sanitizer.anchor),
                        )
                        for variable in sanitizer.variables
                    )
                )
            )
            or (_is_guard_region(sanitizer) and _contains(sanitizer.anchor, edge.anchor))
        )
        and (
            _call_token_matches_sanitizer(input_variable, sanitizer)
            or any(
                _paths_intersect(
                    input_variable,
                    _canonical_path(edge.source.scope, variable, aliases_by_scope, sanitizer.anchor),
                )
                for variable in sanitizer.input_variables
            )
        )
        and _sanitizer_applies_to_kind(sanitizer, sink_kind)
    ]


def _call_token(call: CallSiteFact) -> str:
    return f"@call:{call.callee}:{call.anchor.start_line}:{call.anchor.start_col or 0}"


def _fact_scope(
    fact: SourceFact | SinkFact | SanitizerFact | DataFlowFact | CallSiteFact | ControlFlowFact,
    functions_by_file: dict[str, list[FunctionFact]],
    functions_by_id: dict[str, FunctionFact] | None = None,
) -> tuple[str, str | None]:
    anchor = fact.anchor
    explicit = fact.enclosing_function_id
    if explicit:
        # A framework artifact may reside outside the Java method that owns its
        # semantics: e.g. a MyBatis XML statement bound to a mapper method.
        # Use the method's file as scope while preserving the XML anchor for
        # evidence and UI navigation.
        owner = (functions_by_id or {}).get(explicit)
        return (owner.anchor.file if owner else anchor.file), explicit
    enclosing = _enclosing_function(anchor, functions_by_file.get(anchor.file, []))
    return anchor.file, enclosing.id if enclosing else None


def _same_expression_flow(source: SourceFact, sink: SinkFact) -> bool:
    if source.anchor.file != sink.anchor.file:
        return False
    if source.analysis_method == sink.analysis_method == "ast":
        return _contains(sink.anchor, source.anchor)
    return source.anchor.start_line == sink.anchor.start_line and source.expression == sink.expression


def _inline_sanitizes_source(sanitizer: SanitizerFact, source: SourceFact, sink: SinkFact) -> bool:
    if not _sanitizer_applies(sanitizer, sink):
        return False
    if _is_guard_region(sanitizer):
        source_variables = [*source.variables, *source.input_variables]
        return (
            source.anchor.start_line < sanitizer.anchor.start_line
            and _contains(sanitizer.anchor, sink.anchor)
            and any(
                _paths_intersect(source_name, input_name) for source_name in source_variables for input_name in sanitizer.input_variables
            )
        )
    return _contains(sink.anchor, sanitizer.anchor) and _contains(sanitizer.anchor, source.anchor)


def _inline_sanitizes_variable(
    sanitizer: SanitizerFact,
    variable: str,
    sink: SinkFact,
    source_anchor: CodeAnchor,
) -> bool:
    return (
        _sanitizer_applies(sanitizer, sink)
        and any(_paths_intersect(variable, input_name) for input_name in sanitizer.input_variables)
        and (
            source_anchor.start_line < sanitizer.anchor.start_line and _contains(sanitizer.anchor, sink.anchor)
            if _is_guard_region(sanitizer)
            else _contains(sink.anchor, sanitizer.anchor)
        )
    )


def _canonical_sanitizes_variable(
    sanitizer: SanitizerFact,
    variable: str,
    sink: SinkFact,
    scope: tuple[str, str | None],
    aliases_by_scope: _AliasesByScope,
    source_anchor: CodeAnchor,
) -> bool:
    return (
        _sanitizer_applies(sanitizer, sink)
        and any(
            _paths_intersect(variable, _canonical_path(scope, input_name, aliases_by_scope, sanitizer.anchor))
            for input_name in sanitizer.input_variables
        )
        and (
            source_anchor.start_line < sanitizer.anchor.start_line and _contains(sanitizer.anchor, sink.anchor)
            if _is_guard_region(sanitizer)
            else _contains(sink.anchor, sanitizer.anchor)
        )
    )


def _is_guard_region(sanitizer: SanitizerFact) -> bool:
    return bool(sanitizer.anchor.symbol and sanitizer.anchor.symbol.startswith("guard:"))


def _sanitizer_applies(sanitizer: SanitizerFact, sink: SinkFact) -> bool:
    # Missing sink context is intentionally not treated as protection. A generic
    # sanitizer name is insufficient evidence that this particular sink is safe.
    return _sanitizer_applies_to_kind(sanitizer, sink.kind)


def _sanitizer_applies_to_kind(sanitizer: SanitizerFact, sink_kind: str) -> bool:
    return bool(sanitizer.applies_to_sink_kinds) and sink_kind in sanitizer.applies_to_sink_kinds


def _contains(container: CodeAnchor, child: CodeAnchor) -> bool:
    if container.file != child.file:
        return False
    container_start = (container.start_line, container.start_col or 0)
    container_end = (container.end_line, container.end_col if container.end_col is not None else 10**9)
    child_start = (child.start_line, child.start_col or 0)
    child_end = (child.end_line, child.end_col if child.end_col is not None else 10**9)
    return container_start <= child_start and child_end <= container_end


def _path_segments(path: str) -> list[str]:
    if path.startswith("@"):
        return [path]
    segments: list[str] = []
    current = ""
    index = 0
    while index < len(path):
        char = path[index]
        if char == ".":
            if current:
                segments.append(current)
                current = ""
            index += 1
            continue
        if char == "[":
            if current:
                segments.append(current)
                current = ""
            end = path.find("]", index + 1)
            if end < 0:
                current = path[index:]
                break
            value = path[index + 1 : end].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            segments.append(value or "*")
            index = end + 1
            continue
        current += char
        index += 1
    if current:
        segments.append(current)
    return segments or [path]


def _paths_intersect(left: str, right: str) -> bool:
    """Whether two access paths may describe overlapping runtime storage."""

    if left == right:
        return True
    if left.startswith("@") or right.startswith("@"):
        return False
    left_parts = _path_segments(left)
    right_parts = _path_segments(right)
    for left_part, right_part in zip(left_parts, right_parts, strict=False):
        if left_part != right_part and left_part != "*" and right_part != "*":
            return False
    # A tainted container taints a selected descendant and a tainted descendant
    # makes consuming the whole container unsafe; siblings remain independent.
    return True


def _make_candidate(
    sequence: int,
    source: SourceFact,
    sink: SinkFact,
    steps: list[TraceStep],
    sanitizers: list[SanitizerFact],
    route_id: str | None,
) -> TraceCandidate:
    confidence: Confidence = "high"
    if source.analysis_method != "ast" or sink.analysis_method != "ast" or any(step.confidence != "high" for step in steps):
        confidence = "medium"
    if source.analysis_method == "fallback" or sink.analysis_method == "fallback":
        confidence = "low"
    unique_sanitizers = list({item.id: item for item in sanitizers}.values())
    return TraceCandidate(
        id=f"{sink.vuln_class.upper()}-TRACE-{sequence:03d}",
        vuln_class=sink.vuln_class,
        source=source.anchor,
        sink=sink.anchor,
        steps=steps,
        sanitizers=[item.anchor for item in unique_sanitizers],
        blockers=[
            f"Related {item.kind} at {_format_anchor(item.anchor)} did not sanitize every value reaching this sink."
            for item in unique_sanitizers
        ],
        confidence=confidence,
        static_evidence=(
            f"Scoped {source.analysis_method} data flow connects {source.kind} at {_format_anchor(source.anchor)} "
            f"to {sink.kind} at {_format_anchor(sink.anchor)}."
        ),
        verification_hint=_verification_hint(sink.vuln_class, source, sink),
        route_id=route_id,
        taxonomy_id=sink.taxonomy_id,
        cwe_ids=sink.cwe_ids,
    )


def _append_candidate(
    candidate: TraceCandidate,
    candidates: list[TraceCandidate],
    seen: set[tuple[VulnClass, str, str, int, str, int]],
) -> None:
    key = _candidate_key(candidate)
    if key not in seen:
        seen.add(key)
        candidates.append(candidate)


def _candidate_key(candidate: TraceCandidate) -> tuple[VulnClass, str, str, int, str, int]:
    return (
        candidate.vuln_class,
        candidate.taxonomy_id or "",
        candidate.source.file,
        candidate.source.start_line,
        candidate.sink.file,
        candidate.sink.start_line,
    )


def nearest_route_id(facts: CodeFacts, anchor: CodeAnchor, scope_id: str | None = None) -> str | None:
    if scope_id:
        exact = [route for route in facts.routes if route.handler_function_id == scope_id]
        if exact:
            return exact[0].id
    routes = [route for route in facts.routes if route.anchor.file == anchor.file and route.anchor.start_line <= anchor.start_line]
    if not routes:
        return None
    return min(routes, key=lambda route: anchor.start_line - route.anchor.start_line).id


def _enclosing_function(anchor: CodeAnchor, functions: list[FunctionFact]) -> FunctionFact | None:
    matches = [function for function in functions if _contains(function.anchor, anchor)]
    if not matches:
        return None
    return min(matches, key=lambda function: function.anchor.end_line - function.anchor.start_line)


def _verification_hint(vuln_class: VulnClass, source: SourceFact, sink: SinkFact) -> str:
    if vuln_class == "injection":
        return f"Use an isolated target to verify whether {source.kind} controls the {sink.kind} argument; do not use destructive payloads."
    if vuln_class == "xss":
        return "Submit a unique inert marker and inspect the output encoding context without executing script."
    if vuln_class == "ssrf":
        return "Use only a controlled callback endpoint; never probe metadata, loopback, link-local, or private networks."
    if vuln_class == "auth":
        return "Compare valid and invalid credentials and session transitions in a dedicated test account."
    if vuln_class == "authz":
        return "Use two dedicated test identities to verify ownership and role checks without changing production data."
    return "Review the scoped data-flow evidence and validate in an isolated environment."


def _after(left: CodeAnchor, right: CodeAnchor) -> bool:
    return _anchor_order(left) > _anchor_order(right)


def _anchor_order(anchor: CodeAnchor) -> tuple[str, int, int, int, int]:
    return (
        anchor.file,
        anchor.start_line,
        anchor.start_col or 0,
        anchor.end_line,
        anchor.end_col or 0,
    )


def _anchor_key(anchor: CodeAnchor) -> tuple[str, int, int, int | None, int | None]:
    return anchor.file, anchor.start_line, anchor.end_line, anchor.start_col, anchor.end_col


def _format_anchor(anchor: CodeAnchor) -> str:
    return f"{anchor.file}:{anchor.start_line}"


def _confidence_rank(confidence: Confidence) -> int:
    return {"low": 1, "medium": 2, "high": 3}[confidence]


def _dedupe_graph_edges(edges: list[CodeEdge]) -> list[CodeEdge]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[CodeEdge] = []
    for edge in edges:
        key = (edge.from_id, edge.to_id, edge.kind, edge.evidence)
        if key not in seen:
            seen.add(key)
            output.append(edge)
    return output
