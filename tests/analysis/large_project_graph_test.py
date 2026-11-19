from __future__ import annotations

import auditforge.analysis.graph as graph_module
from auditforge.analysis.graph import build_graph
from auditforge.core.models import CallSiteFact, CodeAnchor, CodeFacts, FunctionFact, IndexedFile, SanitizerFact, SinkFact


def test_indexed_call_resolution_scales_for_many_java_service_calls() -> None:
    service_count = 1200
    call_count = 3600
    files = [
        IndexedFile("file:controller", "Controller.java", "java", 100, call_count + 2, "ast"),
        *[IndexedFile(f"file:{index}", f"services/Service{index}.java", "java", 80, 4, "ast") for index in range(service_count)],
    ]
    functions = [
        FunctionFact(
            id=f"function:{index}",
            name="find",
            anchor=CodeAnchor(f"services/Service{index}.java", 2, 2, f"function-{index}", "find"),
            params=["id"],
            qualified_name=f"Service{index}.find",
            class_id=f"class:{index}",
            analysis_method="ast",
        )
        for index in range(service_count)
    ]
    calls = [
        CallSiteFact(
            id=f"call:{index}",
            callee=f"service{index % service_count}.find",
            anchor=CodeAnchor("Controller.java", index + 2, index + 2, f"call-{index}", "find"),
            analysis_method="ast",
        )
        for index in range(call_count)
    ]

    graph = build_graph(CodeFacts(files=files, functions=functions, call_sites=calls))

    call_edges = [edge for edge in graph.edges if edge.kind == "CALLS"]
    assert len(call_edges) == call_count
    assert {edge.to_id for edge in call_edges} == {f"function:{index}" for index in range(service_count)}


def test_sanitizer_root_index_preserves_guarded_edges_for_large_scopes(monkeypatch) -> None:
    sink_count = 300
    file_path = "app.py"
    scope_id = "function:handler"
    file = IndexedFile("file:app", file_path, "python", 100, sink_count + 400, "ast")
    function = FunctionFact(
        id=scope_id,
        name="handler",
        anchor=CodeAnchor(file_path, 1, sink_count + 400, "handler", "handler"),
        params=[],
        analysis_method="ast",
    )
    sinks = [
        SinkFact(
            id=f"sink:{index}",
            kind="raw_sql",
            vuln_class="sqli",
            expression=f"db.execute(payload{index}.query)",
            anchor=CodeAnchor(file_path, sink_count + index + 20, sink_count + index + 20, f"sink-{index}"),
            confidence="high",
            variables=[f"payload{index}.query"],
            enclosing_function_id=scope_id,
            analysis_method="ast",
        )
        for index in range(sink_count)
    ]
    # A wildcard-root sink must be considered for every concrete sanitizer root.
    sinks.append(
        SinkFact(
            id="sink:wildcard",
            kind="raw_sql",
            vuln_class="sqli",
            expression="db.execute(payload[*].query)",
            anchor=CodeAnchor(file_path, sink_count * 2 + 30, sink_count * 2 + 30, "sink-wildcard"),
            confidence="high",
            variables=["[*].query"],
            enclosing_function_id=scope_id,
            analysis_method="ast",
        )
    )
    sanitizers = [
        SanitizerFact(
            id=f"sanitizer:{index}",
            kind="sql_parameterization",
            expression=f"payload{index}.query = sanitize(payload{index}.query)",
            anchor=CodeAnchor(file_path, index + 2, index + 2, f"sanitizer-{index}"),
            confidence="high",
            variables=[f"payload{index}.query"],
            input_variables=[f"payload{index}.query"],
            enclosing_function_id=scope_id,
            analysis_method="ast",
            applies_to_sink_kinds=["raw_sql"],
        )
        for index in range(sink_count)
    ]
    # An unknown sanitizer root must conservatively inspect every sink in scope.
    sanitizers.append(
        SanitizerFact(
            id="sanitizer:wildcard",
            kind="sql_parameterization",
            expression="sanitize(payload[*].query)",
            anchor=CodeAnchor(file_path, 1, 1, "sanitizer-wildcard"),
            confidence="high",
            variables=["[*].query"],
            input_variables=["[*].query"],
            enclosing_function_id=scope_id,
            analysis_method="ast",
            applies_to_sink_kinds=["raw_sql"],
        )
    )
    facts = CodeFacts(files=[file], functions=[function], sinks=sinks, sanitizers=sanitizers)

    original_paths_intersect = graph_module._paths_intersect
    intersection_calls = 0

    def counted_paths_intersect(left: str, right: str) -> bool:
        nonlocal intersection_calls
        intersection_calls += 1
        return original_paths_intersect(left, right)

    expected = {
        (sanitizer.id, sink.id)
        for sanitizer in sanitizers
        for sink in sinks
        if any(original_paths_intersect(variable, sink_variable) for variable in sanitizer.variables for sink_variable in sink.variables)
        and sanitizer.anchor.start_line <= sink.anchor.start_line
        and sink.kind in sanitizer.applies_to_sink_kinds
    }
    monkeypatch.setattr(graph_module, "_paths_intersect", counted_paths_intersect)

    graph = build_graph(facts)

    guarded = {(edge.from_id, edge.to_id) for edge in graph.edges if edge.kind == "GUARDED_BY"}
    assert guarded == expected
    assert ("sanitizer:0", "sink:wildcard") in guarded
    assert ("sanitizer:wildcard", "sink:0") in guarded
    # The legacy nested join would invoke the predicate for every pair.
    assert intersection_calls < len(sanitizers) * len(sinks) // 20
