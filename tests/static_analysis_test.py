from __future__ import annotations

from pathlib import Path

import pytest

import auditforge.candidates as candidate_engine
from auditforge.candidates import build_trace_candidates
from auditforge.direct_findings import generate_direct_candidates
from auditforge.graph import build_graph
from auditforge.scanner import MAX_INDEXED_FILES, index_source_files, scan_repo


def analyze(repo: Path):
    facts = scan_repo(repo)
    graph = build_graph(facts)
    return facts, graph, build_trace_candidates(facts, graph)


def test_unrelated_source_and_sink_variables_do_not_create_candidate(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db):\n"
        "    untrusted = request.args.get('q')\n"
        "    fixed_query = 'select 1'\n"
        "    return db.execute(fixed_query)\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    assert facts.files[0].parsed_by == "ast"
    assert candidates == []


def test_unconditional_literal_overwrite_clears_taint_before_sink(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db):\n"
        "    query = request.args.get('q')\n"
        "    query = 'select 1'\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    overwrite = next(flow for flow in facts.data_flows if flow.anchor.start_line == 4)
    assert overwrite.ssa_safe_overwrite is True
    assert candidates == []


def test_conditional_literal_overwrite_keeps_taint_conservatively(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db, fallback):\n"
        "    query = request.args.get('q')\n"
        "    if fallback:\n"
        "        query = 'select 1'\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    overwrite = next(flow for flow in facts.data_flows if flow.anchor.start_line == 5)
    assert overwrite.ssa_safe_overwrite is False
    assert len(candidates) == 1
    assert (candidates[0].source.start_line, candidates[0].sink.start_line) == (3, 6)


def test_python_ast_extracts_scoped_structure_routes_calls_and_control_flow(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "class Controller:\n"
        "    @app.route('/items/<int:item_id>', methods=['GET'])\n"
        "    def item(self, item_id, db):\n"
        "        raw = request.args.get('q')\n"
        "        query = raw\n"
        "        if item_id:\n"
        "            return db.execute(query)\n",
        encoding="utf-8",
    )

    facts, graph, candidates = analyze(tmp_path)

    assert facts.files[0].parsed_by == "ast"
    assert [(item.name, item.qualified_name) for item in facts.classes] == [("Controller", "Controller")]
    function = next(item for item in facts.functions if item.name == "item")
    assert function.qualified_name == "Controller.item"
    assert function.class_id == facts.classes[0].id
    assert function.analysis_method == "ast"
    assert facts.routes[0].handler_function_id == function.id
    assert facts.routes[0].path == "/items/<int:item_id>"
    assert any(item.kind == "assignment" and item.target == "query" for item in facts.data_flows)
    assert any(item.kind == "if" and "item_id" in item.variables for item in facts.control_flows)
    assert any(item.callee == "db.execute" for item in facts.call_sites)
    assert all(item.analysis_method == "ast" for item in [*facts.sources, *facts.sinks])
    assert len(candidates) == 1
    assert any(edge.kind == "READS" for edge in graph.edges)


def test_unrelated_sanitizer_does_not_suppress_tainted_variable(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from markupsafe import escape\n"
        "def handler(db, harmless):\n"
        "    user_query = request.args.get('q')\n"
        "    safe_other = escape(harmless)\n"
        "    return db.execute(user_query)\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert len(candidates) == 1
    assert candidates[0].source.start_line == 4
    assert candidates[0].sink.start_line == 6
    assert candidates[0].taxonomy_id == "sql_injection"
    assert candidates[0].cwe_ids == ["CWE-89"]


def test_matching_sanitizer_only_cleans_its_output_variable(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from markupsafe import escape\n"
        "def handler():\n"
        "    raw = request.args.get('name')\n"
        "    clean = escape(raw)\n"
        "    return '<p>' + clean + '</p>'\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert candidates == []


def test_custom_clean_name_is_not_assumed_to_be_html_encoding(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def clean(value):\n"
        "    return value\n"
        "def handler():\n"
        "    raw = request.args.get('name')\n"
        "    unchanged = clean(raw)\n"
        "    return '<p>' + unchanged + '</p>'\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    assert not any(item.kind == "html_encoding" and item.anchor.start_line == 6 for item in facts.sanitizers)
    assert len(candidates) == 1
    assert (candidates[0].source.start_line, candidates[0].sink.start_line) == (5, 7)


def test_known_bleach_clean_remains_an_html_sanitizer(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import bleach\n"
        "from flask import request\n"
        "def handler():\n"
        "    raw = request.args.get('name')\n"
        "    escaped = bleach.clean(raw)\n"
        "    return '<p>' + escaped + '</p>'\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    assert any(item.kind == "html_encoding" and item.anchor.start_line == 5 for item in facts.sanitizers)
    assert candidates == []


@pytest.mark.parametrize("terminator", ["return None", "raise ValueError()"])
def test_negative_validation_guard_clause_dominates_following_sink(tmp_path: Path, terminator: str) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "def handler():\n"
        "    url = request.args.get('url')\n"
        "    if not validate_url(url):\n"
        f"        {terminator}\n"
        "    return requests.get(url)\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    assert candidates == []
    guards = [item for item in facts.sanitizers if item.anchor.symbol == "guard:url_validation"]
    assert len(guards) == 1
    assert (guards[0].anchor.start_line, guards[0].anchor.end_line) == (7, 7)


def test_positive_validation_branch_only_sanitizes_its_body(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "def handler():\n"
        "    url = request.args.get('url')\n"
        "    if validate_url(url):\n"
        "        return requests.get(url)\n"
        "    return 'blocked'\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    assert candidates == []
    guard = next(item for item in facts.sanitizers if item.anchor.symbol == "guard:url_validation")
    assert (guard.anchor.start_line, guard.anchor.end_line) == (6, 6)


def test_non_dominating_or_mismatched_guards_keep_findings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "from markupsafe import escape\n"
        "def non_terminating():\n"
        "    url = request.args.get('url')\n"
        "    if not validate_url(url):\n"
        "        print('invalid')\n"
        "    return requests.get(url)\n"
        "def wrong_variable():\n"
        "    url = request.args.get('url')\n"
        "    other = 'https://example.test'\n"
        "    if not validate_url(other):\n"
        "        return None\n"
        "    return requests.get(url)\n"
        "def wrong_category():\n"
        "    url = request.args.get('url')\n"
        "    if escape(url):\n"
        "        return requests.get(url)\n"
        "    return None\n"
        "def reassigned_after_guard():\n"
        "    url = 'https://example.test'\n"
        "    if not validate_url(url):\n"
        "        return None\n"
        "    url = request.args.get('url')\n"
        "    return requests.get(url)\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert len(candidates) == 4
    assert {candidate.sink.start_line for candidate in candidates} == {8, 14, 18, 25}


def test_same_variable_name_in_different_scopes_does_not_propagate(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def read_input():\n"
        "    value = request.args.get('q')\n"
        "    return value\n"
        "def run_query(db):\n"
        "    value = 'select 1'\n"
        "    return db.execute(value)\n",
        encoding="utf-8",
    )

    facts, graph, candidates = analyze(tmp_path)

    assert candidates == []
    value_nodes = [node for node in graph.nodes if node.kind == "Variable" and node.label == "value"]
    assert len(value_nodes) == 2
    assert len({node.metadata["scope_id"] for node in value_nodes}) == 2
    assert all(fact.enclosing_function_id for fact in [*facts.sources, *facts.sinks])


def test_resolved_call_argument_to_parameter_propagates(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def query_user(db, query):\n"
        "    return db.execute(query)\n"
        "def handler(db):\n"
        "    value = request.args.get('q')\n"
        "    return query_user(db, value)\n",
        encoding="utf-8",
    )

    _, graph, candidates = analyze(tmp_path)

    assert len(candidates) == 1
    assert candidates[0].source.start_line == 5
    assert candidates[0].sink.start_line == 3
    assert any(edge.kind == "CALLS" for edge in graph.edges)
    assert any(edge.kind == "READS" for edge in graph.edges)
    assert any(edge.kind == "WRITES" for edge in graph.edges)


def test_assignment_after_sink_does_not_create_a_backward_taint_path(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\ndef handler(db):\n    raw = request.args.get('q')\n    db.execute(query)\n    query = raw\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert candidates == []


def test_callee_assignment_after_sink_does_not_flow_back_to_earlier_sink(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def run_query(db, value):\n"
        "    query = 'select 1'\n"
        "    db.execute(query)\n"
        "    query = value\n"
        "def handler(db):\n"
        "    raw = request.args.get('q')\n"
        "    run_query(db, raw)\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert candidates == []


def test_object_alias_assigned_after_sink_does_not_retroactively_match(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db, payload):\n"
        "    payload.query = request.args.get('q')\n"
        "    db.execute(alias.query)\n"
        "    alias = payload\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert candidates == []


def test_loop_back_edges_remain_conservative_for_taint_propagation(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db):\n"
        "    raw = request.args.get('q')\n"
        "    for _ in range(2):\n"
        "        db.execute(query)\n"
        "        query = raw\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert len(candidates) == 1
    assert (candidates[0].source.start_line, candidates[0].sink.start_line) == (3, 5)


def test_unrelated_loop_does_not_relax_straight_line_ordering(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db):\n"
        "    raw = request.args.get('q')\n"
        "    db.execute(query)\n"
        "    query = raw\n"
        "    for _ in range(2):\n"
        "        print(_)\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert candidates == []


def test_interprocedural_solver_runs_once_per_source_and_sink_kind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "def handler(db):\n"
        "    raw = request.args.get('q')\n"
        "    db.execute(raw)\n"
        "    db.execute(raw)\n"
        "    requests.get(raw)\n"
        "    db.execute(raw)\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)
    graph = build_graph(facts)
    calls: list[tuple[str, str]] = []
    original = candidate_engine._trace_source_to_sink_kind

    def trace_source_to_sink_kind(*args, **kwargs):
        calls.append((args[0].id, args[2]))
        return original(*args, **kwargs)

    monkeypatch.setattr(candidate_engine, "_trace_source_to_sink_kind", trace_source_to_sink_kind)

    build_trace_candidates(facts, graph)

    source_count = len([source for source in facts.sources if source.variables])
    sink_kinds = {sink.kind for sink in facts.sinks}
    assert len(calls) == source_count * len(sink_kinds)
    assert len(calls) < source_count * len(facts.sinks)


def test_sink_kind_specific_sanitizer_does_not_prune_other_sink_kinds(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from markupsafe import escape\n"
        "def handler(db):\n"
        "    raw = request.args.get('q')\n"
        "    clean = escape(raw)\n"
        "    db.execute(clean)\n"
        "    return '<p>' + clean + '</p>'\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert len(candidates) == 1
    assert candidates[0].sink.symbol == "raw_sql"


def test_attribute_and_subscript_access_paths_propagate_without_tainting_siblings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def attribute_flow(db, state):\n"
        "    raw = request.args.get('q')\n"
        "    state.query = raw\n"
        "    return db.execute(state.query)\n"
        "def mapping_flow(db, payload):\n"
        "    raw = request.args.get('q')\n"
        "    payload['query'] = raw\n"
        "    payload['safe'] = 'select 1'\n"
        "    return db.execute(payload['query'])\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    targets = {flow.target for flow in facts.data_flows if flow.kind == "assignment"}
    assert {"state.query", "payload['query']", "payload['safe']"}.issubset(targets)
    assert {(candidate.source.start_line, candidate.sink.start_line) for candidate in candidates} == {(3, 5), (7, 10)}


def test_cross_file_return_summaries_reach_sink_through_two_calls(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text(
        "from flask import request\ndef user_input():\n    return request.args.get('q')\n",
        encoding="utf-8",
    )
    (tmp_path / "bridge.py").write_text(
        "from source import user_input\ndef forwarded():\n    return user_input()\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from bridge import forwarded\ndef handler(db):\n    query = forwarded()\n    return db.execute(query)\n",
        encoding="utf-8",
    )

    _, graph, candidates = analyze(tmp_path)

    assert len(candidates) == 1
    assert candidates[0].source.file == "source.py"
    assert candidates[0].sink.file == "app.py"
    assert sum(step.kind == "return" for step in candidates[0].steps) >= 2
    assert any(edge.kind == "CALLS" and edge.metadata.get("cross_file") for edge in graph.edges)


def test_call_argument_flow_facts_can_recover_missing_call_site_facts(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def run(db, query):\n"
        "    return db.execute(query)\n"
        "def handler(db):\n"
        "    raw = request.args.get('q')\n"
        "    return run(db, raw)\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)
    facts.call_sites = []
    graph = build_graph(facts)

    candidates = build_trace_candidates(facts, graph)

    assert len(candidates) == 1
    assert candidates[0].sink.start_line == 3


def test_fastapi_query_and_pydantic_body_parameters_are_sources(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "class SearchBody:\n"
        "    query: str\n"
        "@app.get('/search')\n"
        "def search(q: str, db=Depends(get_db)):\n"
        "    return db.execute(q)\n"
        "@app.post('/create')\n"
        "def create(payload: SearchBody, db=Depends(get_db)):\n"
        "    return db.execute(payload.query)\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    sources = {(source.kind, tuple(source.variables)) for source in facts.sources}
    assert ("http_query", ("q",)) in sources
    assert ("http_body", ("payload",)) in sources
    assert not any("db" in source.variables for source in facts.sources)
    assert {candidate.sink.start_line for candidate in candidates} == {7, 10}


def test_object_alias_writes_reach_original_attribute_and_subscript_reads(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def attribute_flow(db, payload):\n"
        "    raw = request.args.get('q')\n"
        "    alias = payload\n"
        "    alias.query = raw\n"
        "    db.execute(payload.query)\n"
        "def subscript_flow(db, payload):\n"
        "    raw = request.args.get('q')\n"
        "    alias = payload\n"
        "    alias['query'] = raw\n"
        "    return db.execute(payload['query'])\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert len(candidates) == 2
    assert {(candidate.source.start_line, candidate.sink.start_line) for candidate in candidates} == {(3, 6), (8, 11)}
    explanations = [step.explanation for candidate in candidates for step in candidate.steps]
    assert any("alias.query" in explanation for explanation in explanations)
    assert any("alias['query']" in explanation for explanation in explanations)


@pytest.mark.parametrize(
    ("tainted_target", "safe_target", "sink_variable"),
    [
        ("alias.query", "alias.query", "payload.query"),
        ("alias.query", "payload.query", "alias.query"),
        ("payload.query", "alias.query", "payload.query"),
    ],
)
def test_literal_overwrite_through_object_alias_clears_taint(
    tmp_path: Path,
    tainted_target: str,
    safe_target: str,
    sink_variable: str,
) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db, payload):\n"
        "    raw = request.args.get('q')\n"
        "    alias = payload\n"
        f"    {tainted_target} = raw\n"
        f"    {safe_target} = 'select 1'\n"
        f"    return db.execute({sink_variable})\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    overwrite = next(flow for flow in facts.data_flows if flow.anchor.start_line == 6)
    assert overwrite.ssa_safe_overwrite is True
    assert candidates == []


def test_rebinding_alias_does_not_overwrite_original_object(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db, payload):\n"
        "    raw = request.args.get('q')\n"
        "    alias = payload\n"
        "    alias.query = raw\n"
        "    alias = None\n"
        "    return db.execute(payload.query)\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert len(candidates) == 1
    assert (candidates[0].source.start_line, candidates[0].sink.start_line) == (3, 7)


def test_sanitized_write_through_object_alias_does_not_reach_original_read(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from markupsafe import escape\n"
        "def handler(payload):\n"
        "    raw = request.args.get('name')\n"
        "    alias = payload\n"
        "    alias.value = escape(raw)\n"
        "    return '<p>' + payload.value + '</p>'\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    assert any(item.kind == "html_encoding" and item.anchor.start_line == 6 for item in facts.sanitizers)
    assert candidates == []


def test_in_place_sanitizer_remains_effective_in_object_alias_scope(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def handler(db, payload):\n"
        "    raw = request.args.get('q')\n"
        "    raw = int(raw)\n"
        "    alias = payload\n"
        "    alias.query = raw\n"
        "    return db.execute(payload.query)\n",
        encoding="utf-8",
    )

    facts, _, candidates = analyze(tmp_path)

    assert any(item.kind == "type_validation" and item.anchor.start_line == 4 for item in facts.sanitizers)
    assert candidates == []


def test_parameter_field_side_effect_returns_to_caller_through_two_functions(tmp_path: Path) -> None:
    (tmp_path / "leaf.py").write_text(
        "def attach(state, value):\n    alias = state\n    alias.query = value\n",
        encoding="utf-8",
    )
    (tmp_path / "bridge.py").write_text(
        "from leaf import attach\ndef forward(state, value):\n    attach(state, value)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from bridge import forward\n"
        "def handler(db, state):\n"
        "    raw = request.args.get('q')\n"
        "    forward(state, raw)\n"
        "    return db.execute(state.query)\n",
        encoding="utf-8",
    )

    _, _, candidates = analyze(tmp_path)

    assert len(candidates) == 1
    assert candidates[0].source.file == "app.py"
    assert candidates[0].sink.file == "app.py"
    side_effect_steps = [step for step in candidates[0].steps if "Side effect" in step.explanation]
    assert len(side_effect_steps) >= 2
    assert {step.to_anchor.file for step in side_effect_steps} == {"app.py", "bridge.py"}


def test_index_limit_records_truncation_instead_of_silent_success(tmp_path: Path) -> None:
    for index in range(MAX_INDEXED_FILES + 1):
        (tmp_path / f"f{index:04d}.py").write_text("value = 1\n", encoding="utf-8")
    diagnostics: dict = {
        "max_indexed_files": MAX_INDEXED_FILES,
        "discovered_source_files": 0,
        "indexed_files": 0,
        "analyzed_files": 0,
        "ast_files": 0,
        "heuristic_files": 0,
        "fallback_files": 0,
        "skipped_files": 0,
        "error_files": 0,
        "truncated": False,
        "truncated_files": 0,
        "skipped": [],
        "errors": [],
        "analysis_coverage": {},
    }

    indexed = index_source_files(tmp_path, diagnostics)

    assert len(indexed) == MAX_INDEXED_FILES
    assert diagnostics["discovered_source_files"] == MAX_INDEXED_FILES + 1
    assert diagnostics["truncated"] is True
    assert diagnostics["truncated_files"] == 1


def test_symlinked_source_and_directory_are_skipped(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("from flask import request\nvalue = request.args.get('x')\n", encoding="utf-8")
    linked_file = tmp_path / "linked.py"
    linked_dir = tmp_path / "linked-dir"
    outside_dir = tmp_path.parent / f"{tmp_path.name}-outside-dir"
    outside_dir.mkdir()
    (outside_dir / "nested.py").write_text("value = 1\n", encoding="utf-8")
    try:
        try:
            linked_file.symlink_to(outside)
            linked_dir.symlink_to(outside_dir, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable on this platform: {exc}")
        facts = scan_repo(tmp_path)

        assert facts.files == []
        skipped = facts.analysis_diagnostics["skipped"]
        assert {item["path"] for item in skipped} == {"linked.py", "linked-dir"}
        assert all("symlink" in item["reason"] for item in skipped)
    finally:
        outside.unlink(missing_ok=True)
        (outside_dir / "nested.py").unlink(missing_ok=True)
        outside_dir.rmdir()


def test_syntax_error_falls_back_and_records_file_error(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    (tmp_path / "valid.py").write_text("def valid():\n    return 1\n", encoding="utf-8")

    facts = scan_repo(tmp_path)
    by_path = {item.path: item for item in facts.files}

    assert by_path["broken.py"].parsed_by == "fallback"
    assert by_path["broken.py"].analysis_error
    assert by_path["valid.py"].parsed_by == "ast"
    assert facts.analysis_diagnostics["error_files"] == 1
    assert facts.analysis_diagnostics["analyzed_files"] == 2


def test_route_name_direct_findings_are_disabled_by_default(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n@app.route('/admin')\ndef admin():\n    return 'ok'\n",
        encoding="utf-8",
    )
    facts, _, candidates = analyze(tmp_path)

    assert generate_direct_candidates(tmp_path, facts, candidates) == []
