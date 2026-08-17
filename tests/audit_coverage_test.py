from __future__ import annotations

import json
from pathlib import Path

from auditforge.audit_coverage import build_audit_coverage
from auditforge.engine import run_scan
from auditforge.llm_candidates import (
    LLM_AUDIT_AGENTS,
    LLMAuditTask,
    LLMConfig,
    build_llm_prompt,
    generate_llm_candidates,
)
from auditforge.models import (
    CallSiteFact,
    CodeAnchor,
    CodeEdge,
    CodeFacts,
    CodeGraph,
    FunctionFact,
    IndexedFile,
    RouteFact,
    SinkFact,
    SourceFact,
)
from auditforge.scanner import scan_repo
from auditforge.store import read_dashboard_detail


def anchor(file: str, line: int, *, end_line: int | None = None, symbol: str | None = None) -> CodeAnchor:
    return CodeAnchor(
        file=file,
        start_line=line,
        end_line=end_line or line,
        snippet_hash=f"hash-{line}",
        symbol=symbol,
    )


def test_coverage_map_classifies_observable_gaps_and_rescan_state() -> None:
    caller = FunctionFact("fn-caller", "caller", anchor("app.py", 1, end_line=8), [], analysis_method="ast")
    target = FunctionFact("fn-target", "target", anchor("service.py", 1, end_line=3), [], analysis_method="ast")
    resolved = CallSiteFact("call-ok", "target", anchor("app.py", 3), enclosing_function_id=caller.id, analysis_method="ast")
    unresolved = CallSiteFact("call-gap", "target", anchor("app.py", 5), enclosing_function_id=caller.id, analysis_method="ast")
    source = SourceFact(
        "source-1",
        "http_query",
        "request.q",
        anchor("app.py", 2),
        "high",
        variables=["q"],
        enclosing_function_id=caller.id,
        analysis_method="ast",
    )
    sink = SinkFact(
        "sink-1",
        "sql_raw",
        "injection",
        "db.execute(q)",
        anchor("app.py", 6),
        "high",
        variables=["q"],
        enclosing_function_id=caller.id,
        analysis_method="ast",
    )
    facts = CodeFacts(
        files=[
            IndexedFile("file-app", "app.py", "python", 100, 8, "ast"),
            IndexedFile("file-service", "service.py", "python", 50, 3, "fallback", analysis_error="SyntaxError"),
        ],
        functions=[caller, target],
        routes=[RouteFact("route-1", "GET", "/items", "fixture", anchor("app.py", 1), analysis_method="ast")],
        call_sites=[resolved, unresolved],
        sources=[source],
        sinks=[sink],
        analysis_diagnostics={"discovered_source_files": 2, "analyzed_files": 2, "error_files": 1},
    )
    graph = CodeGraph(
        edges=[
            CodeEdge(
                from_id=resolved.id,
                to_id=target.id,
                kind="CALLS",
                confidence="high",
                evidence="fixture",
            )
        ]
    )
    llm = {
        "enabled": True,
        "failed": 0,
        "complete": False,
        "coverage": {"ratio": 0.5, "anchors": {"total": 2, "covered": 1}},
        "blindspot_rescan": {
            "enabled": True,
            "planned": 1,
            "executed": 1,
            "succeeded": 1,
            "failed": 0,
            "scopes": [
                {
                    "id": "blindspot:dataflow_injection:001",
                    "reasons": ["unresolved_calls", "unmatched_sinks", "parser_fallback"],
                }
            ],
        },
    }

    coverage = build_audit_coverage(facts, graph, [], llm)
    gaps = {item["id"]: item for item in coverage["blindspots"]}

    assert coverage["recall_measured"] is False
    assert coverage["score_kind"] == "analysis_confidence"
    assert coverage["dimensions"]["call_resolution"]["covered"] == 1
    assert coverage["dimensions"]["call_resolution"]["total"] == 2
    assert {"parser_fallback", "unresolved_calls", "unbound_routes", "unmatched_sinks"} <= set(gaps)
    assert gaps["unresolved_calls"]["anchors"][0] == {"file": "app.py", "line": 5, "symbol": None}
    assert gaps["unresolved_calls"]["auto_rescan"]["status"] == "completed"
    assert coverage["auto_rescan"]["executed"] == 1


def test_scan_persists_coverage_artifact_and_dashboard_summary(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "polyglot_vulnerable"
    result = run_scan(repo, tmp_path)

    artifact = json.loads((tmp_path / "analysis_coverage.json").read_text(encoding="utf-8"))
    dashboard = read_dashboard_detail(tmp_path)
    metadata = json.loads((tmp_path / "scan_metadata.json").read_text(encoding="utf-8"))

    assert artifact == result.analysis_coverage
    assert dashboard["artifacts"]["analysis_coverage"]["score_kind"] == "analysis_confidence"
    assert metadata["analysis_coverage"]["artifact"] == "analysis_coverage.json"
    assert result.stats()["analysis_blindspots"] == len(artifact["blindspots"])
    assert "分析覆盖与盲区" in (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "不代表漏洞检出率" in (tmp_path / "report.md").read_text(encoding="utf-8")


def test_focused_prompt_prioritizes_an_anchor_beyond_normal_fact_sample(tmp_path: Path) -> None:
    lines = ["def handler(value):", "    current = value"] + [f"    step_{index} = current" for index in range(3, 50)]
    (tmp_path / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    function = FunctionFact("fn-handler", "handler", anchor("app.py", 1, end_line=49), ["value"], analysis_method="ast")
    sinks = [
        SinkFact(
            f"sink-{line}",
            "sql_raw",
            "injection",
            f"step_{line}",
            anchor("app.py", line),
            "medium",
            variables=["current"],
            enclosing_function_id=function.id,
            analysis_method="ast",
        )
        for line in range(5, 45)
    ]
    facts = CodeFacts(
        files=[IndexedFile("file-app", "app.py", "python", 1000, 49, "ast")],
        functions=[function],
        sinks=sinks,
    )
    task = LLMAuditTask(
        id="blindspot:dataflow_injection:001",
        agent=next(agent for agent in LLM_AUDIT_AGENTS if agent.id == "dataflow_injection"),
        files=("app.py",),
        function_ids=(function.id,),
        scope_kind="blindspot_rescan",
        seed_function_ids=(function.id,),
        focus_anchor_lines=(("app.py", 44),),
        blindspot_reasons=("unmatched_sinks",),
    )

    payload = json.loads(build_llm_prompt(tmp_path, facts, [], 12000, audit_task=task))

    assert any(item["line"] == 44 for item in payload["facts"]["sinks"])
    assert payload["scope"]["focusAnchors"] == [{"file": "app.py", "line": 44}]
    assert payload["scope"]["blindspotReasons"] == ["unmatched_sinks"]


def test_transient_agent_failures_are_retried_once(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    facts = scan_repo(tmp_path)
    attempts: dict[str, int] = {}

    def flaky_response(prompt: str, config: LLMConfig) -> str:
        del config
        task_id = json.loads(prompt)["scope"]["id"]
        attempts[task_id] = attempts.get(task_id, 0) + 1
        if attempts[task_id] == 1:
            raise TimeoutError("transient fixture timeout")
        return json.dumps({"candidates": []})

    monkeypatch.setattr("auditforge.llm_candidates.load_llm_response", flaky_response)
    candidates, diagnostics = generate_llm_candidates(tmp_path, facts, [], LLMConfig(enabled=True, concurrency=3))

    assert candidates == []
    assert diagnostics["failed"] == 0
    assert diagnostics["blindspot_rescan"]["recovered_initial_tasks"] == 3
    assert all(item["attempts"] == 2 for item in diagnostics["task_details"])
    assert all(count == 2 for count in attempts.values())
