from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from auditforge.analysis.llm_candidates import (
    LLMConfig,
    build_code_context,
    build_llm_prompt,
    generate_llm_candidates,
    plan_llm_audit_tasks,
)
from auditforge.analysis.scanner import scan_repo


def _candidate(vuln_class: str, source_line: int, sink_line: int) -> dict:
    return {
        "vulnClass": vuln_class,
        "source": {"file": "app.py", "startLine": source_line},
        "sink": {"file": "app.py", "startLine": sink_line},
        "confidence": "medium",
        "staticEvidence": f"app.py:{source_line} 的外部输入可能到达 app.py:{sink_line} 的安全敏感操作。",
        "verificationHint": "在本地隔离环境使用无害标记并对比安全控制分支。",
    }


def _agent_response(prompt: str) -> str:
    payload = json.loads(prompt)
    if "app.py" not in payload["scope"]["files"]:
        return json.dumps({"candidates": []}, ensure_ascii=False)
    agent = payload["agent"]["id"]
    if agent == "dataflow_injection":
        candidate = _candidate("injection", 10, 12)
    elif agent == "auth_authz":
        candidate = _candidate("authz", 10, 12)
    else:
        candidate = _candidate("xss", 18, 19)
    return json.dumps({"candidates": [candidate]}, ensure_ascii=False)


def test_multi_agent_plan_contains_specialists_and_targeted_scopes() -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    tasks = plan_llm_audit_tasks(scan_repo(repo))

    assert {task.agent.id for task in tasks} == {"dataflow_injection", "auth_authz", "web_ssrf_xss"}
    assert all(task.files for task in tasks)
    assert any(task.scope_kind == "entrypoint_sink_slice" for task in tasks)
    assert len(tasks) > 3


def test_multi_agent_audit_runs_concurrently_and_merges_stably(monkeypatch) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    facts = scan_repo(repo)
    state = {"active": 0, "peak": 0}
    lock = threading.Lock()

    def fake_response(prompt: str, config: LLMConfig) -> str:
        del config
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        try:
            task_id = json.loads(prompt)["scope"]["id"]
            time.sleep(0.015 if task_id.endswith("001") else 0.03)
            response = json.loads(_agent_response(prompt))
            payload = json.loads(prompt)
            if payload["agent"]["id"] == "dataflow_injection" and "app.py" in payload["scope"]["files"]:
                response["candidates"].append(_candidate("injection", 30, 32))
            return json.dumps(response, ensure_ascii=False)
        finally:
            with lock:
                state["active"] -= 1

    monkeypatch.setattr("auditforge.analysis.llm_candidates.load_llm_response", fake_response)
    config = LLMConfig(enabled=True, concurrency=3, max_candidates=3)

    first, diagnostics = generate_llm_candidates(repo, facts, [], config)
    second, second_diagnostics = generate_llm_candidates(repo, facts, [], config)

    assert state["peak"] >= 2
    assert [candidate.vuln_class for candidate in first] == ["injection", "authz", "xss"]
    assert [(candidate.id, candidate.fingerprint) for candidate in first] == [(candidate.id, candidate.fingerprint) for candidate in second]
    assert diagnostics["agent_count"] == 3
    assert diagnostics["tasks"] == 9
    assert diagnostics["succeeded"] == 9
    assert diagnostics["failed"] == 0
    assert diagnostics["coverage"]["sinks"]["ratio"] == 1.0
    assert diagnostics["complete"] is True
    assert diagnostics["truncated"] is True
    assert diagnostics["evidence_critic"]["passed"] >= 3
    assert second_diagnostics["accepted"] == 3


def test_multi_agent_failure_isolated_and_reported(monkeypatch) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    facts = scan_repo(repo)

    def partially_failing_response(prompt: str, config: LLMConfig) -> str:
        del config
        if json.loads(prompt)["agent"]["id"] == "auth_authz":
            raise TimeoutError("auth agent timed out")
        return _agent_response(prompt)

    monkeypatch.setattr("auditforge.analysis.llm_candidates.load_llm_response", partially_failing_response)
    candidates, diagnostics = generate_llm_candidates(repo, facts, [], LLMConfig(enabled=True, concurrency=4))

    assert [candidate.vuln_class for candidate in candidates] == ["injection", "xss"]
    assert diagnostics["succeeded"] == 6
    assert diagnostics["failed"] == 3
    assert diagnostics["complete"] is False
    assert "auth agent timed out" in diagnostics["error"]
    assert sum(item["status"] == "failed" for item in diagnostics["task_details"]) == 3


def test_multi_agent_stage_deadline_returns_without_waiting_for_stalled_provider(monkeypatch) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    facts = scan_repo(repo)

    def stalled_response(prompt: str, config: LLMConfig) -> str:
        del prompt, config
        time.sleep(1)
        return json.dumps({"candidates": []})

    monkeypatch.setattr("auditforge.analysis.llm_candidates.load_llm_response", stalled_response)
    monkeypatch.setattr("auditforge.analysis.llm_candidates.llm_stage_timeout_seconds", lambda *args: 0)

    started = time.monotonic()
    candidates, diagnostics = generate_llm_candidates(repo, facts, [], LLMConfig(enabled=True, concurrency=3))

    assert candidates == []
    assert time.monotonic() - started < 0.5
    assert diagnostics["overall_timeout"] is True
    assert len(diagnostics["timed_out"]) == diagnostics["tasks"]
    assert all(item["status"] == "timed_out" for item in diagnostics["task_details"])


def test_local_evidence_gate_rejects_disconnected_trace(monkeypatch) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    facts = scan_repo(repo)

    def disconnected_response(prompt: str, config: LLMConfig) -> str:
        del config
        payload = json.loads(prompt)
        if payload["agent"]["id"] != "dataflow_injection" or "app.py" not in payload["scope"]["files"]:
            return json.dumps({"candidates": []})
        candidate = _candidate("injection", 10, 12)
        candidate["steps"] = [
            {
                "kind": "assignment",
                "from": {"file": "app.py", "startLine": 18},
                "to": {"file": "app.py", "startLine": 19},
                "explanation": "该步骤属于另一个处理函数，不能连接声明的 source 和 sink。",
                "confidence": "medium",
            }
        ]
        return json.dumps({"candidates": [candidate]}, ensure_ascii=False)

    monkeypatch.setattr("auditforge.analysis.llm_candidates.load_llm_response", disconnected_response)
    candidates, diagnostics = generate_llm_candidates(repo, facts, [], LLMConfig(enabled=True, concurrency=3))

    assert candidates == []
    assert diagnostics["evidence_critic"]["evaluated"] == 1
    assert diagnostics["evidence_critic"]["rejected"] == 1
    assert any(item["reason"].startswith("evidence_gate") for item in diagnostics["rejected"])


def test_quality_sorting_prefers_complete_unsanitized_trace_before_limit(monkeypatch) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    facts = scan_repo(repo)

    def ranked_response(prompt: str, config: LLMConfig) -> str:
        del config
        payload = json.loads(prompt)
        if payload["agent"]["id"] != "dataflow_injection" or "app.py" not in payload["scope"]["files"]:
            return json.dumps({"candidates": []})
        sanitized = _candidate("injection", 30, 32)
        vulnerable = _candidate("injection", 10, 12)
        vulnerable["confidence"] = "high"
        vulnerable["steps"] = [
            {
                "kind": "assignment",
                "from": {"file": "app.py", "startLine": 10},
                "to": {"file": "app.py", "startLine": 12},
                "explanation": "app.py:10 的查询参数直接进入 app.py:12 的 SQL 字符串拼接。",
                "confidence": "high",
            }
        ]
        return json.dumps({"candidates": [sanitized, vulnerable]}, ensure_ascii=False)

    monkeypatch.setattr("auditforge.analysis.llm_candidates.load_llm_response", ranked_response)
    candidates, diagnostics = generate_llm_candidates(
        repo,
        facts,
        [],
        LLMConfig(enabled=True, concurrency=3, max_candidates=1),
    )

    assert len(candidates) == 1
    assert candidates[0].source.start_line == 10
    assert candidates[0].sink.start_line == 12
    assert candidates[0].route_id is not None
    assert diagnostics["evidence_critic"]["passed"] == 2
    assert diagnostics["quality_order"][0]["fingerprint"] == candidates[0].fingerprint
    assert any(
        "applicable sanitizer" in reason for assessment in diagnostics["evidence_critic"]["assessments"] for reason in assessment["reasons"]
    )


def test_prompt_keeps_cross_file_connected_call_graph_and_structure_context(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "from service import process\n"
        "app = Flask(__name__)\n"
        "AUTH_MODE = 'strict'\n\n"
        "@app.get('/search')\n"
        "def handler():\n"
        "    value = request.args.get('q')\n"
        "    return process(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text(
        "from repo import query\nSERVICE_POLICY = 'default'\n\ndef process(value):\n    return query(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "repo.py").write_text(
        "SQL_PREFIX = 'SELECT * FROM users WHERE name = '\n\ndef query(value):\n    return db.execute(SQL_PREFIX + value)\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)
    handler = next(function for function in facts.functions if function.name == "handler")
    task = next(
        task for task in plan_llm_audit_tasks(facts) if task.agent.id == "dataflow_injection" and handler.id in task.seed_function_ids
    )

    payload = json.loads(build_llm_prompt(tmp_path, facts, [], 36000, audit_task=task))
    node_names = {node["name"] for node in payload["connectedCallSubgraph"]["nodes"]}
    structure = "\n".join(chunk["code"] for chunk in payload["structureContext"])

    assert {"handler", "process", "query"} <= node_names
    assert len(payload["connectedCallSubgraph"]["edges"]) >= 2
    assert "from service import process" in structure
    assert "from repo import query" in structure
    assert "@app.get('/search')" in structure
    assert "AUTH_MODE = 'strict'" in structure
    assert "SERVICE_POLICY = 'default'" in structure
    assert "SQL_PREFIX = 'SELECT * FROM users WHERE name = '" in structure


def test_long_function_does_not_starve_later_function_context(tmp_path: Path) -> None:
    huge_body = "\n".join(f"    value_{index} = {index}" for index in range(400))
    (tmp_path / "module.py").write_text(
        f"def enormous():\n{huge_body}\n    return value_399\n\ndef later(value):\n    return value\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)

    chunks = build_code_context(tmp_path, facts, max_chars=900)

    assert any(chunk.get("name") == "later" for chunk in chunks)
    assert any(chunk.get("name") == "enormous" and chunk["type"] == "function_window" for chunk in chunks)
