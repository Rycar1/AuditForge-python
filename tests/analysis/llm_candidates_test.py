from __future__ import annotations

import json
from pathlib import Path

from auditforge.analysis.llm_candidates import LLMConfig, build_llm_prompt
from auditforge.analysis.llm_candidates import test_llm_connection as run_llm_connection_test
from auditforge.analysis.scanner import scan_repo
from auditforge.core.models import CodeAnchor, TraceCandidate
from auditforge.engine import run_scan
from auditforge.verification.deep_verification import (
    build_deep_verification_prompt,
    check_container_runtime,
    find_container_runtime_path,
    run_sandbox_test,
    select_deep_verification_candidates,
    validate_sandbox_script,
)


def _candidate(
    candidate_id: str,
    *,
    origin: str = "deterministic",
    confidence: str = "low",
    vuln_class: str = "injection",
    source_line: int = 1,
    route_id: str | None = None,
) -> TraceCandidate:
    source = CodeAnchor("app.py", source_line, source_line, f"src-{source_line}", "source")
    sink = CodeAnchor("app.py", source_line + 1, source_line + 1, f"sink-{source_line}", "sink")
    return TraceCandidate(
        id=candidate_id,
        vuln_class=vuln_class,  # type: ignore[arg-type]
        source=source,
        sink=sink,
        steps=[],
        sanitizers=[],
        blockers=[],
        confidence=confidence,  # type: ignore[arg-type]
        static_evidence="test candidate",
        verification_hint="test",
        route_id=route_id,
        origin=origin,  # type: ignore[arg-type]
    )


def test_llm_candidate_prompt_contains_rich_review_guidance() -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    facts = scan_repo(repo)

    payload = json.loads(build_llm_prompt(repo, facts, [], 28000))

    assert payload["role"] == "security_audit_candidate_generator"
    assert "callSites" in payload["facts"]
    assert payload["anchorContext"]
    assert "sourceSinkTaxonomy" in payload
    assert "decisionProcedure" in payload
    assert "pathAnchoringPolicy" in payload
    assert "ambiguityPolicy" in payload
    assert "evidenceQualityBar" in payload
    assert "flowStepRequirements" in payload
    assert "sanitizerContextMatrix" in payload
    assert "frameworkHints" in payload
    assert "languageFrameworkTriage" in payload
    assert "classSpecificFalsePositiveChecks" in payload
    assert "outputQualityGate" in payload
    assert "negativeExamples" in payload
    assert "confidenceRubric" in payload


def test_deep_verification_prompt_contains_declarative_runner_rubrics() -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    candidate = _candidate("llm-injection", origin="llm", confidence="high", source_line=9)

    payload = json.loads(build_deep_verification_prompt(repo, candidate))

    assert payload["role"] == "security_audit_deep_verifier"
    assert "candidateRiskModel" in payload
    assert "verdictDecisionTree" in payload
    assert "runtimeCapabilities" in payload
    assert "validationPlanPolicy" in payload
    assert "confirmationDiscipline" in payload
    assert "classSpecificEvidenceGates" in payload
    assert "negativeEvidencePolicy" in payload
    assert "failureModePolicy" in payload
    assert "verdictRubric" in payload
    assert "validationPlans" in payload["outputSchema"]
    assert "sandboxTests" not in payload["outputSchema"]
    assert "AF_MARKER" in json.dumps(payload, ensure_ascii=False)


def test_llm_candidate_fixture_provider_adds_non_duplicate_candidate(tmp_path: Path) -> None:
    response_file = tmp_path / "llm-response.json"
    response_file.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "vulnClass": "injection",
                        "source": {"file": "app.py", "startLine": 10},
                        "sink": {"file": "app.py", "startLine": 12},
                        "confidence": "high",
                        "staticEvidence": "duplicate deterministic candidate",
                        "verificationHint": "duplicate",
                    },
                    {
                        "vulnClass": "authz",
                        "source": {"file": "app.py", "startLine": 10, "symbol": "request.args"},
                        "sink": {"file": "app.py", "startLine": 12, "symbol": "db.execute"},
                        "steps": [
                            {
                                "kind": "llm_inferred",
                                "from": {"file": "app.py", "startLine": 10},
                                "to": {"file": "app.py", "startLine": 12},
                                "explanation": "LLM 认为该路径缺少业务权限条件，需要验证。",
                                "confidence": "low",
                            }
                        ],
                        "confidence": "low",
                        "staticEvidence": "LLM 补充一条需要人工验证的业务语义候选。",
                        "verificationHint": "使用不同角色重放请求并对比响应。",
                        "notes": ["测试 fixture"],
                    },
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    result = run_scan(
        repo,
        tmp_path / "workspace",
        llm_config=LLMConfig(enabled=True, provider="fixture", response_file=str(response_file)),
    )
    llm_candidates = [candidate for candidate in result.candidates if candidate.origin == "llm"]
    assert len(llm_candidates) == 1
    assert llm_candidates[0].vuln_class == "authz"
    assert result.llm_diagnostics["accepted"] == 1
    assert result.llm_diagnostics["rejected"][0]["reason"] == "duplicate"


def test_deep_verification_balances_deterministic_and_llm_candidates() -> None:
    candidates = [
        _candidate("det-low-1", source_line=1),
        _candidate("det-low-2", source_line=5),
        _candidate("det-high-authz", confidence="high", vuln_class="authz", source_line=9, route_id="route:admin"),
        _candidate("llm-medium-xss", origin="llm", confidence="medium", vuln_class="xss", source_line=30),
        _candidate("llm-high-authz", origin="llm", confidence="high", vuln_class="authz", source_line=40, route_id="route:admin"),
    ]

    selected = select_deep_verification_candidates(candidates, max_candidates=2)

    assert [candidate.id for candidate in selected] == ["det-high-authz", "llm-high-authz"]


def test_llm_candidate_malformed_schema_is_rejected(tmp_path: Path) -> None:
    response_file = tmp_path / "bad-llm-response.json"
    response_file.write_text(json.dumps({"items": [{"vulnClass": "xss"}]}, ensure_ascii=False), encoding="utf-8")
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"

    result = run_scan(
        repo,
        tmp_path / "workspace",
        llm_config=LLMConfig(enabled=True, provider="fixture", response_file=str(response_file)),
    )

    assert result.llm_diagnostics["accepted"] == 0
    assert result.llm_diagnostics["rejected"][0]["reason"].startswith("schema_error")
    assert not [candidate for candidate in result.candidates if candidate.origin == "llm"]


def test_llm_connection_fixture_and_missing_key() -> None:
    fixture_result = run_llm_connection_test(LLMConfig(enabled=True, provider="fixture", model="fixture-model"))
    assert fixture_result["ok"] is True
    assert fixture_result["provider"] == "fixture"

    try:
        run_llm_connection_test(
            LLMConfig(
                enabled=True,
                provider="openai-compatible",
                api_key=None,
                api_key_env="AUDITFORGE_NONEXISTENT_TEST_KEY",
            )
        )
    except ValueError as exc:
        assert "missing API key" in str(exc)
    else:
        raise AssertionError("missing API key should fail")


def test_deep_verification_fixture_reads_but_blocks_legacy_sandbox(tmp_path: Path) -> None:
    response_file = tmp_path / "deep-response.json"
    response_file.write_text(
        json.dumps(
            {
                "verdict": "confirmed",
                "confidence": "high",
                "reason": "用户输入以无害 marker 形式进入危险字符串拼接，沙箱可复现代码片段级行为。",
                "sandboxTests": [
                    {
                        "name": "SQL 拼接 marker 传播",
                        "language": "python",
                        "code": "\n".join(
                            [
                                "user_input = 'AF_MARKER'",
                                'query = "SELECT * FROM users WHERE name = \'" + user_input + "\'"',
                                "assert 'AF_MARKER' in query",
                                "assert '?' not in query",
                                "result_query = query",
                            ]
                        ),
                        "expected": "marker 出现在拼接后的 SQL 中。",
                    }
                ],
                "limitations": ["沙箱验证不等同于线上数据库执行。"],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"

    result = run_scan(
        repo,
        tmp_path,
        verify="deep",
        deep_llm_config=LLMConfig(enabled=True, provider="fixture", response_file=str(response_file), max_candidates=1),
    )

    assert len(result.verification_results) == 1
    assert result.verification_results[0].status == "blocked"
    assert result.verification_results[0].request_log[1]["type"] == "sandbox_python"
    assert result.verification_results[0].request_log[1]["execution_disabled"] is True
    assert result.verification_results[0].request_log[1]["blocked"] is True
    assert result.llm_diagnostics["deep_verification"]["sandbox_tasks"] == 0
    assert result.llm_diagnostics["deep_verification"]["legacy_sandbox_tests"] == 1
    sections = json.loads((tmp_path / "result_sections.json").read_text(encoding="utf-8"))
    assert sections["summary"]["sandbox_executed_reviews"] == 0


def test_deep_verification_malformed_json_contract_blocks_confirmation(tmp_path: Path) -> None:
    response_file = tmp_path / "bad-deep-response.json"
    response_file.write_text(json.dumps({"verdict": "confirmed"}, ensure_ascii=False), encoding="utf-8")
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"

    result = run_scan(
        repo,
        tmp_path,
        verify="deep",
        deep_llm_config=LLMConfig(enabled=True, provider="fixture", response_file=str(response_file), max_candidates=1),
    )

    assert result.verification_results[0].status == "blocked"
    assert "输出格式不符合" in result.verification_results[0].evidence[0]
    assert result.verification_results[0].request_log[0]["schema_valid"] is False


def test_deep_sandbox_rejects_unsafe_import() -> None:
    result = run_sandbox_test({"name": "unsafe", "language": "python", "code": "import os\nresult = os.getcwd()"})

    assert result["ok"] is False
    assert "Import" in result["policy_error"]


def test_sandbox_policy_allows_safe_try_chr_and_local_subscript_dispatch() -> None:
    validate_sandbox_script(
        "\n".join(
            [
                "calls = []",
                "def send_to_sink(value, timeout=0):",
                "    calls.append((value, timeout))",
                "    return True",
                "def get_db():",
                "    return {'execute': send_to_sink}",
                "try:",
                "    ok = get_db()['execute']('AF_MARKER', timeout=2)",
                "except Exception as exc:",
                "    ok = False",
                "letter = chr(65)",
                "assert ok is True",
                "assert letter == 'A'",
                "assert calls[0][0] == 'AF_MARKER'",
            ]
        )
    )


def test_sandbox_runner_exposes_safe_sink_placeholder() -> None:
    code = "sink('AF_MARKER', kind='ssrf')\nresult = 'done'"

    validate_sandbox_script(code)
    result = run_sandbox_test({"name": "safe sink", "language": "python", "code": code})
    runtime_ready, _ = check_container_runtime(find_container_runtime_path())
    if runtime_ready:
        assert result["ok"] is True
        assert result["sink_calls"][0]["args"] == ["'AF_MARKER'"]
        assert result["sink_calls"][0]["kwargs"] == {"kind": "'ssrf'"}
    else:
        assert result["blocked"] is True
