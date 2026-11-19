from __future__ import annotations

import json

from auditforge.core.models import VerificationResult
from auditforge.reporting.report import (
    render_declarative_validation_markdown,
    render_verification_result_html,
)
from auditforge.reporting.result_sections import (
    collect_declarative_validation_runs,
    has_runtime_negative_evidence,
    section_id_for_verification,
)
from auditforge.web.ui.server_ui import partition_candidate_rows, render_verification_block


def declarative_logs(*, runner_configured: bool = True, candidate_id: str = "candidate-1") -> list[dict]:
    return [
        {
            "type": "declarative_validation_plan",
            "plan_id": "plan-1",
            "candidate_id": candidate_id,
            "runner": {"mode": "inline", "configured": runner_configured},
            "plan": {
                "version": 1,
                "id": "plan-1",
                "candidate_id": candidate_id,
                "description": "发送无害 marker 并检查响应。",
                "steps": [
                    {
                        "id": "request-1",
                        "type": "http_request",
                        "action": "http_request",
                        "expected": {"body_contains": "AF_MARKER"},
                        "method": "GET",
                        "url": "http://127.0.0.1:8765/check?access_token=url-secret",
                        "query": {"probe": "AF_MARKER"},
                        "timeout_ms": 2_000,
                        "execution_status": "ready",
                    }
                ],
                "cleanup": {"strategy": "none", "always": True},
            },
        },
        {
            "type": "declarative_validation_result",
            "plan_id": "plan-1",
            "candidate_id": candidate_id,
            "status": "not_reproduced",
            "cleanup_status": "not_required",
            "notes": "password=runner-secret",
            "evidence": [
                {
                    "step_id": "request-1",
                    "action": "http_request",
                    "status": "failed",
                    "summary": "响应中未发现 marker。",
                    "observed": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8765/check?access_token=response-secret",
                        "status": 200,
                        "headers": {
                            "content-type": "application/json",
                            "x-api-key": "header-secret",
                        },
                        "body_sample": '{"password":"body-secret","ok":false}',
                        "response_truncated": False,
                        "assertions": {"body_contains": False},
                    },
                    "elapsed_ms": 7,
                    "artifacts": [],
                }
            ],
        },
    ]


def test_declarative_runner_negative_evidence_can_archive_candidate() -> None:
    verification = VerificationResult(
        candidate_id="candidate-1",
        status="not_reproducible",
        evidence=["marker absent"],
        request_log=declarative_logs(),
    )

    assert has_runtime_negative_evidence(verification) is True
    assert section_id_for_verification(verification) == "archived_results"

    candidates = [{"id": "candidate-1"}]
    results = {"candidate-1": verification.to_dict()}
    partitions = partition_candidate_rows(candidates, results)
    assert partitions["archived"] == [(candidates[0], results["candidate-1"])]
    assert partitions["candidate"] == []


def test_unpaired_or_unconfigured_declarative_result_cannot_archive_candidate() -> None:
    unpaired = VerificationResult(
        candidate_id="candidate-1",
        status="not_reproducible",
        evidence=["LLM says not reproduced"],
        request_log=[declarative_logs()[1]],
    )
    unconfigured = VerificationResult(
        candidate_id="candidate-1",
        status="not_reproducible",
        evidence=["runner disabled"],
        request_log=declarative_logs(runner_configured=False),
    )
    mismatched = VerificationResult(
        candidate_id="candidate-1",
        status="not_reproducible",
        evidence=["wrong candidate"],
        request_log=declarative_logs(candidate_id="candidate-2"),
    )

    for verification in (unpaired, unconfigured, mismatched):
        assert has_runtime_negative_evidence(verification) is False
        assert section_id_for_verification(verification) == "candidate_vulnerabilities"


def test_failed_assertion_on_error_response_cannot_archive_candidate() -> None:
    logs = json.loads(json.dumps(declarative_logs(), ensure_ascii=False))
    logs[1]["evidence"][0]["observed"]["status"] = 404
    verification = VerificationResult(
        candidate_id="candidate-1",
        status="not_reproducible",
        evidence=["marker absent because route returned an error"],
        request_log=logs,
    )

    assert has_runtime_negative_evidence(verification) is False
    assert section_id_for_verification(verification) == "candidate_vulnerabilities"


def test_passed_safe_control_can_support_false_positive_archival() -> None:
    logs = json.loads(json.dumps(declarative_logs(), ensure_ascii=False))
    logs[0]["plan"]["steps"][0]["expected"] = {"status": 200, "body_not_contains": "AF_MARKER"}
    logs[1]["status"] = "runtime_confirmed"
    logs[1]["evidence"][0]["status"] = "passed"
    logs[1]["evidence"][0]["summary"] = "sanitizer removed the marker"
    logs[1]["evidence"][0]["observed"]["assertions"] = {"status": True, "body_not_contains": True}
    verification = VerificationResult(
        candidate_id="candidate-1",
        status="false_positive",
        evidence=["runtime safe control passed"],
        request_log=logs,
    )

    assert has_runtime_negative_evidence(verification) is True
    assert section_id_for_verification(verification) == "archived_results"


def test_reports_render_structured_evidence_redacted_and_keep_legacy_sandbox() -> None:
    request_log = declarative_logs()
    request_log.append(
        {
            "type": "sandbox_python",
            "name": "legacy check",
            "ok": True,
            "code": "assert '<marker>'",
            "isolation": "container",
            "container_runtime": "docker",
            "network": "none",
        }
    )
    verification = VerificationResult(
        candidate_id="candidate-1",
        status="not_reproducible",
        evidence=["marker absent"],
        request_log=request_log,
    )

    report_html = render_verification_result_html(verification)
    dashboard_html = render_verification_block(
        {
            "candidate_id": verification.candidate_id,
            "status": verification.status,
            "payload_json": json.dumps(verification.to_dict(), ensure_ascii=False),
        }
    )
    markdown = "\n".join(render_declarative_validation_markdown(request_log))

    for rendered in (report_html, dashboard_html):
        assert "查看声明式验证计划与运行证据" in rendered
        assert "计划步骤与断言" in rendered
        assert "运行证据" in rendered
        assert "AF_MARKER" in rendered
        assert "响应中未发现 marker" in rendered
        assert "脱敏响应" in rendered
        assert "body_contains" in rendered
        assert "查看容器沙箱测试代码" in rendered
        assert "legacy check" in rendered
        assert "&lt;marker&gt;" in rendered
        assert "url-secret" not in rendered
        assert "response-secret" not in rendered
        assert "header-secret" not in rendered
        assert "body-secret" not in rendered
        assert "runner-secret" not in rendered
        assert "[REDACTED]" in rendered

    assert "声明式验证证据" in markdown
    assert "HTTP 200" in markdown
    assert "响应正文（已脱敏/限长）" in markdown
    assert "response-secret" not in markdown
    assert "body-secret" not in markdown
    assert "[REDACTED]" in markdown


def test_single_entry_declarative_validation_shape_is_supported() -> None:
    plan_entry, result_entry = declarative_logs()
    combined = {
        "type": "declarative_validation",
        "plan_id": "plan-1",
        "candidate_id": "candidate-1",
        "runner": plan_entry["runner"],
        "plan": plan_entry["plan"],
        "result": {
            key: value
            for key, value in result_entry.items()
            if key in {"plan_id", "candidate_id", "status", "cleanup_status", "notes", "evidence"}
        },
    }

    runs = collect_declarative_validation_runs([combined])

    assert len(runs) == 1
    assert runs[0]["plan"]["id"] == "plan-1"
    assert runs[0]["result"]["status"] == "not_reproduced"
    assert has_runtime_negative_evidence(VerificationResult("candidate-1", "not_reproducible", [], [combined]))


def test_flattened_plan_and_result_log_shape_is_supported() -> None:
    plan_entry, result_entry = declarative_logs()
    flattened = [
        {"type": "declarative_validation_plan", **plan_entry["plan"]},
        {
            "type": "declarative_validation_result",
            "runner": "queue",
            **{
                key: value
                for key, value in result_entry.items()
                if key in {"plan_id", "candidate_id", "status", "cleanup_status", "notes", "evidence"}
            },
        },
    ]

    runs = collect_declarative_validation_runs(flattened)

    assert runs[0]["plan"]["id"] == "plan-1"
    assert runs[0]["runner"] == {"mode": "queue", "configured": True}
    assert has_runtime_negative_evidence(VerificationResult("candidate-1", "not_reproducible", [], flattened))
