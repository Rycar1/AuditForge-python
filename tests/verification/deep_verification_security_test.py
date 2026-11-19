from __future__ import annotations

import time
from pathlib import Path

import pytest

import auditforge.deep_verification as deep_verification
from auditforge.deep_verification import (
    ContainerRuntimeError,
    container_sandbox_image,
    decide_declarative_status,
    decide_deep_status,
    evaluate_sandbox_negative_proof,
    evaluate_sandbox_proof,
    finalize_candidate_deep_review,
    normalize_validation_plans,
    run_deep_verification,
    validate_deep_response_schema,
)
from auditforge.llm_candidates import LLMConfig
from auditforge.models import CodeAnchor, CodeFacts, RouteFact, TraceCandidate
from auditforge.validation_dsl import EvidenceRecord, ValidationEvidenceResult, normalize_validation_plan
from auditforge.validation_runner import ValidationRunnerConfig


def test_constant_assertion_cannot_promote_deep_result() -> None:
    proof_valid, reason = evaluate_sandbox_proof("assert True", {"ok": True})

    assert proof_valid is False
    assert "恒真" in reason
    assert decide_deep_status("confirmed", proof_valid, has_tests=True) == "blocked"


def test_observable_marker_proof_is_only_sandbox_executed() -> None:
    code = "value = 'AF_MARKER'\nassert value == 'AF_MARKER'\nresult_value = value"
    proof_valid, _ = evaluate_sandbox_proof(code, {"exports": {"result_value": "'AF_MARKER'"}})

    assert proof_valid is True
    assert decide_deep_status("confirmed", proof_valid, has_tests=True) == "sandbox_executed"


def test_sandbox_image_requires_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITFORGE_SANDBOX_IMAGE", "python:3.12-alpine")
    with pytest.raises(ContainerRuntimeError, match="sha256"):
        container_sandbox_image()

    monkeypatch.delenv("AUDITFORGE_SANDBOX_IMAGE")
    assert "@sha256:" in container_sandbox_image()


def test_llm_negative_verdict_without_runtime_proof_stays_manual() -> None:
    assert decide_deep_status("false_positive", False, has_tests=False) == "needs_manual_review"
    assert decide_deep_status("not_reproducible", False, has_tests=True) == "needs_manual_review"
    assert (
        decide_deep_status(
            "false_positive",
            False,
            has_tests=True,
            negative_proof_valid=True,
            transport_failed=True,
        )
        == "needs_manual_review"
    )


def test_executed_negative_assertion_can_support_negative_verdict() -> None:
    code = "\n".join(
        [
            "marker = 'AF_MARKER'",
            "safe_value = marker.replace('AF_MARKER', '[escaped]')",
            "assert marker not in safe_value",
            "result_safe_value = safe_value",
        ]
    )
    valid, reason = evaluate_sandbox_negative_proof(
        code,
        {"ok": True, "exports": {"result_safe_value": "'[escaped]'"}, "sink_calls": []},
    )

    assert valid is True, reason
    assert decide_deep_status("false_positive", False, has_tests=True, negative_proof_valid=valid) == "false_positive"


def test_deep_verification_uses_independent_llm_and_validation_queues(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    anchor = CodeAnchor("app.py", 1, 1, "hash")
    candidates = [
        TraceCandidate(
            id=f"candidate-{index}",
            vuln_class="injection",
            source=anchor,
            sink=anchor,
            steps=[],
            sanitizers=[],
            blockers=[],
            confidence="high",
            static_evidence="test",
            verification_hint="test",
            route_id="route-test",
        )
        for index in range(4)
    ]
    route = RouteFact("route-test", "GET", "/probe", "test", anchor)
    facts = CodeFacts(routes=[route])

    def fake_prepare(  # noqa: ANN001, ANN202 - executor test double
        repo_path,
        candidate,
        config,
        target_url,
        allow_state_changes,
        allowed_route,
    ):
        time.sleep(0.03)
        plans = [
            normalize_validation_plan(
                {
                    "version": 1,
                    "id": f"{candidate.id}-{suffix}",
                    "candidate_id": candidate.id,
                    "steps": [
                        {
                            "id": "request-1",
                            "action": "http_request",
                            "method": "GET",
                            "url": "/probe",
                            "query": {"input": "AF_MARKER"},
                            "expected": {"status": 200, "body_contains": "AF_MARKER"},
                        }
                    ],
                    "cleanup": "none",
                },
                target_url=target_url,
            )
            for suffix in ("a", "b")
        ]
        return {
            "candidate": candidate,
            "verdict": "confirmed",
            "confidence": "high",
            "reason": "test",
            "validation_plans": plans,
            "legacy_tests": [],
            "route_bound": allowed_route is not None,
            "limitations": [],
            "llm_latency_ms": 1,
            "immediate_result": None,
        }

    def fake_dispatch(plan, *_args):  # noqa: ANN001, ANN202 - executor test double
        time.sleep(0.03)
        return ValidationEvidenceResult(
            plan_id=plan.id,
            candidate_id=plan.candidate_id,
            status="runtime_confirmed",
            evidence=(
                EvidenceRecord(
                    step_id="request-1",
                    action="http_request",
                    status="passed",
                    summary="response matched",
                    observed={
                        "method": "GET",
                        "url": "http://127.0.0.1:8080/probe",
                        "status": 200,
                        "body_sample": "AF_MARKER",
                        "assertions": {"status": True, "body_contains": True},
                    },
                ),
            ),
            cleanup_status="not_required",
        )

    monkeypatch.setattr(deep_verification, "prepare_candidate_deep_review", fake_prepare)
    monkeypatch.setattr(deep_verification, "dispatch_prepared_validation", fake_dispatch)
    monkeypatch.setattr(
        deep_verification,
        "run_sandbox_test",
        lambda _test: pytest.fail("new deep verification must not execute LLM-authored Python"),
    )

    results, diagnostics = run_deep_verification(
        tmp_path,
        candidates,
        LLMConfig(enabled=True, concurrency=2, max_candidates=4),
        sandbox_concurrency=4,
        target_url="http://127.0.0.1:8080",
        validation_runner_config=ValidationRunnerConfig(mode="inline"),
        code_facts=facts,
    )

    assert len(results) == 4
    assert all(result.status == "confirmed" for result in results)
    assert diagnostics["llm_concurrency"] == 2
    assert diagnostics["validation_concurrency"] == 4
    assert diagnostics["validation_tasks"] == 8
    assert diagnostics["validation_runtime_confirmed"] == 8
    assert diagnostics["sandbox_tasks"] == 0
    assert diagnostics["llm_max_concurrency_observed"] == 2
    assert diagnostics["validation_max_concurrency_observed"] == 4


def test_validation_plan_aliases_and_route_binding_are_enforced() -> None:
    route = RouteFact("route-item", "GET", "/items/<int:item_id>", "flask", CodeAnchor("app.py", 1, 1, "route"))
    plan = {
        "version": 1,
        "id": "plan-item",
        "candidate_id": "candidate-item",
        "steps": [
            {
                "id": "request-1",
                "action": "http_request",
                "method": "GET",
                "url": "/items/7",
                "expected": {"status": 200, "body_contains": "AF_MARKER"},
            }
        ],
        "cleanup": "none",
    }
    payload = {
        "verdict": "confirmed",
        "confidence": "high",
        "reason": "route-bound evidence",
        "verificationPlans": [plan],
        "evidence": [],
        "limitations": [],
    }

    assert (
        validate_deep_response_schema(
            payload,
            target_url="http://127.0.0.1:8080",
            candidate_id="candidate-item",
            allowed_route=route,
        )
        == []
    )
    normalized = normalize_validation_plans(
        payload["verificationPlans"],
        candidate_id="candidate-item",
        target_url="http://127.0.0.1:8080",
        allowed_route=route,
    )
    assert normalized[0].id == "plan-item"

    payload["verificationPlans"][0]["steps"][0]["url"] = "/admin"
    errors = validate_deep_response_schema(
        payload,
        target_url="http://127.0.0.1:8080",
        candidate_id="candidate-item",
        allowed_route=route,
    )
    assert any("does not match candidate route" in error for error in errors)

    payload["verificationPlans"][0]["steps"][0]["url"] = "/items/7"
    payload["verificationPlans"][0]["steps"][0]["method"] = "POST"
    payload["verificationPlans"][0]["cleanup"] = "rollback"
    errors = validate_deep_response_schema(
        payload,
        target_url="http://127.0.0.1:8080",
        candidate_id="candidate-item",
        allowed_route=route,
    )
    assert any("is not allowed by candidate route" in error for error in errors)

    payload["verificationPlans"][0]["steps"][0]["method"] = "GET"
    payload["verificationPlans"][0]["steps"][0]["url"] = "/items/%2e%2e/admin"
    payload["verificationPlans"][0]["cleanup"] = "none"
    errors = validate_deep_response_schema(
        payload,
        target_url="http://127.0.0.1:8080",
        candidate_id="candidate-item",
        allowed_route=route,
    )
    assert any("traversal segment" in error for error in errors)


def test_deep_schema_rejects_null_plan_and_legacy_arrays() -> None:
    base = {
        "verdict": "needs_manual_review",
        "confidence": "low",
        "reason": "missing runtime context",
        "evidence": [],
        "limitations": [],
    }

    assert "validationPlans 必须是数组" in validate_deep_response_schema({**base, "validationPlans": None})
    assert "sandboxTests 必须是数组" in validate_deep_response_schema({**base, "sandboxTests": None})


def test_legacy_sandbox_response_is_read_but_never_executed() -> None:
    anchor = CodeAnchor("app.py", 1, 1, "hash")
    candidate = TraceCandidate(
        id="candidate-legacy",
        vuln_class="injection",
        source=anchor,
        sink=anchor,
        steps=[],
        sanitizers=[],
        blockers=[],
        confidence="high",
        static_evidence="test",
        verification_hint="test",
    )
    review = {
        "candidate": candidate,
        "verdict": "confirmed",
        "confidence": "high",
        "reason": "legacy response",
        "validation_plans": [],
        "legacy_tests": [
            {
                "name": "legacy",
                "language": "python",
                "code": "raise RuntimeError('must not run')",
                "expected": "never executed",
            }
        ],
        "limitations": [],
        "llm_latency_ms": 1,
    }

    result = finalize_candidate_deep_review(review, [])

    assert result.status == "blocked"
    assert result.request_log[1]["type"] == "sandbox_python"
    assert result.request_log[1]["execution_disabled"] is True
    assert result.request_log[1]["blocked"] is True


@pytest.mark.parametrize("vuln_class", ["xss", "ssrf", "auth", "authz"])
def test_generic_http_assertion_cannot_confirm_specialized_vulnerability(vuln_class: str) -> None:
    anchor = CodeAnchor("app.py", 1, 1, "hash")
    candidate = TraceCandidate(
        id=f"candidate-{vuln_class}",
        vuln_class=vuln_class,  # type: ignore[arg-type]
        source=anchor,
        sink=anchor,
        steps=[],
        sanitizers=[],
        blockers=[],
        confidence="high",
        static_evidence="test",
        verification_hint="test",
        route_id="route-probe",
    )
    plan = normalize_validation_plan(
        {
            "version": 1,
            "id": f"plan-{vuln_class}",
            "candidate_id": candidate.id,
            "steps": [
                {
                    "id": "request-1",
                    "action": "http_request",
                    "method": "GET",
                    "url": "/probe",
                    "query": {"input": "AF_MARKER"},
                    "expected": {"status": 200, "body_contains": "AF_MARKER"},
                }
            ],
            "cleanup": "none",
        }
    )
    runner_result = ValidationEvidenceResult(
        plan_id=plan.id,
        candidate_id=candidate.id,
        status="runtime_confirmed",
        evidence=(
            EvidenceRecord(
                step_id="request-1",
                action="http_request",
                status="passed",
                summary="generic response matched",
                observed={
                    "method": "GET",
                    "url": "http://127.0.0.1:8080/probe",
                    "status": 200,
                    "body_sample": "AF_MARKER",
                    "assertions": {"status": True, "body_contains": True},
                },
            ),
        ),
        cleanup_status="not_required",
    )

    assert decide_declarative_status(candidate, "confirmed", [plan], [runner_result], route_bound=True) == "needs_manual_review"


def test_structured_declarative_request_log_and_route_bound_confirmation() -> None:
    anchor = CodeAnchor("app.py", 1, 1, "hash")
    candidate = TraceCandidate(
        id="candidate-injection",
        vuln_class="injection",
        source=anchor,
        sink=anchor,
        steps=[],
        sanitizers=[],
        blockers=[],
        confidence="high",
        static_evidence="test",
        verification_hint="test",
        route_id="route-probe",
    )
    plan = normalize_validation_plan(
        {
            "version": 1,
            "id": "plan-injection",
            "candidate_id": candidate.id,
            "steps": [
                {
                    "id": "request-1",
                    "action": "http_request",
                    "method": "GET",
                    "url": "/probe",
                    "query": {"input": "AF_MARKER"},
                    "expected": {"status": 200, "body_contains": "AF_MARKER"},
                }
            ],
            "cleanup": "none",
        }
    )
    runner_result = ValidationEvidenceResult(
        plan_id=plan.id,
        candidate_id=candidate.id,
        status="runtime_confirmed",
        evidence=(
            EvidenceRecord(
                step_id="request-1",
                action="http_request",
                status="passed",
                summary="marker observed",
                observed={
                    "method": "GET",
                    "url": "http://127.0.0.1:8080/probe",
                    "status": 200,
                    "body_sample": "AF_MARKER",
                    "assertions": {"status": True, "body_contains": True},
                },
            ),
        ),
        cleanup_status="not_required",
    )
    review = {
        "candidate": candidate,
        "verdict": "confirmed",
        "confidence": "high",
        "reason": "marker reached route-bound response",
        "validation_plans": [plan],
        "legacy_tests": [],
        "route_bound": True,
        "limitations": [],
        "llm_latency_ms": 1,
    }

    result = finalize_candidate_deep_review(
        review,
        [runner_result],
        validation_runner_config=ValidationRunnerConfig(mode="inline"),
    )

    assert result.status == "confirmed"
    assert [entry["type"] for entry in result.request_log] == [
        "llm_deep_review",
        "declarative_validation_plan",
        "declarative_validation_result",
    ]
    assert result.request_log[1]["plan"]["id"] == "plan-injection"
    assert result.request_log[2]["runner"]["mode"] == "inline"
    assert result.request_log[2]["runner"]["configured"] is True
    assert result.request_log[2]["result"]["plan_id"] == "plan-injection"


def test_injection_nonreproduction_requires_a_successful_response_to_the_marker_probe() -> None:
    anchor = CodeAnchor("app.py", 1, 1, "hash")
    candidate = TraceCandidate(
        id="candidate-injection-negative",
        vuln_class="injection",
        source=anchor,
        sink=anchor,
        steps=[],
        sanitizers=[],
        blockers=[],
        confidence="high",
        static_evidence="test",
        verification_hint="test",
        route_id="route-probe",
    )
    plan = normalize_validation_plan(
        {
            "version": 1,
            "id": "plan-injection-negative",
            "candidate_id": candidate.id,
            "steps": [
                {
                    "id": "request-1",
                    "action": "http_request",
                    "method": "GET",
                    "url": "/probe",
                    "query": {"input": "AF_MARKER"},
                    "expected": {"status": 200, "body_contains": "AF_MARKER"},
                }
            ],
            "cleanup": "none",
        }
    )

    def result_for_status(status: int) -> ValidationEvidenceResult:
        return ValidationEvidenceResult(
            plan_id=plan.id,
            candidate_id=candidate.id,
            status="not_reproduced",
            evidence=(
                EvidenceRecord(
                    step_id="request-1",
                    action="http_request",
                    status="failed",
                    summary="marker absent",
                    observed={
                        "method": "GET",
                        "url": "http://127.0.0.1:8080/probe",
                        "status": status,
                        "body_sample": "not found",
                        "assertions": {"status": status == 200, "body_contains": False},
                    },
                ),
            ),
            cleanup_status="not_required",
        )

    assert (
        decide_declarative_status(candidate, "not_reproducible", [plan], [result_for_status(404)], route_bound=True)
        == "needs_manual_review"
    )
    assert (
        decide_declarative_status(candidate, "not_reproducible", [plan], [result_for_status(200)], route_bound=True) == "not_reproducible"
    )
