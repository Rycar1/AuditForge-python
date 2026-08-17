from __future__ import annotations

import pytest

from auditforge.validation_dsl import (
    MAX_BODY_BYTES,
    MAX_HEADERS,
    MAX_STEPS,
    EvidenceRecord,
    ValidationEvidenceResult,
    ValidationPlan,
    ValidationPlanError,
    normalize_validation_plan,
)


def read_only_plan(**overrides):  # noqa: ANN003, ANN201 - compact test fixture builder
    payload = {
        "version": 1,
        "id": "plan-1",
        "candidate_id": "candidate-1",
        "steps": [
            {
                "id": "request-1",
                "action": "http_request",
                "method": "get",
                "url": "/api/users?id=2",
                "headers": {"Accept": "application/json"},
                "expected": {"status": 200, "body_contains": "user-2"},
            }
        ],
        "cleanup": "none",
    }
    payload.update(overrides)
    return payload


def test_plan_normalizes_and_round_trips() -> None:
    plan = normalize_validation_plan(read_only_plan())

    assert isinstance(plan, ValidationPlan)
    assert plan.version == 1
    assert plan.steps[0].method == "GET"
    assert plan.steps[0].type == "http_request"
    assert plan.steps[0].action == "http_request"
    assert plan.steps[0].is_executable is True
    assert plan.cleanup.strategy == "none"

    restored = ValidationPlan.from_dict(plan.to_dict())
    assert restored == plan


def test_response_assertion_can_cover_a_preceding_request() -> None:
    plan = normalize_validation_plan(
        {
            "version": 1,
            "id": "plan-separated-assertion",
            "candidateId": "candidate-1",
            "steps": [
                {
                    "id": "request-1",
                    "type": "http_request",
                    "method": "GET",
                    "url": "/health",
                },
                {
                    "id": "assert-1",
                    "type": "assert_response",
                    "expected": {"status_in": [200, 204]},
                },
            ],
            "cleanup": {"strategy": "none", "always": True},
        }
    )

    assertion = plan.steps[1]
    assert assertion.action == "runtime_assert"
    assert assertion.request_id == "request-1"


@pytest.mark.parametrize(
    ("url", "target_url"),
    [
        ("https://evil.example/api", "https://app.example"),
        ("//evil.example/api", "https://app.example"),
        ("/%2f%2fevil.example/api", "https://app.example"),
        ("http://169.254.169.254/latest/meta-data", "http://169.254.169.254"),
        ("http://[fe80::1]/", "http://[fe80::1]"),
        ("http://metadata.google.internal/computeMetadata/v1", "http://metadata.google.internal"),
    ],
)
def test_url_policy_rejects_cross_origin_metadata_and_link_local(url: str, target_url: str) -> None:
    payload = read_only_plan()
    payload["steps"][0]["url"] = url

    with pytest.raises(ValidationPlanError):
        normalize_validation_plan(payload, target_url=target_url)


def test_absolute_url_is_allowed_only_for_controlled_origin() -> None:
    payload = read_only_plan()
    payload["steps"][0]["url"] = "https://app.example:443/api/users"

    plan = normalize_validation_plan(payload, target_url="https://app.example/base")
    assert plan.steps[0].url == "https://app.example:443/api/users"

    with pytest.raises(ValidationPlanError, match="target_url"):
        normalize_validation_plan(payload)


def test_actions_methods_and_assertions_are_allowlisted() -> None:
    payload = read_only_plan()
    payload["steps"][0]["action"] = "shell"
    with pytest.raises(ValidationPlanError, match="unsupported action"):
        normalize_validation_plan(payload)

    payload = read_only_plan()
    payload["steps"][0]["method"] = "TRACE"
    with pytest.raises(ValidationPlanError, match="HTTP method"):
        normalize_validation_plan(payload)

    payload = read_only_plan()
    payload["steps"][0]["expected"] = {"python_expression": "__import__('os')"}
    with pytest.raises(ValidationPlanError, match="unsupported assertions"):
        normalize_validation_plan(payload)

    payload = read_only_plan()
    payload["steps"][0]["expected"] = {}
    with pytest.raises(ValidationPlanError, match="expected"):
        normalize_validation_plan(payload)


def test_state_changing_requests_require_always_cleanup() -> None:
    payload = read_only_plan()
    payload["steps"][0].update({"method": "POST", "body": {"name": "AF_TEST"}})

    with pytest.raises(ValidationPlanError, match="cleanup strategy"):
        normalize_validation_plan(payload)

    payload["cleanup"] = {"strategy": "rollback", "always": False}
    with pytest.raises(ValidationPlanError, match="cleanup must run"):
        normalize_validation_plan(payload)

    payload["cleanup"] = "rollback"
    plan = normalize_validation_plan(payload)
    assert plan.cleanup.strategy == "rollback"
    assert plan.cleanup.always is True


@pytest.mark.parametrize(
    ("location", "value"),
    [
        ("query", "http://169.254.1.2/latest"),
        ("query", "http://0251.0376.0251.0376/latest"),
        ("body", "100.100.100.200"),
        ("body", "fe80::1"),
        ("body", "http%3A%2F%2Fmetadata.google.internal%2FcomputeMetadata%2Fv1"),
    ],
)
def test_metadata_and_link_local_references_are_blocked_inside_inputs(location: str, value: str) -> None:
    payload = read_only_plan()
    step = payload["steps"][0]
    step["method"] = "POST"
    step[location] = {"target": value}
    payload["cleanup"] = "rollback"

    with pytest.raises(ValidationPlanError, match="metadata|link-local"):
        normalize_validation_plan(payload)


def test_headers_bodies_and_step_counts_are_bounded() -> None:
    payload = read_only_plan()
    payload["steps"][0]["headers"] = {f"X-Test-{index}": "x" for index in range(MAX_HEADERS + 1)}
    with pytest.raises(ValidationPlanError, match="headers"):
        normalize_validation_plan(payload)

    payload = read_only_plan()
    payload["steps"][0]["headers"] = {"Host": "metadata.google.internal"}
    with pytest.raises(ValidationPlanError, match="controlled by the runner"):
        normalize_validation_plan(payload)

    payload = read_only_plan()
    payload["steps"][0].update({"method": "POST", "body": {"value": "x" * (MAX_BODY_BYTES + 1)}})
    payload["cleanup"] = "rollback"
    with pytest.raises(ValidationPlanError, match="body"):
        normalize_validation_plan(payload)

    step = read_only_plan()["steps"][0]
    payload = read_only_plan(steps=[{**step, "id": f"step-{index}"} for index in range(MAX_STEPS + 1)])
    with pytest.raises(ValidationPlanError, match="at most"):
        normalize_validation_plan(payload)


@pytest.mark.parametrize(
    ("action", "expected", "extra", "step_type"),
    [
        ("oast_probe", {"interaction_received": True}, {"channel": "dns"}, "oast_placeholder"),
        ("browser_assert", {"visible": True}, {"url": "/account", "selector": "#account"}, "playwright_placeholder"),
    ],
)
def test_unavailable_actions_are_explicit_unsupported_placeholders(action, expected, extra, step_type) -> None:  # noqa: ANN001
    payload = read_only_plan(
        steps=[
            {
                "id": "placeholder-1",
                "action": action,
                "expected": expected,
                **extra,
            }
        ]
    )

    plan = normalize_validation_plan(payload)
    step = plan.steps[0]
    assert step.type == step_type
    assert step.execution_status == "unsupported"
    assert step.is_executable is False
    assert step.blocked_reason
    assert EvidenceRecord.unsupported_step(step).status == "unsupported"

    payload["steps"][0]["supported"] = True
    with pytest.raises(ValidationPlanError, match="contradicts"):
        normalize_validation_plan(payload)


def test_evidence_models_round_trip_and_prevent_placeholder_success() -> None:
    result = ValidationEvidenceResult.from_dict(
        {
            "plan_id": "plan-1",
            "candidate_id": "candidate-1",
            "status": "runtime_confirmed",
            "cleanup_status": "not_required",
            "evidence": [
                {
                    "step_id": "request-1",
                    "action": "http_request",
                    "status": "passed",
                    "summary": "Received the expected marker.",
                    "observed": {"status": 200, "body_contains": True},
                    "elapsed_ms": 12,
                    "artifacts": ["response/request-1.json"],
                }
            ],
        }
    )

    assert ValidationEvidenceResult.from_dict(result.to_dict()) == result

    with pytest.raises(ValidationPlanError, match="placeholder evidence"):
        EvidenceRecord.from_dict(
            {
                "step_id": "oast-1",
                "type": "oast_placeholder",
                "status": "passed",
                "summary": "Must not claim unsupported execution.",
            }
        )

    with pytest.raises(ValidationPlanError, match="every evidence record"):
        ValidationEvidenceResult.from_dict(
            {
                "plan_id": "plan-1",
                "candidate_id": "candidate-1",
                "status": "runtime_confirmed",
                "evidence": [
                    {
                        "step_id": "request-1",
                        "action": "http_request",
                        "status": "failed",
                        "summary": "Assertion failed.",
                    }
                ],
            }
        )
