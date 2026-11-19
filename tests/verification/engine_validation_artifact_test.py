from __future__ import annotations

from auditforge.core.models import VerificationResult
from auditforge.engine import extract_validation_runner_plans


def test_extract_validation_runner_plans_keeps_only_normalized_plan_records() -> None:
    plan = {
        "schema_version": 1,
        "id": "plan-1",
        "candidate_id": "CAND-1",
        "name": "marker reflection",
        "steps": [],
        "cleanup": {"strategy": "none"},
    }
    results = [
        VerificationResult(
            candidate_id="CAND-1",
            status="needs_manual_review",
            evidence=[],
            request_log=[
                {"type": "declarative_validation_plan", "plan": plan},
                {"type": "declarative_validation_plan", **plan},
                {"type": "declarative_validation_result", "result": {"status": "inconclusive"}},
                {"type": "sandbox_python", "code": "legacy"},
            ],
        )
    ]

    assert extract_validation_runner_plans(results) == [plan]
