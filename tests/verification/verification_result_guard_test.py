from __future__ import annotations

from auditforge.core.models import VerificationResult
from auditforge.engine import parse_verification_modes, protect_unsubstantiated_negative
from auditforge.reporting.result_sections import section_id_for_verification


def test_transport_failure_is_not_treated_as_not_reproduced() -> None:
    result = VerificationResult(
        candidate_id="candidate-1",
        status="not_reproducible",
        evidence=["route unreachable"],
        request_log=[
            {
                "method": "GET",
                "url": "http://127.0.0.1:1/test",
                "status": None,
                "error": "connection refused",
            }
        ],
    )

    protected = protect_unsubstantiated_negative(result)

    assert protected.status == "needs_manual_review"
    assert section_id_for_verification(result) == "candidate_vulnerabilities"


def test_concrete_http_negative_evidence_may_be_archived() -> None:
    result = VerificationResult(
        candidate_id="candidate-1",
        status="not_reproducible",
        evidence=["marker absent"],
        request_log=[
            {
                "method": "GET",
                "url": "http://127.0.0.1/test",
                "status": 200,
                "error": None,
            }
        ],
    )

    assert protect_unsubstantiated_negative(result) is result
    assert section_id_for_verification(result) == "archived_results"


def test_safe_and_deep_modes_are_composable() -> None:
    assert parse_verification_modes("safe+deep") == {"safe", "deep"}
    assert parse_verification_modes("stateful_deep") == {"stateful", "deep"}
    assert parse_verification_modes("combined") == {"safe", "deep"}
