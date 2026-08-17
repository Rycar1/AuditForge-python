from __future__ import annotations

from pathlib import Path

from auditforge.engine import run_scan


def test_deliberately_vulnerable_service_is_detected_end_to_end(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "e2e_vulnerable_service"

    result = run_scan(repo, tmp_path, None, "none")

    assert {
        "sql_injection",
        "cross_site_scripting",
        "server_side_request_forgery",
        "path_traversal",
        "command_injection",
        "authorization_failure",
    } <= {candidate.taxonomy_id for candidate in result.candidates}
    assert not [item for item in result.verification_results if item.status == "confirmed"]
