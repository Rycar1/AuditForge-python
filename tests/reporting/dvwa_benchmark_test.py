from __future__ import annotations

from pathlib import Path, PurePosixPath

from auditforge.benchmark import load_ground_truth

ROOT = Path(__file__).resolve().parents[1]
REVISION = "d45ba3c4e7efa7f023f25f58ab4af9912c887057"
TAXONOMIES = {
    "command_injection",
    "sql_injection",
    "cross_site_scripting",
    "path_traversal",
    "server_side_request_forgery",
    "authentication_failure",
    "authorization_failure",
}


def test_dvwa_ground_truth_is_pinned_scoped_and_uses_relative_anchors() -> None:
    payload, truth = load_ground_truth(ROOT / "benchmarks" / "dvwa_vuln_lab.json")

    assert payload["target"]["revision"] == REVISION
    assert payload["target"]["source_root"] == "."
    assert set(payload["scope"]["included_taxonomies"]) == TAXONOMIES
    assert payload["scope"]["unsupported_modules"]
    assert len({item.truth_id for item in truth}) == len(truth)

    for item in truth:
        for anchor in (item.source, item.sink):
            path = PurePosixPath(anchor.file)
            assert not path.is_absolute()
            assert ".." not in path.parts
            assert "\\" not in anchor.file
        assert item.line_tolerance in {0, 1, 2}


def test_dvwa_ground_truth_covers_vulnerable_and_impossible_safe_paths() -> None:
    _, truth = load_ground_truth(ROOT / "benchmarks" / "dvwa_vuln_lab.json")

    by_taxonomy = {
        taxonomy: [item for item in truth if item.taxonomy_id == taxonomy]
        for taxonomy in TAXONOMIES
    }
    for findings in by_taxonomy.values():
        assert any(item.expected == "vulnerable" for item in findings)
        assert any(item.expected == "safe" for item in findings)

    impossible_safe = [
        item
        for item in truth
        if item.expected == "safe" and "impossible" in item.source.file.lower()
    ]
    assert {item.taxonomy_id for item in impossible_safe} == TAXONOMIES
