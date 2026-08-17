from __future__ import annotations

import json
import re
from pathlib import Path

from auditforge.benchmark import TruthAnchor, TruthFinding, evaluate_candidates, load_ground_truth
from auditforge.candidates import build_trace_candidates
from auditforge.fingerprints import finding_fingerprint
from auditforge.graph import build_graph
from auditforge.models import CodeAnchor, TraceCandidate
from auditforge.scanner import scan_repo
from auditforge.semantic_findings import generate_semantic_candidates

ROOT = Path(__file__).resolve().parents[1]


def make_candidate(source_line: int = 10, sink_line: int = 20) -> TraceCandidate:
    return TraceCandidate(
        id="INJECTION-TRACE-001",
        vuln_class="injection",
        source=CodeAnchor("app.py", source_line, source_line, "source-snippet", "request.args.get('q')"),
        sink=CodeAnchor("app.py", sink_line, sink_line, "sink-snippet", "db.execute"),
        steps=[],
        sanitizers=[],
        blockers=[],
        confidence="high",
        static_evidence="test",
        verification_hint="test",
        taxonomy_id="sql_injection",
    )


def test_fingerprint_is_stable_when_only_line_numbers_move() -> None:
    first = make_candidate(10, 20)
    moved = make_candidate(110, 220)

    assert finding_fingerprint(first) == finding_fingerprint(moved)
    assert first.to_dict()["fingerprint"].startswith("af:v1:")


def test_benchmark_reports_tp_fp_fn_and_duplicates() -> None:
    truth = [
        TruthFinding(
            "VULN-1",
            "vulnerable",
            "sql_injection",
            "injection",
            TruthAnchor("app.py", 10),
            TruthAnchor("app.py", 20),
        ),
        TruthFinding(
            "MISSED-1",
            "vulnerable",
            "path_traversal",
            "injection",
            TruthAnchor("app.py", 30),
            TruthAnchor("app.py", 40),
        ),
        TruthFinding(
            "SAFE-1",
            "safe",
            "sql_injection",
            "injection",
            TruthAnchor("safe.py", 10),
            TruthAnchor("safe.py", 20),
        ),
    ]
    duplicate = make_candidate()
    unrelated = make_candidate()
    unrelated = TraceCandidate(**{**unrelated.__dict__, "id": "UNMATCHED", "source": CodeAnchor("other.py", 1, 1, "x", "x")})

    result = evaluate_candidates(truth, [make_candidate(), duplicate, unrelated])

    assert (result["tp"], result["fp"], result["fn"], result["tn"]) == (1, 1, 1, 1)
    assert result["duplicate_candidates"] == 1
    assert result["missed_truth_ids"] == ["MISSED-1"]


def test_python_fixture_has_machine_readable_recall_baseline() -> None:
    repo = ROOT / "fixtures" / "python_vuln_lab"
    _, truth = load_ground_truth(ROOT / "benchmarks" / "python_vuln_lab.json")
    facts = scan_repo(repo)
    candidates = build_trace_candidates(facts, build_graph(facts))
    candidates.extend(generate_semantic_candidates(repo, facts, candidates))

    result = evaluate_candidates(truth, candidates)

    assert result["recall"] >= 0.85
    assert result["precision"] >= 0.75


def test_public_target_corpus_catalog_uses_pinned_sources() -> None:
    payload = json.loads((ROOT / "benchmarks" / "public_target_corpus.json").read_text(encoding="utf-8"))

    assert payload["schema_version"] == 1
    assert "Do not install dependencies" in payload["safety"]
    assert {entry["id"] for entry in payload["entries"]} >= {"owasp-nodegoat", "dvwa"}
    for entry in payload["entries"]:
        assert entry["source_url"].startswith("https://github.com/")
        assert re.fullmatch(r"[0-9a-f]{40}", entry["revision"])
        assert entry["observed_static_candidates"]
