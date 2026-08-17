from __future__ import annotations

from pathlib import Path

from auditforge.benchmark import evaluate_candidates, load_ground_truth
from auditforge.candidates import build_trace_candidates
from auditforge.graph import build_graph
from auditforge.scanner import scan_repo

ROOT = Path(__file__).resolve().parents[1]


def test_django_drf_framework_benchmark_has_full_recall() -> None:
    repo = ROOT / "fixtures" / "django_drf_vuln_lab"
    _, truth = load_ground_truth(ROOT / "benchmarks" / "django_drf_vuln_lab.json")
    facts = scan_repo(repo)
    candidates = build_trace_candidates(facts, build_graph(facts))

    result = evaluate_candidates(truth, candidates)

    assert result["recall"] == 1.0
    assert result["precision"] == 1.0
