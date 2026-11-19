from __future__ import annotations

from pathlib import Path

from auditforge.analysis.candidates import build_trace_candidates
from auditforge.analysis.graph import build_graph
from auditforge.analysis.scanner import scan_repo
from auditforge.reporting.benchmark import evaluate_candidates, load_ground_truth

ROOT = Path(__file__).resolve().parents[2]


def test_django_drf_framework_benchmark_has_full_recall() -> None:
    repo = ROOT / "fixtures" / "django_drf_vuln_lab"
    _, truth = load_ground_truth(ROOT / "benchmarks" / "django_drf_vuln_lab.json")
    facts = scan_repo(repo)
    candidates = build_trace_candidates(facts, build_graph(facts))

    result = evaluate_candidates(truth, candidates)

    assert result["recall"] == 1.0
    assert result["precision"] == 1.0
