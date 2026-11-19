from __future__ import annotations

from pathlib import Path

from auditforge.benchmark import evaluate_candidates, load_ground_truth
from auditforge.candidates import build_trace_candidates
from auditforge.graph import build_graph
from auditforge.scanner import scan_repo

ROOT = Path(__file__).resolve().parents[1]


def test_js_typescript_java_go_php_frontends_have_a_machine_readable_baseline() -> None:
    repo = ROOT / "fixtures" / "polyglot_language_vuln_lab"
    _, truth = load_ground_truth(ROOT / "benchmarks" / "polyglot_language_vuln_lab.json")
    facts = scan_repo(repo)
    candidates = build_trace_candidates(facts, build_graph(facts))

    result = evaluate_candidates(truth, candidates)

    assert result["recall"] == 1.0
    assert result["precision"] == 1.0
    frontends = facts.analysis_diagnostics["language_frontends"]
    assert frontends["php-v2"] == 1
    assert sum(frontends.get(name, 0) for name in {"typescript-v1", "typescript-compiler-api"}) == 1
    assert sum(frontends.get(name, 0) for name in {"java-v1", "java-native-ast"}) == 1
    assert sum(frontends.get(name, 0) for name in {"go-v1", "go-native-ast"}) == 1
