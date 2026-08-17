from __future__ import annotations

import argparse
import json
from pathlib import Path

from auditforge.benchmark import evaluate_candidates, load_ground_truth
from auditforge.candidates import build_trace_candidates
from auditforge.graph import build_graph
from auditforge.scanner import scan_repo
from auditforge.semantic_findings import generate_semantic_candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an AuditForge finding-level recall/precision benchmark.")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--min-recall", type=float, default=0.0)
    parser.add_argument("--min-precision", type=float, default=0.0)
    parser.add_argument("--max-duplicates", type=int, default=-1)
    args = parser.parse_args()

    facts = scan_repo(args.repo.resolve())
    candidates = build_trace_candidates(facts, build_graph(facts))
    candidates.extend(generate_semantic_candidates(args.repo.resolve(), facts, candidates))
    metadata, truth = load_ground_truth(args.truth.resolve())
    result = evaluate_candidates(truth, candidates)
    result["benchmark"] = metadata.get("name") or args.truth.stem
    result["repo"] = str(args.repo.resolve())
    print(json.dumps(result, indent=2, ensure_ascii=False))

    failed = result["recall"] < args.min_recall or result["precision"] < args.min_precision
    if args.max_duplicates >= 0 and result["duplicate_candidates"] > args.max_duplicates:
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
