from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ..core.fingerprints import serialized_finding_fingerprint
from ..core.utils import normalize_path

TruthExpectation = Literal["vulnerable", "safe"]


@dataclass(frozen=True)
class TruthAnchor:
    file: str
    line: int | None = None
    symbol: str | None = None


@dataclass(frozen=True)
class TruthFinding:
    truth_id: str
    expected: TruthExpectation
    taxonomy_id: str | None
    vuln_class: str | None
    source: TruthAnchor
    sink: TruthAnchor
    line_tolerance: int = 0


def load_ground_truth(path: Path) -> tuple[dict[str, Any], list[TruthFinding]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ValueError("ground truth must be an object containing a findings array")
    findings = [_parse_truth_item(item, index) for index, item in enumerate(payload["findings"], start=1)]
    return payload, findings


def evaluate_candidates(
    truth: list[TruthFinding],
    candidates: list[Any],
    *,
    closed_world: bool = True,
) -> dict[str, Any]:
    serialized = [_serialize_candidate(item) for item in candidates]
    matches: dict[str, list[int]] = {item.truth_id: [] for item in truth}
    candidate_vulnerable_matches: dict[int, list[str]] = {index: [] for index in range(len(serialized))}
    candidate_safe_matches: dict[int, list[str]] = {index: [] for index in range(len(serialized))}

    for truth_item in truth:
        for index, candidate in enumerate(serialized):
            if not _matches_truth(truth_item, candidate):
                continue
            matches[truth_item.truth_id].append(index)
            target = candidate_vulnerable_matches if truth_item.expected == "vulnerable" else candidate_safe_matches
            target[index].append(truth_item.truth_id)

    vulnerable = [item for item in truth if item.expected == "vulnerable"]
    safe = [item for item in truth if item.expected == "safe"]
    detected_truth = [item.truth_id for item in vulnerable if matches[item.truth_id]]
    missed_truth = [item.truth_id for item in vulnerable if not matches[item.truth_id]]
    safe_hits = [item.truth_id for item in safe if matches[item.truth_id]]
    true_negatives = [item.truth_id for item in safe if not matches[item.truth_id]]

    false_positive_candidates: list[int] = []
    unmatched_candidates: list[int] = []
    for index in range(len(serialized)):
        if candidate_vulnerable_matches[index]:
            continue
        if candidate_safe_matches[index] or closed_world:
            false_positive_candidates.append(index)
        if not candidate_vulnerable_matches[index] and not candidate_safe_matches[index]:
            unmatched_candidates.append(index)

    duplicate_count = sum(max(0, len(matches[item.truth_id]) - 1) for item in vulnerable)
    tp = len(detected_truth)
    fn = len(missed_truth)
    fp = len(false_positive_candidates)
    tn = len(true_negatives)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "truth": {"vulnerable": len(vulnerable), "safe": len(safe)},
        "candidates": len(serialized),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "duplicate_candidates": duplicate_count,
        "duplicate_rate": round(duplicate_count / len(serialized), 6) if serialized else 0.0,
        "detected_truth_ids": detected_truth,
        "missed_truth_ids": missed_truth,
        "safe_truth_hits": safe_hits,
        "false_positive_candidate_ids": [str(serialized[index].get("id") or "") for index in false_positive_candidates],
        "unmatched_candidate_ids": [str(serialized[index].get("id") or "") for index in unmatched_candidates],
        "candidate_fingerprints": [serialized_finding_fingerprint(item) for item in serialized],
        "matches": {truth_id: [str(serialized[index].get("id") or "") for index in indexes] for truth_id, indexes in matches.items()},
    }


def _parse_truth_item(item: object, index: int) -> TruthFinding:
    if not isinstance(item, dict):
        raise ValueError(f"ground truth finding #{index} must be an object")
    truth_id = str(item.get("truth_id") or "").strip()
    expected = str(item.get("expected") or "").strip().lower()
    if not truth_id:
        raise ValueError(f"ground truth finding #{index} is missing truth_id")
    if expected not in {"vulnerable", "safe"}:
        raise ValueError(f"ground truth {truth_id} has invalid expected value")
    return TruthFinding(
        truth_id=truth_id,
        expected=expected,  # type: ignore[arg-type]
        taxonomy_id=_optional_text(item.get("taxonomy_id")),
        vuln_class=_optional_text(item.get("vuln_class")),
        source=_parse_truth_anchor(item.get("source"), truth_id, "source"),
        sink=_parse_truth_anchor(item.get("sink"), truth_id, "sink"),
        line_tolerance=max(0, int(item.get("line_tolerance") or 0)),
    )


def _parse_truth_anchor(value: object, truth_id: str, role: str) -> TruthAnchor:
    if not isinstance(value, dict) or not str(value.get("file") or "").strip():
        raise ValueError(f"ground truth {truth_id} has invalid {role} anchor")
    raw_line = value.get("line")
    line = int(raw_line) if raw_line is not None else None
    return TruthAnchor(
        file=normalize_path(str(value["file"])),
        line=line,
        symbol=_optional_text(value.get("symbol")),
    )


def _serialize_candidate(candidate: Any) -> dict[str, Any]:
    if isinstance(candidate, dict):
        return candidate
    if hasattr(candidate, "to_dict"):
        payload = candidate.to_dict()
        if isinstance(payload, dict):
            return payload
    raise TypeError(f"unsupported candidate value: {type(candidate).__name__}")


def _matches_truth(truth: TruthFinding, candidate: dict[str, Any]) -> bool:
    taxonomy = str(candidate.get("taxonomy_id") or "")
    vuln_class = str(candidate.get("vuln_class") or candidate.get("vulnClass") or "")
    if truth.taxonomy_id and taxonomy != truth.taxonomy_id:
        return False
    if truth.vuln_class and vuln_class != truth.vuln_class:
        return False
    return _anchor_matches(truth.source, candidate.get("source"), truth.line_tolerance) and _anchor_matches(
        truth.sink, candidate.get("sink"), truth.line_tolerance
    )


def _anchor_matches(truth: TruthAnchor, candidate: object, tolerance: int) -> bool:
    if not isinstance(candidate, dict):
        return False
    if normalize_path(str(candidate.get("file") or "")).lower() != truth.file.lower():
        return False
    if truth.line is not None:
        candidate_line = int(candidate.get("start_line") or candidate.get("startLine") or 0)
        if abs(candidate_line - truth.line) > tolerance:
            return False
    if truth.symbol:
        candidate_symbol = str(candidate.get("symbol") or "").strip().lower()
        if candidate_symbol != truth.symbol.strip().lower():
            return False
    return True


def _optional_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None
