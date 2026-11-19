from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from .utils import normalize_path, sha256_text

if TYPE_CHECKING:
    from .models import CodeAnchor, TraceCandidate


FINDING_FINGERPRINT_VERSION = "v1"


def finding_fingerprint(candidate: TraceCandidate) -> str:
    """Return a line-number-independent identity for a code finding.

    Display IDs are deliberately sequential and may change when a new finding is
    inserted.  This fingerprint is intended for baseline diffs, triage carry-over,
    and deterministic/LLM de-duplication.
    """

    payload = {
        "version": FINDING_FINGERPRINT_VERSION,
        "taxonomy": candidate.taxonomy_id or candidate.vuln_class,
        "vuln_class": candidate.vuln_class,
        "route_scope": str(candidate.route_id or ""),
        "source": _anchor_identity(candidate.source),
        "sink": _anchor_identity(candidate.sink),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"af:{FINDING_FINGERPRINT_VERSION}:{sha256_text(encoded)[:24]}"


def serialized_finding_fingerprint(candidate: dict[str, Any]) -> str:
    existing = str(candidate.get("fingerprint") or "").strip()
    if existing:
        return existing
    payload = {
        "version": FINDING_FINGERPRINT_VERSION,
        "taxonomy": candidate.get("taxonomy_id") or candidate.get("vuln_class") or candidate.get("vulnClass"),
        "vuln_class": candidate.get("vuln_class") or candidate.get("vulnClass"),
        "route_scope": str(candidate.get("route_id") or candidate.get("routeId") or ""),
        "source": _serialized_anchor_identity(candidate.get("source") or {}),
        "sink": _serialized_anchor_identity(candidate.get("sink") or {}),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"af:{FINDING_FINGERPRINT_VERSION}:{sha256_text(encoded)[:24]}"


def _anchor_identity(anchor: CodeAnchor) -> dict[str, str]:
    return {
        "file": normalize_path(anchor.file).lower(),
        "symbol": _normalize_symbol(anchor.symbol),
        "snippet": str(anchor.snippet_hash or "").lower(),
    }


def _serialized_anchor_identity(anchor: dict[str, Any]) -> dict[str, str]:
    return {
        "file": normalize_path(str(anchor.get("file") or "")).lower(),
        "symbol": _normalize_symbol(anchor.get("symbol")),
        "snippet": str(anchor.get("snippet_hash") or anchor.get("snippetHash") or "").lower(),
    }


def _normalize_symbol(value: object) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip().lower()
    return text[:240]
