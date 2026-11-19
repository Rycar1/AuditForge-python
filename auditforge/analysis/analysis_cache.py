"""Safe, content-addressed cache for per-file source analysis facts.

The scanner's facts intentionally retain source anchors, so an entry is scoped to
both the repository-relative path and the file content hash.  Entries are JSON
instead of pickles: a damaged or manually modified cache can never execute code
when it is read back.  Cache failures are deliberately non-fatal; scanning the
source is always the authoritative fallback.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from ..core.models import (
    CallSiteFact,
    ClassFact,
    CodeAnchor,
    ControlFlowFact,
    DataFlowFact,
    FunctionFact,
    ImportFact,
    IndexedFile,
    RouteFact,
    SanitizerFact,
    SinkFact,
    SourceFact,
)
from ..core.utils import atomic_write_text, sha256_text

CACHE_SCHEMA_VERSION = 1
# Bump this when scanner extraction semantics change without a facts-model
# schema change.  The dataclass-field signature below handles the latter.
ANALYZER_REVISION = "source-facts-v7"
MAX_CACHE_ENTRY_BYTES = 8 * 1024 * 1024

FACT_SECTIONS: dict[str, type[Any]] = {
    "functions": FunctionFact,
    "classes": ClassFact,
    "routes": RouteFact,
    "sources": SourceFact,
    "sinks": SinkFact,
    "sanitizers": SanitizerFact,
    "call_sites": CallSiteFact,
    "data_flows": DataFlowFact,
    "control_flows": ControlFlowFact,
    "imports": ImportFact,
}


def _fact_schema_signature() -> str:
    schema = {name: [field.name for field in fields(fact_type)] for name, fact_type in sorted(FACT_SECTIONS.items())}
    schema["file"] = [field.name for field in fields(IndexedFile)]
    schema["anchor"] = [field.name for field in fields(CodeAnchor)]
    return sha256_text(json.dumps(schema, sort_keys=True, separators=(",", ":")))


FACT_SCHEMA_SIGNATURE = _fact_schema_signature()


@dataclass(frozen=True)
class CachedFileAnalysis:
    """A validated, source-independent set of facts for one file."""

    file: IndexedFile
    facts: dict[str, list[Any]]
    profile: str


class AnalysisCache:
    """Best-effort cache scoped to a repository and current scanner schema."""

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path.resolve()
        self.enabled = _env_enabled(os.getenv("AUDITFORGE_ANALYSIS_CACHE", "1"))
        self.root = _cache_root_for_repository(self.repo_path)
        self.stats: dict[str, int] = {
            "lookups": 0,
            "hits": 0,
            "misses": 0,
            "writes": 0,
            "read_errors": 0,
            "write_errors": 0,
            "bypassed": 0,
        }

    def has_candidate(self, *, path: str, language: str, content_hash: str | None) -> bool:
        """Return whether an entry path exists without deserialising all facts.

        This is used solely to exclude likely cache hits from Java parser batches.
        ``load`` still fully validates the entry before it can affect a scan.
        """

        entry_path = self._entry_path(path=path, language=language, content_hash=content_hash)
        return bool(self.enabled and entry_path and entry_path.is_file())

    def load(self, *, path: str, language: str, content_hash: str | None) -> CachedFileAnalysis | None:
        if not self.enabled:
            self.stats["bypassed"] += 1
            return None
        entry_path = self._entry_path(path=path, language=language, content_hash=content_hash)
        if entry_path is None:
            self.stats["bypassed"] += 1
            return None
        self.stats["lookups"] += 1
        try:
            if entry_path.stat().st_size > MAX_CACHE_ENTRY_BYTES:
                self.stats["read_errors"] += 1
                self.stats["misses"] += 1
                return None
            raw = entry_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self.stats["misses"] += 1
            return None
        except OSError:
            self.stats["read_errors"] += 1
            self.stats["misses"] += 1
            return None
        try:
            payload = json.loads(raw)
            cached = _cached_from_payload(payload, path=path, language=language, content_hash=content_hash)
        except (TypeError, ValueError, json.JSONDecodeError):
            self.stats["read_errors"] += 1
            self.stats["misses"] += 1
            return None
        self.stats["hits"] += 1
        return cached

    def store(
        self,
        *,
        path: str,
        language: str,
        content_hash: str | None,
        file: IndexedFile,
        facts: dict[str, list[Any]],
        profile: str,
    ) -> None:
        if not self.enabled:
            self.stats["bypassed"] += 1
            return
        if not content_hash or file.parsed_by == "fallback" or file.analysis_error:
            # A fallback can be caused by a temporary parser/toolchain problem.
            # Caching it would silently suppress a later, more complete analysis.
            self.stats["bypassed"] += 1
            return
        entry_path = self._entry_path(path=path, language=language, content_hash=content_hash)
        if entry_path is None:
            self.stats["bypassed"] += 1
            return
        try:
            payload = {
                "schema_version": CACHE_SCHEMA_VERSION,
                "analyzer_revision": ANALYZER_REVISION,
                "fact_schema": FACT_SCHEMA_SIGNATURE,
                "path": path,
                "language": language,
                "content_hash": content_hash,
                "profile": profile,
                "file": file.to_dict(),
                "facts": {name: [item.to_dict() for item in facts.get(name, [])] for name in FACT_SECTIONS},
            }
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            if len(encoded.encode("utf-8", errors="replace")) > MAX_CACHE_ENTRY_BYTES:
                self.stats["bypassed"] += 1
                return
            atomic_write_text(entry_path, encoded)
        except (OSError, TypeError, ValueError):
            self.stats["write_errors"] += 1
            return
        self.stats["writes"] += 1

    def diagnostics(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "schema_version": CACHE_SCHEMA_VERSION,
            "analyzer_revision": ANALYZER_REVISION,
            **self.stats,
        }

    def record_bypass(self) -> None:
        """Record a deliberately ineligible analysis without changing scan flow."""

        self.stats["bypassed"] += 1

    def _entry_path(self, *, path: str, language: str, content_hash: str | None) -> Path | None:
        if not content_hash or len(content_hash) != 64:
            return None
        # Keeping the relative path in the key avoids reusing anchors/identifiers
        # after a rename, where relative imports and framework conventions may
        # change even if bytes are identical.
        identity = f"{CACHE_SCHEMA_VERSION}:{ANALYZER_REVISION}:{language}:{path}:{content_hash}"
        return self.root / f"{sha256_text(identity)}.json"


def _cache_root_for_repository(repo_path: Path) -> Path:
    configured = os.getenv("AUDITFORGE_ANALYSIS_CACHE_DIR", "").strip()
    if configured:
        base = Path(configured).expanduser()
    else:
        local_app_data = os.getenv("LOCALAPPDATA", "").strip()
        xdg_cache = os.getenv("XDG_CACHE_HOME", "").strip()
        if local_app_data:
            base = Path(local_app_data) / "AuditForge" / "analysis-cache"
        elif xdg_cache:
            base = Path(xdg_cache) / "auditforge" / "analysis-cache"
        else:
            base = Path.home() / ".cache" / "auditforge" / "analysis-cache"
    repository_id = sha256_text(str(repo_path).casefold() if os.name == "nt" else str(repo_path))[:32]
    return base / repository_id


def _cached_from_payload(
    payload: Any,
    *,
    path: str,
    language: str,
    content_hash: str | None,
) -> CachedFileAnalysis:
    if not isinstance(payload, dict):
        raise ValueError("cache entry is not an object")
    expected = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "analyzer_revision": ANALYZER_REVISION,
        "fact_schema": FACT_SCHEMA_SIGNATURE,
        "path": path,
        "language": language,
        "content_hash": content_hash,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise ValueError("cache entry identity does not match")
    profile = payload.get("profile")
    if not isinstance(profile, str) or not profile:
        raise ValueError("cache entry has no analysis profile")
    file = _construct_fact(IndexedFile, payload.get("file"))
    if file.path != path or file.language != language or file.parsed_by == "fallback" or file.analysis_error:
        raise ValueError("cache file metadata is invalid")
    raw_facts = payload.get("facts")
    if not isinstance(raw_facts, dict):
        raise ValueError("cache facts are invalid")
    parsed: dict[str, list[Any]] = {}
    for name, fact_type in FACT_SECTIONS.items():
        raw_items = raw_facts.get(name, [])
        if not isinstance(raw_items, list):
            raise ValueError(f"cache facts section {name} is invalid")
        items = [_construct_fact(fact_type, item) for item in raw_items]
        if any(item.anchor.file != path for item in items):
            raise ValueError("cache fact anchor path does not match entry path")
        parsed[name] = items
    return CachedFileAnalysis(file=file, facts=parsed, profile=profile)


def _construct_fact(fact_type: type[Any], value: Any) -> Any:
    if not isinstance(value, dict):
        raise ValueError("cache fact is not an object")
    known_fields = {field.name for field in fields(fact_type)}
    data = {name: item for name, item in value.items() if name in known_fields}
    if "anchor" in known_fields:
        data["anchor"] = _construct_fact(CodeAnchor, data.get("anchor"))
    try:
        return fact_type(**data)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"cache fact could not be constructed: {exc}") from exc


def _env_enabled(value: str) -> bool:
    return value.strip().lower() not in {"0", "false", "no", "off"}
