from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

from ..core.models import ScanResult
from .result_sections import build_result_sections

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  repo_path TEXT NOT NULL,
  target_url TEXT,
  stats_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  name TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY,
  vuln_class TEXT NOT NULL,
  confidence TEXT NOT NULL,
  source_file TEXT NOT NULL,
  source_line INTEGER NOT NULL,
  sink_file TEXT NOT NULL,
  sink_line INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_results (
  candidate_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
"""


# The run-detail view needs these small, user-facing records but never the
# full fact or graph payloads.  Keeping this allow-list close to the store
# prevents a dashboard route from accidentally hydrating a multi-hundred-MB
# graph just to render counters and diagnostics.
DASHBOARD_DETAIL_ARTIFACTS = (
    "analysis_coverage",
    "dependency_diagnostics",
    "dependency_findings",
    "dependency_inventory",
    "llm_diagnostics",
    "project_inventory",
    "result_sections",
)


def write_store(workspace: Path, result: ScanResult) -> Path:
    db_path = workspace / "auditforge.db"
    workspace.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(prefix=".auditforge.", suffix=".db.tmp", dir=workspace, delete=False)
    temporary_path = Path(handle.name)
    handle.close()
    con = sqlite3.connect(temporary_path)
    try:
        con.executescript(SCHEMA)
        con.execute("DELETE FROM scans")
        con.execute("DELETE FROM artifacts")
        con.execute("DELETE FROM candidates")
        con.execute("DELETE FROM verification_results")
        con.execute(
            "INSERT INTO scans (id, repo_path, target_url, stats_json) VALUES (1, ?, ?, ?)",
            (result.repo_path, result.target_url, json.dumps(result.stats())),
        )
        artifacts = {
            "plans": [plan.to_dict() for plan in result.plans],
            "analysis_coverage": result.analysis_coverage,
            "llm_diagnostics": result.llm_diagnostics,
            "dependency_inventory": [manifest.to_dict() for manifest in result.dependency_inventory],
            "dependency_findings": [finding.to_dict() for finding in result.dependency_findings],
            "dependency_diagnostics": result.dependency_diagnostics,
            "project_inventory": result.project_inventory,
            "result_sections": build_result_sections(result),
        }
        for name, payload in artifacts.items():
            con.execute(
                "INSERT INTO artifacts (name, payload_json) VALUES (?, ?)",
                (name, json.dumps(payload, ensure_ascii=False)),
            )
        for candidate in result.candidates:
            con.execute(
                """
                INSERT INTO candidates
                (id, vuln_class, confidence, source_file, source_line, sink_file, sink_line, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate.id,
                    candidate.vuln_class,
                    candidate.confidence,
                    candidate.source.file,
                    candidate.source.start_line,
                    candidate.sink.file,
                    candidate.sink.start_line,
                    json.dumps(candidate.to_dict(), ensure_ascii=False),
                ),
            )
        for verification in result.verification_results:
            con.execute(
                "INSERT INTO verification_results (candidate_id, status, payload_json) VALUES (?, ?, ?)",
                (verification.candidate_id, verification.status, json.dumps(verification.to_dict(), ensure_ascii=False)),
            )
        con.commit()
        con.close()
        os.replace(temporary_path, db_path)
        con = None
    finally:
        if con is not None:
            con.close()
        temporary_path.unlink(missing_ok=True)
    return db_path


def read_dashboard_summary(workspace: Path) -> dict:
    """Read only the lightweight scan row used by run discovery and lists."""

    db_path = workspace / "auditforge.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        scan = con.execute("SELECT * FROM scans WHERE id = 1").fetchone()
        return {"scan": dict(scan) if scan else None}
    finally:
        con.close()


def read_dashboard_detail(workspace: Path) -> dict:
    """Load detail-page evidence without hydrating raw facts or the code graph."""

    return read_dashboard_data(workspace, artifact_names=DASHBOARD_DETAIL_ARTIFACTS)


def read_dashboard_data(workspace: Path, *, artifact_names: tuple[str, ...] | None = None) -> dict:
    """Read stored data, optionally restricting artifact hydration by name.

    ``None`` preserves the legacy/full API behavior.  Dashboard list and
    detail routes should use the dedicated summary/detail readers above so
    large facts and graph JSON remain on disk until explicitly requested.
    """

    db_path = workspace / "auditforge.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        scan = con.execute("SELECT * FROM scans WHERE id = 1").fetchone()
        candidates = con.execute(
            """
            SELECT * FROM candidates
            ORDER BY CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, id ASC
            """
        ).fetchall()
        results = con.execute("SELECT * FROM verification_results ORDER BY candidate_id ASC").fetchall()
        artifacts = _read_artifact_rows(con, artifact_names)
        return {
            "scan": dict(scan) if scan else None,
            "candidates": [dict(row) for row in candidates],
            "verification_results": [dict(row) for row in results],
            "artifacts": {row["name"]: json.loads(row["payload_json"]) for row in artifacts},
        }
    finally:
        con.close()


def _read_artifact_rows(con: sqlite3.Connection, artifact_names: tuple[str, ...] | None) -> list[sqlite3.Row]:
    if artifact_names is None:
        return con.execute("SELECT * FROM artifacts").fetchall()
    if not artifact_names:
        return []
    placeholders = ", ".join("?" for _ in artifact_names)
    return con.execute(f"SELECT * FROM artifacts WHERE name IN ({placeholders})", artifact_names).fetchall()
