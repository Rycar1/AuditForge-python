"""Isolated worker process for Dashboard-initiated scans.

The HTTP server must stay responsive while a repository scan builds a large
graph or waits on an LLM provider.  This module deliberately has no dependency
on :mod:`auditforge.web.server`: it receives a non-secret job descriptor, writes a
small atomic state file, and executes the normal scan pipeline in its own
process.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..analysis.llm_candidates import LLMConfig
from ..core.logging_config import configure_logging, contextual_logger, get_logger, shutdown_logging
from ..core.settings import llm_config_from_settings, load_workspace_settings, sandbox_concurrency_from_settings
from ..core.user_errors import classify_error, failure_payload, format_cli_error, new_reference, user_error
from ..core.utils import atomic_write_text
from ..engine import run_scan

WORKER_STATE_FILE = "worker_state.json"
WORKER_JOB_FILE = "scan_job.json"
CANCEL_REQUEST_FILE = "cancel_requested.json"
WORKER_SCHEMA_VERSION = 1
LOGGER = get_logger("scan_worker")


class ScanCancelled(RuntimeError):
    """Raised when the Dashboard has requested graceful worker cancellation."""


def worker_state_path(run_dir: Path) -> Path:
    return run_dir / WORKER_STATE_FILE


def worker_job_path(run_dir: Path) -> Path:
    return run_dir / WORKER_JOB_FILE


def cancel_request_path(run_dir: Path) -> Path:
    return run_dir / CANCEL_REQUEST_FILE


def read_worker_state(run_dir: Path) -> dict[str, Any]:
    try:
        payload = json.loads(worker_state_path(run_dir).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_worker_state(run_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    state = dict(payload)
    state["schema_version"] = WORKER_SCHEMA_VERSION
    state["updated_at"] = datetime.now(UTC).isoformat()
    serialized = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
    for attempt in range(5):
        try:
            atomic_write_text(worker_state_path(run_dir), serialized)
            break
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.02 * (attempt + 1))
    return state


def write_worker_job(run_dir: Path, payload: dict[str, Any]) -> Path:
    job = dict(payload)
    job["schema_version"] = WORKER_SCHEMA_VERSION
    atomic_write_text(worker_job_path(run_dir), json.dumps(job, ensure_ascii=False, separators=(",", ":")))
    return worker_job_path(run_dir)


def scan_job_payload(workspace: Path, prepared: dict[str, Any]) -> dict[str, Any]:
    """Serialize only launch parameters; secrets remain in the local secret store."""

    run = prepared["run"]
    return {
        "workspace": str(workspace.resolve()),
        "run_dir": str(Path(prepared["run_dir"]).resolve()),
        "run_id": str(prepared["run_id"]),
        "repo_path": str(Path(prepared["repo_path"]).resolve()),
        "target_url": prepared.get("target_url"),
        "verify": str(prepared.get("verify") or "none"),
        "use_llm": bool(run.get("llm_enabled")),
        "dependency_scan": bool(prepared.get("dependency_scan")),
    }


def execute_worker_job(job_path: Path) -> int:
    job = read_worker_job(job_path)
    workspace = Path(str(job.get("workspace") or "")).resolve()
    run_dir = Path(str(job.get("run_dir") or "")).resolve()
    run_id = str(job.get("run_id") or "")
    if not workspace.is_dir() or not run_dir.is_dir() or not run_id:
        raise ValueError("invalid scan worker job")
    try:
        run_dir.relative_to((workspace / "runs").resolve())
    except ValueError as exc:
        raise ValueError("scan worker run directory is outside the workspace") from exc

    started_at = datetime.now(UTC).isoformat()
    existing = read_worker_state(run_dir)
    worker_logger = contextual_logger(LOGGER, component="scan-worker", workspace=str(workspace), run_id=run_id)
    if cancel_request_path(run_dir).exists():
        public_error = user_error("SCAN_CANCELLED")
        write_worker_state(
            run_dir,
            {
                **existing,
                "run_id": run_id,
                "pid": os.getpid(),
                "status": "cancelled",
                "completed_at": started_at,
                "error": public_error.message,
                "failure": failure_payload(public_error, stage="starting"),
            },
        )
        worker_logger.info(
            "scan cancelled before worker startup",
            extra={"event": "scan.cancelled", "diagnostic_id": public_error.reference, "stage": "starting"},
        )
        return 2
    write_worker_state(
        run_dir,
        {
            **existing,
            "run_id": run_id,
            "pid": os.getpid(),
            "status": "running",
            "started_at": existing.get("started_at") or started_at,
            "progress": existing.get("progress") or {},
            "error": None,
            "failure": None,
        },
    )

    verify = str(job.get("verify") or "none")
    dependency_scan = bool(job.get("dependency_scan"))
    use_llm = bool(job.get("use_llm"))
    current_stage = "configuration"
    try:
        settings = load_workspace_settings(workspace) if use_llm or dependency_scan or "deep" in verify else {}
        taint_config = _enabled_profile(settings, "taint") if use_llm else LLMConfig(enabled=False)
        deep_config = _enabled_profile(settings, "deep") if "deep" in verify else LLMConfig(enabled=False)
        dependency_config = _enabled_profile(settings, "dependency") if dependency_scan else LLMConfig(enabled=False)
        sandbox_concurrency = sandbox_concurrency_from_settings(settings, deep_config.concurrency)

        def progress(stage: str, percent: int, message: str) -> None:
            nonlocal current_stage
            current_stage = str(stage or "scan")[:80]
            if cancel_request_path(run_dir).exists():
                raise ScanCancelled("scan cancellation requested")
            current = read_worker_state(run_dir)
            write_worker_state(
                run_dir,
                {
                    **current,
                    "run_id": run_id,
                    "pid": os.getpid(),
                    "status": "running",
                    "started_at": current.get("started_at") or started_at,
                    "progress": {"stage": stage, "percent": max(0, min(100, int(percent))), "detail": str(message)[:2000]},
                    "error": None,
                    "failure": None,
                },
            )

        current_stage = "scan"
        result = run_scan(
            Path(str(job["repo_path"])),
            run_dir,
            target_url=str(job.get("target_url") or "") or None,
            verify=verify,
            llm_config=taint_config,
            deep_llm_config=deep_config,
            dependency_scan=dependency_scan,
            dependency_llm_config=dependency_config,
            sandbox_concurrency=sandbox_concurrency,
            progress_callback=progress,
        )
    except ScanCancelled:
        public_error = user_error("SCAN_CANCELLED")
        write_worker_state(
            run_dir,
            {
                **read_worker_state(run_dir),
                "run_id": run_id,
                "pid": os.getpid(),
                "status": "cancelled",
                "completed_at": datetime.now(UTC).isoformat(),
                "error": public_error.message,
                "failure": failure_payload(public_error, stage=current_stage),
            },
        )
        worker_logger.info(
            "scan cancelled",
            extra={"event": "scan.cancelled", "diagnostic_id": public_error.reference, "stage": current_stage},
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - parent turns this into a visible run failure
        reference = new_reference("AFW")
        public_error = classify_error(exc, context="worker", reference=reference)
        worker_logger.exception(
            "scan worker failed",
            extra={
                "event": "worker.failed",
                "diagnostic_id": reference,
                "error_type": type(exc).__name__,
                "stage": current_stage,
            },
        )
        write_worker_state(
            run_dir,
            {
                **read_worker_state(run_dir),
                "run_id": run_id,
                "pid": os.getpid(),
                "status": "failed",
                "completed_at": datetime.now(UTC).isoformat(),
                "error": public_error.message,
                "failure": failure_payload(public_error, stage=current_stage),
            },
        )
        return 1

    write_worker_state(
        run_dir,
        {
            **read_worker_state(run_dir),
            "run_id": run_id,
            "pid": os.getpid(),
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
            "stats": result.stats(),
            "project_inventory": result.project_inventory,
            "error": None,
            "failure": None,
        },
    )
    return 0


def read_worker_job(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("scan worker job cannot be read") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != WORKER_SCHEMA_VERSION:
        raise ValueError("scan worker job has an unsupported schema")
    return payload


def _enabled_profile(settings: dict[str, Any], profile: str) -> LLMConfig:
    configured = llm_config_from_settings(settings, profile=profile)
    return replace(configured, enabled=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="auditforge-scan-worker")
    parser.add_argument("--job", required=True)
    args = parser.parse_args(argv)
    job_path = Path(args.job).resolve()
    configured_logger = None
    try:
        configured_logger = configure_logging()
        return execute_worker_job(job_path)
    except Exception as exc:  # noqa: BLE001 - last-resort worker process boundary
        reference = new_reference("AFW")
        contextual_logger(LOGGER, component="scan-worker", job=str(job_path)).exception(
            "scan worker could not start job",
            extra={
                "event": "worker.job_invalid",
                "diagnostic_id": reference,
                "error_type": type(exc).__name__,
                "stage": "starting",
            },
        )
        public_error = classify_error(exc, context="scan_worker", reference=reference)
        print(format_cli_error(public_error), file=sys.stderr)
        return 1
    finally:
        if configured_logger is not None:
            shutdown_logging(configured_logger)


if __name__ == "__main__":  # pragma: no cover - exercised through the spawned subprocess
    raise SystemExit(main(sys.argv[1:]))
