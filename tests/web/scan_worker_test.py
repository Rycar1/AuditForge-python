from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from auditforge import scan_worker, server
from auditforge.logging_config import configure_logging, get_recent_logs, shutdown_logging
from auditforge.scan_worker import (
    cancel_request_path,
    execute_worker_job,
    main,
    read_worker_state,
    scan_job_payload,
    worker_job_path,
    write_worker_job,
)


def test_scan_job_payload_excludes_llm_secrets(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "isolated"
    repo = tmp_path / "repo"
    run_dir.mkdir(parents=True)
    repo.mkdir()
    prepared = {
        "run": {"id": "isolated", "llm_enabled": True},
        "run_id": "isolated",
        "run_dir": run_dir,
        "repo_path": repo,
        "target_url": None,
        "verify": "none",
        "dependency_scan": False,
        "llm_config": SimpleNamespace(api_key="do-not-serialize"),
    }

    payload = scan_job_payload(workspace, prepared)

    assert payload["run_id"] == "isolated"
    assert "api_key" not in json.dumps(payload)
    assert "do-not-serialize" not in json.dumps(payload)


def test_worker_executes_scan_and_persists_terminal_state(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "worker-run"
    repo = tmp_path / "repo"
    run_dir.mkdir(parents=True)
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import request\n\n"
        "def query():\n"
        "    value = request.args.get('q')\n"
        "    return db.execute('select * from users where name=' + value)\n",
        encoding="utf-8",
    )
    job = {
        "workspace": str(workspace),
        "run_dir": str(run_dir),
        "run_id": "worker-run",
        "repo_path": str(repo),
        "target_url": None,
        "verify": "none",
        "use_llm": False,
        "dependency_scan": False,
    }
    job_path = write_worker_job(run_dir, job)

    assert execute_worker_job(job_path) == 0

    state = read_worker_state(run_dir)
    assert state["status"] == "completed"
    assert state["stats"]["files"] == 1
    assert state["project_inventory"]["file_count"] == 1
    assert state["error"] is None
    assert state["failure"] is None


def test_worker_failure_persists_only_safe_structured_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "failed-run"
    repo = tmp_path / "repo"
    run_dir.mkdir(parents=True)
    repo.mkdir()
    job_path = write_worker_job(
        run_dir,
        {
            "workspace": str(workspace),
            "run_dir": str(run_dir),
            "run_id": "failed-run",
            "repo_path": str(repo),
            "target_url": None,
            "verify": "none",
            "use_llm": False,
            "dependency_scan": False,
        },
    )

    def fail_scan(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("provider failed: api_key=worker-super-secret")

    monkeypatch.setattr(scan_worker, "run_scan", fail_scan)

    logger = configure_logging(console=False)
    try:
        assert execute_worker_job(job_path) == 1
        logs = get_recent_logs()
    finally:
        shutdown_logging(logger)

    state = read_worker_state(run_dir)
    serialized = json.dumps(state, ensure_ascii=False)
    assert state["status"] == "failed"
    assert state["error"] == "扫描执行失败。"
    assert state["failure"]["code"] == "SCAN_FAILED"
    assert state["failure"]["stage"] == "scan"
    assert state["failure"]["diagnostic_id"].startswith("AFW-")
    assert state["failure"]["action"]
    assert state["failure"]["retryable"] is False
    assert "RuntimeError" not in serialized
    assert "worker-super-secret" not in serialized
    failure_log = next(item for item in logs if item.get("event") == "worker.failed")
    assert failure_log["diagnostic_id"] == state["failure"]["diagnostic_id"]
    assert "RuntimeError" in failure_log["exception"]


def test_worker_cancellation_persists_structured_failure(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "cancelled-run"
    repo = tmp_path / "repo"
    run_dir.mkdir(parents=True)
    repo.mkdir()
    job_path = write_worker_job(
        run_dir,
        {
            "workspace": str(workspace),
            "run_dir": str(run_dir),
            "run_id": "cancelled-run",
            "repo_path": str(repo),
            "target_url": None,
            "verify": "none",
            "use_llm": False,
            "dependency_scan": False,
        },
    )
    cancel_request_path(run_dir).write_text("{}", encoding="utf-8")

    assert execute_worker_job(job_path) == 2

    state = read_worker_state(run_dir)
    assert state["status"] == "cancelled"
    assert state["error"] == "扫描任务已取消。"
    assert state["failure"]["code"] == "SCAN_CANCELLED"
    assert state["failure"]["stage"] == "starting"
    assert state["failure"]["diagnostic_id"]


def test_worker_main_handles_unreadable_job_at_process_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_job = tmp_path / "missing-job.json"
    monkeypatch.setattr(scan_worker, "configure_logging", lambda **_kwargs: configure_logging(console=False))

    assert main(["--job", str(missing_job)]) == 1

    stderr = capsys.readouterr().err
    assert "错误 [SCAN_FAILED]" in stderr
    assert "诊断编号：AFW-" in stderr
    assert "Traceback" not in stderr
    assert str(missing_job) not in stderr


def test_start_scan_worker_launches_module_worker(monkeypatch, tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    prepared = server.prepare_scan_run(
        workspace,
        {"sourceType": ["path"], "repoPath": [str(repo)]},
        allowed_repo_roots=(tmp_path,),
    )
    captured: dict[str, object] = {}

    class Process:
        pid = 43210

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Process()

    monkeypatch.setattr(server.subprocess, "Popen", fake_popen)

    process = server.start_scan_worker(workspace, prepared)

    assert process.pid == 43210
    assert captured["command"][1:3] == ["-m", "auditforge.scan_worker"]
    assert worker_job_path(Path(prepared["run_dir"])).exists()


def test_start_scan_run_completes_in_an_isolated_worker(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import request\n\ndef query():\n    return db.execute('select * from users where name=' + request.args.get('q'))\n",
        encoding="utf-8",
    )

    run = server.start_scan_run(
        workspace,
        {"sourceType": ["path"], "repoPath": [str(repo)]},
        scan_semaphore=threading.BoundedSemaphore(1),
        max_scan_concurrency=1,
        allowed_repo_roots=(tmp_path,),
    )
    deadline = time.monotonic() + 20
    current = run
    while time.monotonic() < deadline:
        current = next(item for item in server.load_runs(workspace) if item["id"] == run["id"])
        if current["status"] != "running":
            break
        time.sleep(0.1)

    assert current["status"] == "completed"
    assert (workspace / "runs" / run["id"] / "worker_state.json").exists()
