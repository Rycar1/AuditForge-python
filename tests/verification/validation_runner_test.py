from __future__ import annotations

import importlib.util
import json
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from auditforge.core.utils import read_json, write_json
from auditforge.verification.validation_dsl import ValidationPlanError, normalize_validation_plan
from auditforge.verification.validation_runner import (
    MAX_RESPONSE_SAMPLE_BYTES,
    RUNNER_TIMEOUT_ENV,
    STALE_PROCESSING_SECONDS,
    ValidationRunnerConfig,
    claim_validation_job,
    ensure_validation_queue,
    execute_validation_plan,
    process_claimed_validation_job,
    queue_runner_status,
    recover_stale_validation_jobs,
    run_validation_worker,
    submit_validation_job,
    wait_for_validation_result,
)


def load_batch_runner_module():
    path = Path(__file__).resolve().parents[2] / "validation" / "batch_vuln_lab_runner.py"
    spec = importlib.util.spec_from_file_location("batch_vuln_lab_runner_test_module", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_batch_validation_separates_runtime_confirmation_and_sandbox_review(tmp_path: Path) -> None:
    batch_runner = load_batch_runner_module()
    old_workspace = batch_runner.WORKSPACE
    batch_runner.WORKSPACE = tmp_path / "workspace"
    try:
        run_dir = batch_runner.WORKSPACE / "runs" / "run-validation"
        run_dir.mkdir(parents=True)
        (run_dir / "code_graph.json").write_text(
            json.dumps(
                {
                    "facts": {
                        "routes": [
                            {"id": "route-fetch", "path": "/fetch"},
                            {"id": "route-deserialize", "path": "/deserialize"},
                        ]
                    }
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        (run_dir / "trace_candidates.json").write_text(
            json.dumps(
                [
                    {"id": "SSRF", "route_id": "route-fetch", "static_evidence": "", "sink": {"symbol": ""}},
                    {"id": "DESER", "route_id": "route-deserialize", "static_evidence": "", "sink": {"symbol": ""}},
                ],
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        (run_dir / "verification_results.json").write_text(
            json.dumps(
                [
                    {"candidate_id": "SSRF", "status": "sandbox_executed"},
                    {"candidate_id": "DESER", "status": "confirmed"},
                    {"candidate_id": "MISSING", "status": "confirmed"},
                    {"candidate_id": "NOPE", "status": "not_reproducible"},
                ],
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        summary = batch_runner.analyze_run({"id": "run-validation", "workspace": "runs/run-validation", "stats": {}})

        assert summary["confirmed"] == 1
        assert summary["runtime_confirmed"] == 1
        assert summary["sandbox_reviewed"] == 1
        assert summary["types"] == ["unsafe_deserialization"]
        assert summary["sandbox_reviewed_types"] == ["ssrf"]
    finally:
        batch_runner.WORKSPACE = old_workspace


@dataclass
class _ServerState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    active_requests: int = 0
    maximum_active_requests: int = 0
    redirect_target_hits: int = 0
    paths: list[str] = field(default_factory=list)


class _RunnerTestServer(ThreadingHTTPServer):
    daemon_threads = True
    state: _ServerState


class _RunnerTestHandler(BaseHTTPRequestHandler):
    server: _RunnerTestServer

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler callback
        state = self.server.state
        with state.lock:
            state.active_requests += 1
            state.maximum_active_requests = max(state.maximum_active_requests, state.active_requests)
            state.paths.append(self.path)
        try:
            path = self.path.split("?", 1)[0]
            if path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/redirect-target")
                self.end_headers()
                return
            if path == "/redirect-target":
                with state.lock:
                    state.redirect_target_hits += 1
                self._send(200, b"redirect target marker")
                return
            if path == "/slow":
                time.sleep(0.25)
                self._send(200, b"AF_MARKER slow")
                return
            if path == "/concurrent":
                time.sleep(0.12)
                self._send(200, b"AF_MARKER concurrent")
                return
            if path == "/large":
                self._send(200, b"AF_MARKER:" + b"x" * (MAX_RESPONSE_SAMPLE_BYTES + 128))
                return
            payload = json.dumps(
                {
                    "message": "AF_MARKER",
                    "nested": {"value": 7},
                    "items": [{"id": 1}, {"id": 2}],
                    "path": self.path,
                }
            ).encode()
            self._send(200, payload, headers={"Content-Type": "application/json", "X-Proof": "yes", "Set-Cookie": "secret=1"})
        finally:
            with state.lock:
                state.active_requests -= 1

    def _send(self, status: int, body: bytes, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - BaseHTTPRequestHandler callback
        return


@dataclass(frozen=True)
class _LiveServer:
    target_url: str
    state: _ServerState


@pytest.fixture
def live_server() -> Iterator[_LiveServer]:
    server = _RunnerTestServer(("127.0.0.1", 0), _RunnerTestHandler)
    server.state = _ServerState()
    thread = threading.Thread(target=server.serve_forever, name="validation-runner-test-http", daemon=True)
    thread.start()
    try:
        yield _LiveServer(target_url=f"http://127.0.0.1:{server.server_port}", state=server.state)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _plan(
    *,
    plan_id: str = "plan-1",
    candidate_id: str = "candidate-1",
    path: str = "/evidence",
    expected: dict[str, Any] | None = None,
    method: str = "GET",
    cleanup: str = "none",
    identity: str | None = None,
) -> dict[str, Any]:
    step: dict[str, Any] = {
        "id": "request-1",
        "action": "http_request",
        "method": method,
        "url": path,
        "expected": expected or {"status": 200, "body_contains": "AF_MARKER"},
    }
    if identity:
        step["identity"] = identity
    if method not in {"GET", "HEAD"}:
        step["body"] = {"marker": "AF_MARKER"}
    return {
        "version": 1,
        "id": plan_id,
        "candidate_id": candidate_id,
        "steps": [step],
        "cleanup": cleanup,
    }


def _wait_until(predicate, *, timeout: float = 4.0) -> bool:  # noqa: ANN001, ANN201 - compact polling helper
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return bool(predicate())


def test_inline_runner_collects_structured_assertion_evidence_and_redacts_secrets(live_server: _LiveServer) -> None:
    plan = _plan(
        expected={
            "status_in": [200, 204],
            "body_contains": "AF_MARKER",
            "body_not_contains": "unexpected-secret",
            "header_equals": {"X-Proof": "yes"},
            "json_contains": {"items": [{"id": 2}]},
            "json_path_equals": {"$.nested.value": 7},
        }
    )

    result = execute_validation_plan(plan, target_url=live_server.target_url)

    assert result.status == "runtime_confirmed"
    assert result.cleanup_status == "not_required"
    assert result.evidence[0].status == "passed"
    observed = result.evidence[0].observed
    assert observed["assertions"] == {
        "status_in": True,
        "body_contains": True,
        "body_not_contains": True,
        "header_equals": True,
        "json_contains": True,
        "json_path_equals": True,
    }
    assert observed["headers"]["x-proof"] == "yes"
    assert "set-cookie" not in observed["headers"]


def test_status_only_assertion_is_not_enough_to_confirm_a_vulnerability(live_server: _LiveServer) -> None:
    result = execute_validation_plan(_plan(expected={"status": 200}), target_url=live_server.target_url)

    assert result.status == "inconclusive"
    assert result.evidence[0].status == "passed"


def test_separate_response_assertion_can_produce_negative_runtime_evidence(live_server: _LiveServer) -> None:
    plan = {
        "version": 1,
        "id": "plan-separated",
        "candidate_id": "candidate-separated",
        "steps": [
            {"id": "request-1", "action": "http_request", "method": "GET", "url": "/evidence"},
            {
                "id": "assert-1",
                "action": "runtime_assert",
                "request_id": "request-1",
                "expected": {"body_contains": "definitely-missing"},
            },
        ],
        "cleanup": "none",
    }

    result = execute_validation_plan(plan, target_url=live_server.target_url)

    assert result.status == "not_reproduced"
    assert [item.status for item in result.evidence] == ["passed", "failed"]


def test_redirect_response_is_observed_without_following_it(live_server: _LiveServer) -> None:
    result = execute_validation_plan(
        _plan(path="/redirect", expected={"status": 302, "header_equals": {"Location": "/redirect-target"}}),
        target_url=live_server.target_url,
    )

    assert result.status == "runtime_confirmed"
    assert result.evidence[0].observed["status"] == 302
    assert live_server.state.redirect_target_hits == 0


def test_http_timeout_becomes_structured_error_evidence(live_server: _LiveServer) -> None:
    plan = _plan(path="/slow")
    plan["steps"][0]["timeout_ms"] = 100

    result = execute_validation_plan(plan, target_url=live_server.target_url)

    assert result.status == "error"
    assert result.evidence[0].status == "error"
    assert "error" in result.evidence[0].observed


def test_response_evidence_is_bounded_and_marks_truncation(live_server: _LiveServer) -> None:
    result = execute_validation_plan(_plan(path="/large"), target_url=live_server.target_url)

    assert result.status == "runtime_confirmed"
    observed = result.evidence[0].observed
    assert observed["response_truncated"] is True
    assert len(observed["body_sample"].encode()) == MAX_RESPONSE_SAMPLE_BYTES


def test_state_changes_and_identity_references_remain_blocked(live_server: _LiveServer) -> None:
    mutating = _plan(method="POST", cleanup="rollback")
    denied = execute_validation_plan(mutating, target_url=live_server.target_url)
    cleanup_unavailable = execute_validation_plan(mutating, target_url=live_server.target_url, allow_state_changes=True)
    identity = execute_validation_plan(_plan(identity="admin"), target_url=live_server.target_url)

    assert denied.status == "blocked"
    assert "不允许状态变更" in denied.notes
    assert cleanup_unavailable.status == "blocked"
    assert "cleanup provider" in cleanup_unavailable.notes
    assert identity.status == "blocked"
    assert "身份凭据" in identity.notes


@pytest.mark.parametrize(
    ("plan", "target_url"),
    [
        (_plan(path="http://evil.example/evidence"), "http://127.0.0.1:8080"),
        (_plan(path="/%2f%2fevil.example/evidence"), "http://127.0.0.1:8080"),
        (_plan(), "http://169.254.169.254"),
    ],
)
def test_runner_revalidates_cross_origin_encoded_authority_and_metadata_boundaries(plan, target_url) -> None:  # noqa: ANN001
    with pytest.raises((ValidationPlanError, ValueError)):
        execute_validation_plan(plan, target_url=target_url)


def test_queue_job_round_trip_returns_typed_evidence(live_server: _LiveServer, tmp_path: Path) -> None:
    queue = tmp_path / "queue"
    plan = normalize_validation_plan(_plan(), target_url=live_server.target_url)
    job_id = submit_validation_job(
        queue,
        plan,
        target_url=live_server.target_url,
        allow_state_changes=False,
        timeout_seconds=5,
    )

    assert run_validation_worker(queue, once=True, poll_interval=0.05) == 1
    result = wait_for_validation_result(queue, job_id, plan=plan, timeout_seconds=5)

    assert result.status == "runtime_confirmed"
    assert not (queue / "completed" / f"{job_id}.json").exists()
    status = queue_runner_status(queue)
    assert status["runner_ready"] is False
    assert status["runner_reason"] == "runner_stopping"


def test_non_once_worker_continues_claiming_jobs_and_executes_them_concurrently(live_server: _LiveServer, tmp_path: Path) -> None:
    queue = tmp_path / "queue"
    job_ids: list[str] = []
    for index in range(5):
        plan = normalize_validation_plan(
            _plan(plan_id=f"plan-{index}", candidate_id=f"candidate-{index}", path=f"/concurrent?job={index}"),
            target_url=live_server.target_url,
        )
        job_ids.append(
            submit_validation_job(
                queue,
                plan,
                target_url=live_server.target_url,
                allow_state_changes=False,
                timeout_seconds=5,
            )
        )

    stop_event = threading.Event()
    processed: list[int] = []
    thread = threading.Thread(
        target=lambda: processed.append(run_validation_worker(queue, concurrency=2, poll_interval=0.05, stop_event=stop_event)),
        name="validation-runner-test-worker",
        daemon=True,
    )
    thread.start()
    try:
        assert _wait_until(lambda: queue_runner_status(queue).get("runner_ready") is True)
        assert _wait_until(lambda: all((queue / "completed" / f"{job_id}.json").exists() for job_id in job_ids))
    finally:
        stop_event.set()
        thread.join(timeout=3)

    assert not thread.is_alive()
    assert processed == [5]
    assert live_server.state.maximum_active_requests >= 2
    assert not list((queue / "pending").glob("*.json"))
    assert queue_runner_status(queue)["runner_reason"] == "runner_stopping"


def test_expired_and_malformed_queue_jobs_fail_closed(live_server: _LiveServer, tmp_path: Path) -> None:
    queue = tmp_path / "queue"
    plan = normalize_validation_plan(_plan(), target_url=live_server.target_url)
    job_id = submit_validation_job(
        queue,
        plan,
        target_url=live_server.target_url,
        allow_state_changes=False,
        timeout_seconds=5,
    )
    pending = queue / "pending" / f"{job_id}.json"
    payload = read_json(pending)
    payload["expires_at"] = time.time() - 1
    payload["unexpected"] = "must be rejected"
    write_json(pending, payload)

    claimed = claim_validation_job(queue)
    assert claimed is not None
    process_claimed_validation_job(queue, claimed)
    result = wait_for_validation_result(queue, job_id, plan=plan, timeout_seconds=5)

    assert result.status == "blocked"
    assert "unknown fields" in result.notes


def test_wait_rejects_result_for_a_different_plan(live_server: _LiveServer, tmp_path: Path) -> None:
    queue = ensure_validation_queue(tmp_path / "queue")
    plan = normalize_validation_plan(_plan(), target_url=live_server.target_url)
    job_id = "a" * 32
    write_json(
        queue / "completed" / f"{job_id}.json",
        {
            "schema_version": 1,
            "job_id": job_id,
            "ok": True,
            "result": {
                "plan_id": "different-plan",
                "candidate_id": plan.candidate_id,
                "status": "runtime_confirmed",
                "cleanup_status": "not_required",
                "evidence": [
                    {
                        "step_id": "request-1",
                        "action": "http_request",
                        "status": "passed",
                        "summary": "forged",
                    }
                ],
            },
        },
    )

    result = wait_for_validation_result(queue, job_id, plan=plan, timeout_seconds=5)

    assert result.status == "blocked"
    assert "identity" in result.notes
    assert not (queue / "completed" / f"{job_id}.json").exists()


def test_stale_processing_jobs_are_recovered(tmp_path: Path, live_server: _LiveServer) -> None:
    queue = tmp_path / "queue"
    plan = normalize_validation_plan(_plan(), target_url=live_server.target_url)
    job_id = submit_validation_job(
        queue,
        plan,
        target_url=live_server.target_url,
        allow_state_changes=False,
        timeout_seconds=5,
    )
    claimed = claim_validation_job(queue)
    assert claimed is not None
    old = time.time() - STALE_PROCESSING_SECONDS - 1
    os.utime(claimed, (old, old))

    assert recover_stale_validation_jobs(queue) == 1
    assert (queue / "pending" / f"{job_id}.json").exists()
    assert not claimed.exists()


def test_runner_configuration_rejects_non_finite_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(RUNNER_TIMEOUT_ENV, "nan")

    with pytest.raises(ValueError, match="finite"):
        ValidationRunnerConfig.from_environment()


def test_queue_api_rejects_ambiguous_state_change_flag_and_unsafe_job_id(live_server: _LiveServer, tmp_path: Path) -> None:
    queue = tmp_path / "queue"
    plan = normalize_validation_plan(_plan(), target_url=live_server.target_url)

    with pytest.raises(ValueError, match="boolean"):
        submit_validation_job(
            queue,
            plan,
            target_url=live_server.target_url,
            allow_state_changes="false",  # type: ignore[arg-type]
            timeout_seconds=5,
        )
    with pytest.raises(ValueError, match="32 lowercase hexadecimal"):
        wait_for_validation_result(queue, "../outside", plan=plan, timeout_seconds=5)


def test_invalid_heartbeat_fails_closed(tmp_path: Path) -> None:
    queue = ensure_validation_queue(tmp_path / "queue")
    write_json(
        queue / "runner-heartbeat.json",
        {
            "observed_at_epoch": time.time(),
            "concurrency": "not-an-integer",
            "active_jobs": 0,
            "stopping": False,
        },
    )

    assert queue_runner_status(queue) == {"runner_ready": False, "runner_reason": "heartbeat_invalid"}


def test_queue_root_symlink_is_rejected_when_supported(tmp_path: Path) -> None:
    real_queue = tmp_path / "real-queue"
    real_queue.mkdir()
    linked_queue = tmp_path / "linked-queue"
    try:
        linked_queue.symlink_to(real_queue, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        ensure_validation_queue(linked_queue)
