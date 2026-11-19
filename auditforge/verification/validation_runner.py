"""Independent executor and filesystem queue for declarative validation plans.

The dashboard process only writes validated jobs to a narrow shared queue.  A
separate ``auditforge validation-runner`` process executes bounded HTTP plans
and returns structured evidence.  No source tree, Docker socket, shell command
or executable LLM output crosses this boundary.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .utils import read_json, write_json
from .validation_dsl import (
    DeclarativeValidationPlan,
    EvidenceRecord,
    ValidationEvidenceResult,
    ValidationPlanError,
    ValidationStep,
    normalize_validation_plan,
)
from .verification import validate_request_url, validate_target_url

RUNNER_MODE_ENV = "AUDITFORGE_VALIDATION_RUNNER_MODE"
QUEUE_PATH_ENV = "AUDITFORGE_VALIDATION_QUEUE"
RUNNER_TIMEOUT_ENV = "AUDITFORGE_VALIDATION_TIMEOUT"
RUNNER_ID_ENV = "AUDITFORGE_VALIDATION_RUNNER_ID"

RUNNER_MODES = {"disabled", "inline", "queue"}
QUEUE_DIRECTORIES = ("pending", "processing", "completed", "failed")
MAX_QUEUE_DOCUMENT_BYTES = 512 * 1024
MAX_RESPONSE_SAMPLE_BYTES = 32 * 1024
MAX_RESPONSE_HEADERS = 64
MAX_RESPONSE_HEADER_BYTES = 16 * 1024
DEFAULT_RESULT_TIMEOUT_SECONDS = 90.0
MAX_RESULT_TIMEOUT_SECONDS = 600.0
HEARTBEAT_MAX_AGE_SECONDS = 15.0
STALE_PROCESSING_SECONDS = 600.0


@dataclass(frozen=True, slots=True)
class ValidationRunnerConfig:
    mode: str = "disabled"
    queue_path: Path | None = None
    result_timeout_seconds: float = DEFAULT_RESULT_TIMEOUT_SECONDS

    @classmethod
    def from_environment(cls) -> ValidationRunnerConfig:
        raw_queue = os.getenv(QUEUE_PATH_ENV, "").strip()
        raw_mode = os.getenv(RUNNER_MODE_ENV, "").strip().lower()
        mode = raw_mode or ("queue" if raw_queue else "disabled")
        if mode not in RUNNER_MODES:
            raise ValueError(f"{RUNNER_MODE_ENV} must be one of: {', '.join(sorted(RUNNER_MODES))}")
        queue_path = Path(os.path.abspath(Path(raw_queue).expanduser())) if raw_queue else None
        if mode == "queue" and queue_path is None:
            raise ValueError(f"{QUEUE_PATH_ENV} is required when {RUNNER_MODE_ENV}=queue")
        raw_timeout = os.getenv(RUNNER_TIMEOUT_ENV, str(DEFAULT_RESULT_TIMEOUT_SECONDS)).strip()
        try:
            timeout = float(raw_timeout)
        except ValueError as exc:
            raise ValueError(f"{RUNNER_TIMEOUT_ENV} must be numeric") from exc
        timeout = _bounded_result_timeout(timeout)
        return cls(mode=mode, queue_path=queue_path, result_timeout_seconds=timeout)

    def public_diagnostics(self) -> dict[str, Any]:
        diagnostics: dict[str, Any] = {
            "mode": self.mode,
            "configured": self.mode != "disabled",
            "result_timeout_seconds": self.result_timeout_seconds,
        }
        if self.mode == "queue" and self.queue_path is not None:
            diagnostics.update(queue_runner_status(self.queue_path))
        return diagnostics


@dataclass(frozen=True, slots=True)
class HttpResponseSnapshot:
    request_id: str
    method: str
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    truncated: bool

    def observed(self, assertions: dict[str, Any] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "headers": _public_response_headers(self.headers),
            "body_sample": self.body,
            "response_truncated": self.truncated,
        }
        if assertions is not None:
            payload["assertions"] = assertions
        return payload


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201 - urllib override
        return None


def execute_validation_plan(
    plan: DeclarativeValidationPlan | dict[str, Any],
    *,
    target_url: str,
    allow_state_changes: bool = False,
) -> ValidationEvidenceResult:
    """Execute one validated plan without evaluating arbitrary code."""

    normalized = normalize_validation_plan(_plan_payload(plan), target_url=target_url)
    controlled_target = validate_target_url(target_url)
    mutating = [step for step in normalized.steps if step.type == "http_request" and step.method not in {"GET", "HEAD"}]
    if mutating and not allow_state_changes:
        return _blocked_result(normalized, mutating[0], "当前扫描模式不允许状态变更请求。")
    if mutating:
        return _blocked_result(normalized, mutating[0], "独立 runner 尚未配置可信 cleanup provider，已拒绝状态变更计划。")
    identified = [step for step in normalized.steps if step.identity]
    if identified:
        return _blocked_result(normalized, identified[0], "独立 runner 尚未配置身份凭据提供器，无法执行 identity 引用。")

    evidence: list[EvidenceRecord] = []
    responses: dict[str, HttpResponseSnapshot] = {}
    meaningful_assertion_passed = False
    for step in normalized.steps:
        if not step.is_executable:
            evidence.append(EvidenceRecord.unsupported_step(step))
            continue
        if step.type == "http_request":
            record, snapshot, meaningful = _execute_http_step(step, controlled_target)
            evidence.append(record)
            if snapshot is not None:
                responses[step.id] = snapshot
            meaningful_assertion_passed = meaningful_assertion_passed or meaningful
            continue
        if step.type == "assert_response":
            snapshot = responses.get(step.request_id or "")
            if snapshot is None:
                evidence.append(
                    EvidenceRecord(
                        step_id=step.id,
                        action=step.action,
                        status="blocked",
                        summary="断言引用的 HTTP 响应不存在。",
                        observed={"request_id": step.request_id},
                    )
                )
                continue
            passed, assertion_results, meaningful = _evaluate_http_assertions(snapshot, step.expected)
            evidence.append(
                EvidenceRecord(
                    step_id=step.id,
                    action=step.action,
                    status="passed" if passed else "failed",
                    summary="响应断言全部通过。" if passed else "响应断言未全部通过。",
                    observed=snapshot.observed(assertion_results),
                    elapsed_ms=snapshot.elapsed_ms,
                )
            )
            meaningful_assertion_passed = meaningful_assertion_passed or (passed and meaningful)

    if not evidence:
        evidence.append(
            EvidenceRecord(
                step_id="runner",
                action="runtime_assert",
                status="blocked",
                summary="计划中没有可执行步骤。",
            )
        )

    statuses = {item.status for item in evidence}
    if "error" in statuses:
        status = "error"
    elif statuses.intersection({"blocked", "unsupported"}):
        status = "blocked"
    elif "failed" in statuses:
        status = "not_reproduced"
    elif meaningful_assertion_passed:
        status = "runtime_confirmed"
    else:
        status = "inconclusive"
    cleanup_status = "not_required" if normalized.cleanup.strategy == "none" else "not_run"
    return ValidationEvidenceResult(
        plan_id=normalized.id,
        candidate_id=normalized.candidate_id,
        status=status,  # type: ignore[arg-type]
        evidence=tuple(evidence),
        cleanup_status=cleanup_status,  # type: ignore[arg-type]
        notes="声明式 runner 仅执行同源、受限 HTTP 步骤；未执行脚本、Shell、Docker 命令或源码。",
    )


def dispatch_validation_plan(
    plan: DeclarativeValidationPlan | dict[str, Any],
    *,
    target_url: str,
    allow_state_changes: bool = False,
    config: ValidationRunnerConfig | None = None,
) -> ValidationEvidenceResult:
    config = config or ValidationRunnerConfig.from_environment()
    normalized = normalize_validation_plan(_plan_payload(plan), target_url=target_url)
    if config.mode == "inline":
        return execute_validation_plan(normalized, target_url=target_url, allow_state_changes=allow_state_changes)
    if config.mode == "queue" and config.queue_path is not None:
        job_id = submit_validation_job(
            config.queue_path,
            normalized,
            target_url=target_url,
            allow_state_changes=allow_state_changes,
            timeout_seconds=config.result_timeout_seconds,
        )
        return wait_for_validation_result(
            config.queue_path,
            job_id,
            plan=normalized,
            timeout_seconds=config.result_timeout_seconds,
        )
    first_step = normalized.steps[0]
    return _blocked_result(normalized, first_step, "未配置独立声明式验证 runner。")


def submit_validation_job(
    queue_path: Path,
    plan: DeclarativeValidationPlan,
    *,
    target_url: str,
    allow_state_changes: bool,
    timeout_seconds: float,
) -> str:
    root = ensure_validation_queue(queue_path)
    if not isinstance(allow_state_changes, bool):
        raise ValueError("allow_state_changes must be a boolean")
    job_id = secrets.token_hex(16)
    now = time.time()
    bounded_timeout = _bounded_result_timeout(timeout_seconds)
    payload = {
        "schema_version": 1,
        "job_id": job_id,
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": now + bounded_timeout,
        "target_url": validate_target_url(target_url),
        "allow_state_changes": allow_state_changes,
        "plan": plan.to_dict(),
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_QUEUE_DOCUMENT_BYTES:
        raise ValidationPlanError("serialized runner job is too large", path="job")
    write_json(root / "pending" / f"{job_id}.json", payload)
    return job_id


def wait_for_validation_result(
    queue_path: Path,
    job_id: str,
    *,
    plan: DeclarativeValidationPlan,
    timeout_seconds: float,
) -> ValidationEvidenceResult:
    root = ensure_validation_queue(queue_path)
    if not _safe_job_filename(f"{job_id}.json"):
        raise ValueError("runner job id must be 32 lowercase hexadecimal characters")
    deadline = time.monotonic() + _bounded_result_timeout(timeout_seconds)
    completed = root / "completed" / f"{job_id}.json"
    failed = root / "failed" / f"{job_id}.json"
    while time.monotonic() < deadline:
        for path in (completed, failed):
            if not path.exists():
                continue
            try:
                payload = _read_bounded_json(path)
                if payload.get("schema_version") != 1 or str(payload.get("job_id") or "") != job_id:
                    raise ValueError("runner result identity does not match the requested job")
                if path.parent.name == "completed" and payload.get("ok") is True and isinstance(payload.get("result"), dict):
                    result = ValidationEvidenceResult.from_dict(payload["result"])
                    if result.plan_id != plan.id or result.candidate_id != plan.candidate_id:
                        raise ValueError("runner result plan identity does not match the submitted plan")
                    return result
                message = str(payload.get("error") or "独立 runner 执行失败。")[:2000]
                return _blocked_result(plan, plan.steps[0], message)
            except (OSError, TypeError, ValueError, json.JSONDecodeError, ValidationPlanError) as exc:
                return _blocked_result(plan, plan.steps[0], f"独立 runner 返回了无效结果：{type(exc).__name__}: {exc}")
            finally:
                path.unlink(missing_ok=True)
        time.sleep(0.1)
    (root / "pending" / f"{job_id}.json").unlink(missing_ok=True)
    return _blocked_result(plan, plan.steps[0], "等待独立 runner 返回结果超时。")


def ensure_validation_queue(queue_path: Path) -> Path:
    root = Path(os.path.abspath(Path(queue_path).expanduser()))
    if root.exists() and root.is_symlink():
        raise ValueError("validation queue root must not be a symlink")
    root.mkdir(parents=True, exist_ok=True)
    for name in QUEUE_DIRECTORIES:
        directory = root / name
        if directory.exists() and directory.is_symlink():
            raise ValueError(f"validation queue directory must not be a symlink: {name}")
        directory.mkdir(parents=True, exist_ok=True)
    return root


def queue_runner_status(queue_path: Path) -> dict[str, Any]:
    root = ensure_validation_queue(queue_path)
    heartbeat = root / "runner-heartbeat.json"
    if not heartbeat.exists():
        return {"runner_ready": False, "runner_reason": "heartbeat_missing"}
    try:
        payload = _read_bounded_json(heartbeat)
        observed_at = float(payload.get("observed_at_epoch") or 0)
        concurrency = int(payload.get("concurrency") or 0)
        active_jobs = int(payload.get("active_jobs") or 0)
        stopping = payload.get("stopping", False)
        if (
            payload.get("schema_version") != 1
            or not math.isfinite(observed_at)
            or concurrency < 1
            or active_jobs < 0
            or active_jobs > concurrency
            or not isinstance(stopping, bool)
        ):
            raise ValueError("heartbeat values are invalid")
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {"runner_ready": False, "runner_reason": "heartbeat_invalid"}
    age = max(0.0, time.time() - observed_at)
    ready = age <= HEARTBEAT_MAX_AGE_SECONDS and not stopping
    return {
        "runner_ready": ready,
        "runner_reason": None if ready else ("runner_stopping" if stopping else "heartbeat_stale"),
        "runner_id": str(payload.get("runner_id") or "")[:120],
        "heartbeat_age_seconds": round(age, 3),
        "runner_concurrency": concurrency,
        "runner_active_jobs": active_jobs,
    }


def run_validation_worker(
    queue_path: Path,
    *,
    concurrency: int = 2,
    poll_interval: float = 0.25,
    once: bool = False,
    stop_event: threading.Event | None = None,
) -> int:
    root = ensure_validation_queue(queue_path)
    recover_stale_validation_jobs(root)
    worker_id = os.getenv(RUNNER_ID_ENV, "").strip() or f"runner-{secrets.token_hex(6)}"
    workers = max(1, min(12, int(concurrency or 1)))
    poll_interval = float(poll_interval)
    if not math.isfinite(poll_interval):
        raise ValueError("poll_interval must be finite")
    poll_interval = min(max(poll_interval, 0.05), 5.0)
    stop_event = stop_event or threading.Event()
    processed = 0
    futures: dict[Future[None], Path] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="auditforge-validation-runner") as executor:
        while not stop_event.is_set():
            done = [future for future in futures if future.done()]
            for future in done:
                future.result()
                futures.pop(future, None)
                processed += 1
            while len(futures) < workers and (not once or processed + len(futures) < 1):
                claimed = claim_validation_job(root)
                if claimed is None:
                    break
                futures[executor.submit(process_claimed_validation_job, root, claimed)] = claimed
            _write_runner_heartbeat(root, worker_id=worker_id, concurrency=workers, active_jobs=len(futures))
            if once and processed >= 1 and not futures:
                break
            if not futures and once:
                break
            stop_event.wait(poll_interval)
        for future in list(futures):
            future.result()
            processed += 1
    _write_runner_heartbeat(root, worker_id=worker_id, concurrency=workers, active_jobs=0, stopping=True)
    return processed


def claim_validation_job(queue_path: Path) -> Path | None:
    root = ensure_validation_queue(queue_path)
    for pending in sorted((root / "pending").glob("*.json"), key=lambda item: item.name):
        if not _safe_job_filename(pending.name) or pending.is_symlink() or not pending.is_file():
            continue
        claimed = root / "processing" / pending.name
        try:
            os.replace(pending, claimed)
        except FileNotFoundError:
            continue
        return claimed
    return None


def process_claimed_validation_job(queue_path: Path, claimed_path: Path) -> None:
    root = ensure_validation_queue(queue_path)
    claimed_path = Path(os.path.abspath(claimed_path))
    if claimed_path.parent != root / "processing" or not _safe_job_filename(claimed_path.name):
        raise ValueError("claimed runner job must be a safe file in the processing directory")
    job_id = claimed_path.stem
    destination = root / "completed" / f"{job_id}.json"
    try:
        job = _validated_runner_job(_read_bounded_json(claimed_path), expected_job_id=job_id)
        if job["expires_at"] < time.time():
            raise TimeoutError("runner job expired before execution")
        target_url = job["target_url"]
        plan = normalize_validation_plan(job["plan"], target_url=target_url)
        result = execute_validation_plan(
            plan,
            target_url=target_url,
            allow_state_changes=job["allow_state_changes"],
        )
        write_json(
            destination,
            {
                "schema_version": 1,
                "job_id": job_id,
                "ok": True,
                "completed_at": datetime.now(UTC).isoformat(),
                "result": result.to_dict(),
            },
        )
    except Exception as exc:  # noqa: BLE001 - isolate one untrusted job from the worker
        destination = root / "failed" / f"{job_id}.json"
        write_json(
            destination,
            {
                "schema_version": 1,
                "job_id": job_id,
                "ok": False,
                "completed_at": datetime.now(UTC).isoformat(),
                "error": f"{type(exc).__name__}: {exc}"[:2000],
            },
        )
    finally:
        claimed_path.unlink(missing_ok=True)


def recover_stale_validation_jobs(queue_path: Path) -> int:
    root = ensure_validation_queue(queue_path)
    recovered = 0
    cutoff = time.time() - STALE_PROCESSING_SECONDS
    for claimed in (root / "processing").glob("*.json"):
        if not _safe_job_filename(claimed.name) or claimed.is_symlink() or not claimed.is_file():
            continue
        try:
            if claimed.stat().st_mtime > cutoff:
                continue
            os.replace(claimed, root / "pending" / claimed.name)
            recovered += 1
        except FileNotFoundError:
            continue
    return recovered


def _execute_http_step(step: ValidationStep, target_url: str) -> tuple[EvidenceRecord, HttpResponseSnapshot | None, bool]:
    started = time.monotonic()
    try:
        request_url = _materialize_request_url(target_url, step)
        data, content_type = _encode_request_body(step.body)
        headers = {**step.headers}
        headers.setdefault("Accept", "application/json, text/plain, */*;q=0.1")
        headers.setdefault("User-Agent", "AuditForge-ValidationRunner/1.0")
        if content_type:
            headers.setdefault("Content-Type", content_type)
        request = urllib.request.Request(request_url, data=data, headers=headers, method=step.method or "GET")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())
        try:
            response = opener.open(request, timeout=step.timeout_ms / 1000)
        except urllib.error.HTTPError as exc:
            response = exc
        try:
            raw_body = response.read(MAX_RESPONSE_SAMPLE_BYTES + 1)
            truncated = len(raw_body) > MAX_RESPONSE_SAMPLE_BYTES
            raw_body = raw_body[:MAX_RESPONSE_SAMPLE_BYTES]
            response_headers = _bounded_response_headers(response.headers.items())
            body = _decode_body(raw_body, response_headers.get("content-type", ""))
            snapshot = HttpResponseSnapshot(
                request_id=step.id,
                method=step.method or "GET",
                url=request_url,
                status=int(response.status),
                headers=response_headers,
                body=body,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                truncated=truncated,
            )
        finally:
            response.close()
        if step.expected:
            passed, assertion_results, meaningful = _evaluate_http_assertions(snapshot, step.expected)
            record = EvidenceRecord(
                step_id=step.id,
                action=step.action,
                status="passed" if passed else "failed",
                summary="HTTP 请求和内联断言通过。" if passed else "HTTP 请求完成，但内联断言未全部通过。",
                observed=snapshot.observed(assertion_results),
                elapsed_ms=snapshot.elapsed_ms,
            )
            return record, snapshot, passed and meaningful
        return (
            EvidenceRecord(
                step_id=step.id,
                action=step.action,
                status="passed",
                summary="HTTP 请求已完成，等待后续声明式断言。",
                observed=snapshot.observed(),
                elapsed_ms=snapshot.elapsed_ms,
            ),
            snapshot,
            False,
        )
    except Exception as exc:  # noqa: BLE001 - transport errors become structured evidence
        return (
            EvidenceRecord(
                step_id=step.id,
                action=step.action,
                status="error",
                summary="HTTP 请求执行失败。",
                observed={"error": f"{type(exc).__name__}: {exc}"[:2000]},
                elapsed_ms=int((time.monotonic() - started) * 1000),
            ),
            None,
            False,
        )


def _materialize_request_url(target_url: str, step: ValidationStep) -> str:
    if not step.url:
        raise ValidationPlanError("HTTP step URL is missing", path=f"step.{step.id}.url")
    parsed = urllib.parse.urlsplit(step.url)
    base_url = step.url if parsed.scheme else urllib.parse.urljoin(target_url, step.url)
    request_parts = urllib.parse.urlsplit(validate_request_url(base_url))
    existing = urllib.parse.parse_qsl(request_parts.query, keep_blank_values=True)
    additions: list[tuple[str, str]] = []
    for key, value in step.query.items():
        if isinstance(value, list):
            additions.extend((key, item) for item in value)
        else:
            additions.append((key, value))
    query = urllib.parse.urlencode([*existing, *additions], doseq=True)
    return urllib.parse.urlunsplit((request_parts.scheme, request_parts.netloc, request_parts.path or "/", query, ""))


def _encode_request_body(body: Any) -> tuple[bytes | None, str | None]:
    if body is None:
        return None, None
    if isinstance(body, str):
        return body.encode("utf-8"), "text/plain; charset=utf-8"
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), "application/json"


def _decode_body(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            charset = value.strip("\"'")[:40]
            break
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _evaluate_http_assertions(snapshot: HttpResponseSnapshot, expected: dict[str, Any]) -> tuple[bool, dict[str, bool], bool]:
    results: dict[str, bool] = {}
    status_value = expected.get("status", expected.get("status_code"))
    if status_value is not None:
        results["status"] = snapshot.status == int(status_value)
    if "status_in" in expected:
        results["status_in"] = snapshot.status in {int(item) for item in expected["status_in"]}
    if "body_contains" in expected:
        values = _as_text_list(expected["body_contains"])
        results["body_contains"] = all(value in snapshot.body for value in values)
    if "body_not_contains" in expected:
        values = _as_text_list(expected["body_not_contains"])
        results["body_not_contains"] = all(value not in snapshot.body for value in values)
    if "header_equals" in expected:
        values = expected["header_equals"] if isinstance(expected["header_equals"], dict) else {}
        results["header_equals"] = all(snapshot.headers.get(str(key).lower()) == str(value) for key, value in values.items())
    if "json_contains" in expected:
        try:
            actual_json = json.loads(snapshot.body)
        except json.JSONDecodeError:
            results["json_contains"] = False
        else:
            results["json_contains"] = _json_contains(actual_json, expected["json_contains"])
    if "json_path_equals" in expected:
        try:
            actual_json = json.loads(snapshot.body)
        except json.JSONDecodeError:
            results["json_path_equals"] = False
        else:
            assertions = expected["json_path_equals"] if isinstance(expected["json_path_equals"], dict) else {}
            results["json_path_equals"] = bool(assertions) and all(
                _json_path_value(actual_json, str(path)) == value for path, value in assertions.items()
            )
    meaningful_keys = set(results) - {"status", "status_in"}
    return bool(results) and all(results.values()), results, bool(meaningful_keys)


def _json_contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and _json_contains(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and all(any(_json_contains(item, wanted) for item in actual) for wanted in expected)
    return actual == expected


def _json_path_value(value: Any, path: str) -> Any:
    if path == "$":
        return value
    if not path.startswith("$."):
        return object()
    current = value
    for segment in path[2:].split("."):
        if not segment:
            return object()
        name, bracket, index_text = segment.partition("[")
        if name:
            if not isinstance(current, dict) or name not in current:
                return object()
            current = current[name]
        if bracket:
            if not index_text.endswith("]") or not index_text[:-1].isdigit() or not isinstance(current, list):
                return object()
            index = int(index_text[:-1])
            if index >= len(current):
                return object()
            current = current[index]
    return current


def _as_text_list(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else [str(value)]


def _public_response_headers(headers: dict[str, str]) -> dict[str, str]:
    sensitive = {"authorization", "cookie", "proxy-authenticate", "proxy-authorization", "set-cookie", "set-cookie2"}
    return {key: value for key, value in headers.items() if key not in sensitive}


def _blocked_result(plan: DeclarativeValidationPlan, step: ValidationStep, message: str) -> ValidationEvidenceResult:
    return ValidationEvidenceResult(
        plan_id=plan.id,
        candidate_id=plan.candidate_id,
        status="blocked",
        evidence=(
            EvidenceRecord(
                step_id=step.id,
                action=step.action,
                status="blocked",
                summary=message[:2000],
            ),
        ),
        cleanup_status="not_run",
        notes=message[:4000],
    )


def _plan_payload(plan: DeclarativeValidationPlan | dict[str, Any]) -> dict[str, Any]:
    return plan.to_dict() if isinstance(plan, DeclarativeValidationPlan) else dict(plan)


def _read_bounded_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("validation queue document must be a regular file")
    if path.stat().st_size > MAX_QUEUE_DOCUMENT_BYTES:
        raise ValueError("validation queue document is too large")
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise ValueError("validation queue document must be a JSON object")
    return payload


def _safe_job_filename(name: str) -> bool:
    stem, suffix = os.path.splitext(name)
    return suffix == ".json" and len(stem) == 32 and all(character in "0123456789abcdef" for character in stem)


def _bounded_result_timeout(value: float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("runner result timeout must be numeric") from exc
    if not math.isfinite(timeout):
        raise ValueError("runner result timeout must be finite")
    return min(max(timeout, 5.0), MAX_RESULT_TIMEOUT_SECONDS)


def _validated_runner_job(payload: dict[str, Any], *, expected_job_id: str) -> dict[str, Any]:
    allowed = {
        "schema_version",
        "job_id",
        "created_at",
        "expires_at",
        "target_url",
        "allow_state_changes",
        "plan",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"runner job contains unknown fields: {', '.join(unknown)}")
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported runner job schema version")
    if str(payload.get("job_id") or "") != expected_job_id:
        raise ValueError("runner job id does not match its filename")
    if not isinstance(payload.get("created_at"), str) or not payload["created_at"]:
        raise ValueError("runner job created_at must be a non-empty string")
    expires_at = payload.get("expires_at")
    if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)) or not math.isfinite(float(expires_at)):
        raise ValueError("runner job expires_at must be a finite number")
    target_url = payload.get("target_url")
    if not isinstance(target_url, str):
        raise ValueError("runner job target_url must be a string")
    controlled_target = validate_target_url(target_url)
    allow_state_changes = payload.get("allow_state_changes")
    if not isinstance(allow_state_changes, bool):
        raise ValueError("runner job allow_state_changes must be a boolean")
    plan = payload.get("plan")
    if not isinstance(plan, dict):
        raise ValueError("runner job plan must be an object")
    return {
        **payload,
        "expires_at": float(expires_at),
        "target_url": controlled_target,
        "allow_state_changes": allow_state_changes,
        "plan": plan,
    }


def _bounded_response_headers(items: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    total = 0
    for index, (raw_key, raw_value) in enumerate(items):
        if index >= MAX_RESPONSE_HEADERS:
            break
        key = str(raw_key).lower()[:256]
        value = str(raw_value)[:4096]
        size = len(key.encode("utf-8", errors="replace")) + len(value.encode("utf-8", errors="replace"))
        if total + size > MAX_RESPONSE_HEADER_BYTES:
            break
        total += size
        headers[key] = value
    return headers


def _write_runner_heartbeat(
    queue_path: Path,
    *,
    worker_id: str,
    concurrency: int,
    active_jobs: int,
    stopping: bool = False,
) -> None:
    write_json(
        queue_path / "runner-heartbeat.json",
        {
            "schema_version": 1,
            "runner_id": worker_id[:120],
            "pid": os.getpid(),
            "concurrency": concurrency,
            "active_jobs": active_jobs,
            "stopping": stopping,
            "observed_at": datetime.now(UTC).isoformat(),
            "observed_at_epoch": time.time(),
        },
    )


__all__ = [
    "QUEUE_PATH_ENV",
    "RUNNER_MODE_ENV",
    "RUNNER_TIMEOUT_ENV",
    "ValidationRunnerConfig",
    "claim_validation_job",
    "dispatch_validation_plan",
    "ensure_validation_queue",
    "execute_validation_plan",
    "process_claimed_validation_job",
    "queue_runner_status",
    "recover_stale_validation_jobs",
    "run_validation_worker",
    "submit_validation_job",
    "wait_for_validation_result",
]
