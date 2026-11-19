from __future__ import annotations

import ctypes
import email.policy
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import uuid
import zipfile
from copy import deepcopy
from datetime import UTC, datetime
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlsplit

from ..analysis.graph_artifacts import GRAPH_DIRECTORY, graph_summary, read_graph_page
from ..analysis.llm_candidates import DEFAULT_BASE_URL, DEFAULT_MODEL, LLMConfig, test_llm_connection
from ..analysis.project_inventory import inventory_summary
from ..core.logging_config import contextual_logger, get_logger, get_recent_logs
from ..core.settings import (
    llm_config_from_settings,
    load_workspace_settings,
    mask_secret,
    public_settings,
    sandbox_concurrency_from_settings,
    save_workspace_settings,
)
from ..core.user_errors import (
    UserError,
    UserFacingError,
    classify_error,
    error_payload,
    failure_payload,
    new_reference,
    user_error,
    with_status,
)
from ..core.utils import sha256_text
from ..engine import run_scan
from ..reporting.store import read_dashboard_detail, read_dashboard_summary
from ..verification.verification import validate_target_url
from .scan_worker import (
    WORKER_JOB_FILE,
    WORKER_STATE_FILE,
    cancel_request_path,
    read_worker_state,
    scan_job_payload,
    write_worker_job,
    write_worker_state,
)
from .ui import server_ui as _server_ui
from .web_security import (
    AuthContext,
    SessionStore,
    WebSecurityConfig,
    atomic_write_json,
    configured_repo_roots,
    csrf_bootstrap_script,
    csrf_is_valid,
    host_is_allowed,
    is_loopback_host,
    locked_path,
    origin_is_allowed,
    redact_url,
    session_cookie,
    validate_repo_path,
)

# Compatibility shim: presentation implementations live in server_ui, while
# existing callers may continue importing them from auditforge.server.
for _ui_export in _server_ui.__all__:
    globals()[_ui_export] = getattr(_server_ui, _ui_export)
del _ui_export

RUNS_FILE = "auditforge_runs.json"
RUNS_DIR = "runs"
UPLOADS_DIR = "uploads"
REPOS_DIR = "uploaded_repos"
CONFIRMED_VERIFICATION_STATUSES = {"confirmed"}
MAX_UPLOAD_BYTES = 120 * 1024 * 1024
MAX_JSON_BODY_BYTES = 256 * 1024
MAX_FORM_FIELD_BYTES = 64 * 1024
MAX_MULTIPART_PARTS = 64
MAX_ZIP_ENTRIES = 10000
MAX_ZIP_FILES = 8000
MAX_ZIP_UNCOMPRESSED_BYTES = 350 * 1024 * 1024
MAX_ZIP_DEPTH = 20
MAX_ZIP_PATH_LENGTH = 240
MAX_ZIP_COMPRESSION_RATIO = 100
TRIAGE_FILE = "triage_notes.json"
TRIAGE_STATUS_OPTIONS = {
    "needs_review": "待复核",
    "accepted": "人工确认",
    "false_positive": "标记误报",
    "fixing": "修复中",
    "fixed": "已修复",
}

RUN_LOCK = threading.RLock()
RUN_INDEX_CACHE_LOCK = threading.Lock()
RUN_INDEX_CACHE: dict[Path, tuple[tuple[int, int], dict[str, dict]]] = {}
RUN_INDEX_CACHE_LIMIT = 64
DEFAULT_SCAN_SEMAPHORE = threading.BoundedSemaphore(2)
LOGGER = get_logger(__name__)
CLIENT_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionAbortedError, ConnectionResetError)
WORKER_STDOUT_FILE = "worker.stdout.log"
WORKER_STDERR_FILE = "worker.stderr.log"
WORKER_STARTUP_GRACE_SECONDS = 30


def _write_response_body(stream, body: bytes, logger, request_path: str) -> bool:
    """Write an HTTP response body without treating a closed browser as a server error."""

    try:
        stream.write(body)
    except CLIENT_DISCONNECT_ERRORS:
        logger.debug(
            "client disconnected before response completed",
            extra={"event": "server.client_disconnected", "path": request_path},
        )
        return False
    return True


def request_body_limit_exceeded(exc: BaseException) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in ("too large", "exceeds", "larger than", "size limit", "maximum"))


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server with a hard cap on live request threads."""

    daemon_threads = True

    def __init__(self, server_address, handler_class, *, max_concurrency: int = 32):
        self._request_slots = threading.BoundedSemaphore(max(1, int(max_concurrency)))
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            public_error = user_error("SERVER_BUSY")
            body = json.dumps(error_payload(public_error), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Type: application/json; charset=utf-8\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Retry-After: 3\r\n"
                    + f"X-AuditForge-Reference: {public_error.reference}\r\n".encode("ascii")
                    + b"X-Content-Type-Options: nosniff\r\n\r\n"
                    + body
                )
                LOGGER.warning(
                    "request rejected because server is busy",
                    extra={"event": "server.busy", "reference": public_error.reference},
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def create_workspace_server(
    workspace: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    security: WebSecurityConfig | None = None,
) -> BoundedThreadingHTTPServer:
    workspace = workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    security = security or WebSecurityConfig.from_environment(workspace, host)
    sessions = SessionStore(security.admin_token)
    scan_semaphore = threading.BoundedSemaphore(security.max_scan_concurrency)
    upload_semaphore = threading.BoundedSemaphore(min(2, security.max_scan_concurrency))
    server_logger = contextual_logger(LOGGER, component="web", workspace=str(workspace))
    token_path: Path | None = None
    if is_loopback_host(host):
        token_path = workspace / ".auditforge_admin_token.json"
        atomic_write_json(token_path, {"token": security.admin_token})

    class Handler(BaseHTTPRequestHandler):
        server_version = "AuditForge"
        sys_version = ""
        auth_context: AuthContext | None = None

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(security.socket_timeout_seconds)

        def end_headers(self) -> None:
            super().end_headers()
            self._auditforge_response_started = True

        def handle_api_exception(self, exc: BaseException, *, context: str = "internal") -> None:
            reference = str(getattr(exc, "reference", "") or "") or new_reference("AFR")
            public_error = classify_error(exc, context=context, reference=reference)
            if public_error.status >= 500:
                server_logger.exception(
                    "request failed",
                    extra={
                        "event": "server.request_failed",
                        "method": getattr(self, "command", ""),
                        "path": urlparse(getattr(self, "path", "") or "").path,
                        "reference": reference,
                        "error_type": type(exc).__name__,
                    },
                )
            if getattr(self, "_auditforge_response_started", False):
                self.close_connection = True
                return
            self.send_api_error(public_error)

        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            try:
                self.dispatch_GET()
            except CLIENT_DISCONNECT_ERRORS:
                self.close_connection = True
            except Exception as exc:  # noqa: BLE001 - HTTP request boundary
                self.handle_api_exception(exc)

        def dispatch_GET(self) -> None:  # noqa: N802 - mirrors HTTP callback for a protected dispatcher
            parsed = urlparse(self.path)
            if not self.authorize_request(parsed, unsafe=False):
                return
            if parsed.path == "/":
                self.send_html(_server_ui.render_overview_page(workspace))
                return
            if parsed.path == "/scan":
                self.send_html(_server_ui.render_scan_page(workspace))
                return
            if parsed.path == "/history":
                self.send_html(_server_ui.render_history_page(workspace))
                return
            if parsed.path == "/logs":
                self.send_html(_server_ui.render_logs_page(workspace))
                return
            if parsed.path == "/legacy":
                self.send_html(_server_ui.render_overview_page(workspace))
                return
            if parsed.path == "/settings":
                self.send_html(_server_ui.render_settings_page(workspace))
                return
            if parsed.path == "/api/runs":
                self.send_json({"runs": list_runs(workspace)})
                return
            if parsed.path == "/api/logs":
                self.handle_logs_get(parsed.query)
                return
            triage_api_match = re.match(r"^/api/runs/([^/]+)/triage$", parsed.path)
            if triage_api_match:
                run = find_run(workspace, triage_api_match.group(1))
                if not run:
                    self.send_api_error(user_error("RUN_NOT_FOUND"))
                    return
                self.send_json(load_triage_notes(run_workspace_path(workspace, run)))
                return
            run_api_match = re.match(r"^/api/runs/([^/]+)$", parsed.path)
            if run_api_match:
                run = find_run(workspace, run_api_match.group(1))
                if not run:
                    self.send_api_error(user_error("RUN_NOT_FOUND"))
                    return
                self.send_json({"run": public_run(run)})
                return
            if parsed.path.startswith("/runs/"):
                self.handle_run_get(workspace, parsed.path, parsed.query)
                return
            if parsed.path == "/api":
                payload = read_dashboard_detail(workspace) if (workspace / "auditforge.db").exists() else {"scan": None, "candidates": []}
                payload["graph"] = graph_summary(workspace)
                self.send_json(redact_public_payload(payload), headers={"Cache-Control": "private, max-age=30"})
                return
            if parsed.path == "/api/settings":
                self.send_json(public_settings(load_workspace_settings(workspace)))
                return
            if parsed.path in {"/report.md", "/report.html"}:
                file_path = workspace / parsed.path.lstrip("/")
                if not file_path.exists():
                    self.send_error(404)
                    return
                content_type = "text/html; charset=utf-8" if file_path.suffix == ".html" else "text/plain; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_security_headers()
                self.end_headers()
                self.write_response_body(file_path.read_bytes())
                return
            self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
            try:
                self.dispatch_POST()
            except CLIENT_DISCONNECT_ERRORS:
                self.close_connection = True
            except Exception as exc:  # noqa: BLE001 - HTTP request boundary
                self.handle_api_exception(exc)

        def dispatch_POST(self) -> None:  # noqa: N802 - mirrors HTTP callback for a protected dispatcher
            parsed = urlparse(self.path)
            try:
                enforce_global_body_limit(
                    self,
                    MAX_UPLOAD_BYTES if parsed.path == "/api/scan" else MAX_JSON_BODY_BYTES,
                )
            except ValueError as exc:
                code = "REQUEST_BODY_TOO_LARGE" if request_body_limit_exceeded(exc) else "REQUEST_INVALID"
                self.send_api_error(user_error(code))
                return
            if parsed.path == "/api/login":
                self.handle_login_post()
                return
            if not self.authorize_request(parsed, unsafe=True):
                return
            triage_match = re.match(r"^/api/runs/([^/]+)/triage$", parsed.path)
            if triage_match:
                self.handle_run_triage_post(workspace, triage_match.group(1))
                return
            delete_match = re.match(r"^/api/runs/([^/]+)/delete$", parsed.path)
            if delete_match:
                self.handle_run_delete_post(workspace, delete_match.group(1))
                return
            cancel_match = re.match(r"^/api/runs/([^/]+)/cancel$", parsed.path)
            if cancel_match:
                self.handle_run_cancel_post(workspace, cancel_match.group(1))
                return
            if parsed.path == "/api/settings":
                self.handle_settings_post(workspace)
                return
            if parsed.path == "/api/settings/test-llm":
                self.handle_llm_test_post(workspace)
                return
            if parsed.path == "/api/scan":
                self.handle_scan_post(workspace)
                return
            self.send_error(404)

        def do_HEAD(self) -> None:  # noqa: N802 - stdlib callback name
            parsed = urlparse(self.path)
            if not self.authorize_request(parsed, unsafe=False):
                return
            self.send_response(405)
            self.send_header("Allow", "GET, POST")
            self.send_security_headers()
            self.end_headers()

        def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib callback name
            parsed = urlparse(self.path)
            if not self.authorize_request(parsed, unsafe=False):
                return
            self.send_response(405)
            self.send_header("Allow", "GET, POST")
            self.send_security_headers()
            self.end_headers()

        def do_PUT(self) -> None:  # noqa: N802 - stdlib callback name
            self.reject_unsafe_method()

        def do_PATCH(self) -> None:  # noqa: N802 - stdlib callback name
            self.reject_unsafe_method()

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib callback name
            self.reject_unsafe_method()

        def reject_unsafe_method(self) -> None:
            parsed = urlparse(self.path)
            try:
                enforce_global_body_limit(self, MAX_JSON_BODY_BYTES)
            except ValueError as exc:
                code = "REQUEST_BODY_TOO_LARGE" if request_body_limit_exceeded(exc) else "REQUEST_INVALID"
                self.send_api_error(user_error(code))
                return
            if not self.authorize_request(parsed, unsafe=True):
                return
            self.send_api_error(user_error("METHOD_NOT_ALLOWED"))

        def handle_login_post(self) -> None:
            host_header = str(self.headers.get("Host") or "")
            origin = self.headers.get("Origin")
            if not host_is_allowed(host_header, security):
                self.send_api_error(user_error("REQUEST_HOST_REJECTED"))
                return
            if not origin or not origin_is_allowed(origin, host_header, security):
                self.send_api_error(user_error("REQUEST_ORIGIN_REJECTED"))
                return
            try:
                payload = read_json_request(self, max_bytes=4096)
            except ValueError as exc:
                self.handle_api_exception(exc, context="request")
                return
            if not sessions.valid_admin_token(str(payload.get("token") or "")):
                self.send_api_error(user_error("AUTH_INVALID_TOKEN"))
                return
            session_id, _ = sessions.create()
            self.send_json(
                {"ok": True},
                headers={"Set-Cookie": session_cookie(session_id, secure=not is_loopback_host(host))},
            )

        def handle_settings_post(self, workspace: Path) -> None:
            try:
                payload = read_json_request(self)
            except (TypeError, ValueError) as exc:
                self.handle_api_exception(exc, context="request")
                return
            try:
                settings = save_workspace_settings(workspace, payload)
                server_logger.info("settings changed", extra={"event": "settings.changed"})
                self.send_json(public_settings(settings))
            except Exception as exc:  # noqa: BLE001 - surface local settings errors to UI
                self.handle_api_exception(exc, context="settings")

        def handle_logs_get(self, raw_query: str) -> None:
            try:
                query = parse_qs(raw_query, keep_blank_values=True, max_num_fields=8)
                raw_after = (query.get("after") or [""])[0].strip()
                raw_limit = (query.get("limit") or ["100"])[0].strip()
                level = (query.get("level") or [""])[0].strip() or None
                after = int(raw_after) if raw_after else None
                limit = int(raw_limit)
                logs = get_recent_logs(after_sequence=after, limit=limit, level=level)
            except (TypeError, ValueError) as exc:
                self.handle_api_exception(exc, context="logs")
                return
            next_after = int(logs[-1].get("sequence") or 0) if logs else int(after or 0)
            self.send_json(
                {
                    "logs": [public_log_entry(item) for item in logs],
                    "next_after": next_after,
                }
            )

        def handle_llm_test_post(self, workspace: Path) -> None:
            try:
                payload = read_json_request(self)
                config = llm_config_from_test_payload(workspace, payload)
                self.send_json(test_llm_connection(config))
            except Exception as exc:  # noqa: BLE001 - return concise connection diagnostics to UI
                self.handle_api_exception(exc, context="llm_test")

        def handle_scan_post(self, workspace: Path) -> None:
            if not upload_semaphore.acquire(blocking=False):
                self.send_api_error(user_error("UPLOAD_BUSY"), headers={"Retry-After": "3"})
                return
            try:
                form = parse_multipart_form(self)
            except Exception as exc:  # noqa: BLE001 - show actionable local upload errors
                self.handle_api_exception(exc, context="upload")
                return
            finally:
                upload_semaphore.release()
            try:
                run = start_scan_run(
                    workspace,
                    form,
                    scan_semaphore=scan_semaphore,
                    max_scan_concurrency=security.max_scan_concurrency,
                    allowed_repo_roots=security.allowed_repo_roots,
                )
                server_logger.info(
                    "scan queued",
                    extra={"event": "scan.queued", "run_id": run.get("id"), "source_type": run.get("source_type")},
                )
                self.send_json({"run": public_run(run)})
            except Exception as exc:  # noqa: BLE001 - show actionable local scan errors
                self.handle_api_exception(exc, context="scan_start")

        def handle_run_delete_post(self, workspace: Path, run_id: str) -> None:
            try:
                result = delete_scan_run(workspace, run_id)
                self.send_json({"ok": True, "run": public_run(result["run"]), "removed": result["removed"], "redirect": "/history"})
            except LookupError:
                self.send_api_error(user_error("RUN_NOT_FOUND"))
            except Exception as exc:  # noqa: BLE001 - surface local cleanup errors in UI
                self.handle_api_exception(exc, context="delete")

        def handle_run_cancel_post(self, workspace: Path, run_id: str) -> None:
            try:
                run = cancel_scan_run(workspace, run_id)
                self.send_json({"ok": True, "run": public_run(run)})
            except LookupError:
                self.send_api_error(user_error("RUN_NOT_FOUND"))
            except Exception as exc:  # noqa: BLE001 - surface a safe, actionable cancellation error
                self.handle_api_exception(exc, context="cancel")

        def handle_run_triage_post(self, workspace: Path, run_id: str) -> None:
            try:
                run = find_run(workspace, run_id)
                if not run:
                    self.send_api_error(user_error("RUN_NOT_FOUND"))
                    return
                payload = read_json_request(self, max_bytes=64 * 1024)
                item = save_candidate_triage(run_workspace_path(workspace, run), payload)
                self.send_json({"ok": True, "item": item, "triage": load_triage_notes(run_workspace_path(workspace, run))})
            except Exception as exc:  # noqa: BLE001 - show actionable local triage errors
                self.handle_api_exception(exc, context="triage")

        def handle_run_get(self, workspace: Path, path: str, raw_query: str = "") -> None:
            match = re.match(r"^/runs/([^/]+)(?:/(.*))?$", path)
            if not match:
                self.send_error(404)
                return
            run_id = match.group(1)
            tail = match.group(2) or ""
            run = find_run(workspace, run_id)
            if not run:
                self.send_error(404)
                return
            run_workspace = run_workspace_path(workspace, run)
            if tail == "":
                if run.get("status") == "completed":
                    self.send_html(_server_ui.render_run_detail_page(workspace, run_workspace, run))
                else:
                    self.send_html(_server_ui.render_run_status_page(workspace, run))
                return
            if tail == "api":
                payload = (
                    read_dashboard_detail(run_workspace) if (run_workspace / "auditforge.db").exists() else {"scan": None, "candidates": []}
                )
                payload["graph"] = graph_summary(run_workspace)
                self.send_json(redact_public_payload(payload), headers={"Cache-Control": "private, max-age=30"})
                return
            if tail == "graph":
                try:
                    page = read_graph_page(run_workspace, **parse_graph_page_query(raw_query))
                except ValueError as exc:
                    self.handle_api_exception(exc, context="graph")
                    return
                self.send_json(redact_public_payload(page), headers={"Cache-Control": "private, max-age=60"})
                return
            if tail == "export.zip":
                archive = build_run_export_zip(run_workspace, run)
                filename = f"auditforge-{safe_filename(str(run.get('id') or 'run'))}-evidence.zip"
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(archive)))
                self.send_security_headers()
                self.end_headers()
                self.write_response_body(archive)
                return
            if tail in {"report.html", "report.md", "sbom.cdx.json"}:
                file_path = run_workspace / tail
                if not file_path.exists():
                    self.send_error(404)
                    return
                if file_path.suffix == ".html":
                    content_type = "text/html; charset=utf-8"
                elif file_path.suffix == ".json":
                    content_type = "application/json; charset=utf-8"
                else:
                    content_type = "text/plain; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_security_headers()
                self.end_headers()
                self.write_response_body(file_path.read_bytes())
                return
            self.send_error(404)

        def authorize_request(self, parsed, *, unsafe: bool) -> bool:
            host_header = str(self.headers.get("Host") or "")
            if not host_is_allowed(host_header, security):
                self.send_api_error(user_error("REQUEST_HOST_REJECTED"))
                return False
            origin = self.headers.get("Origin")
            if not origin_is_allowed(origin, host_header, security):
                self.send_api_error(user_error("REQUEST_ORIGIN_REJECTED"))
                return False

            context = sessions.authenticate(self.headers)
            if context is None:
                if not parsed.path.startswith("/api"):
                    self.send_login_page()
                    return False
                self.send_api_error(
                    user_error("AUTH_REQUIRED"),
                    headers={"WWW-Authenticate": 'Bearer realm="AuditForge"'},
                )
                return False
            if unsafe:
                if context.kind == "session" and not origin:
                    self.send_api_error(user_error("REQUEST_ORIGIN_REJECTED"))
                    return False
                if not csrf_is_valid(context, self.headers.get("X-AuditForge-CSRF")):
                    self.send_api_error(user_error("REQUEST_CSRF_REJECTED"))
                    return False
            self.auth_context = context
            return True

        def send_login_page(self) -> None:
            body = _server_ui.render_login_page(token_path)
            encoded = body.encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_security_headers()
            self.end_headers()
            self.write_response_body(encoded)

        def log_request(self, code="-", size="-") -> None:
            request_path = urlparse(getattr(self, "path", "") or "").path
            status = int(code) if isinstance(code, int) or str(code).isdigit() else str(code)
            if request_path == "/api/logs" or (
                getattr(self, "command", "") == "GET"
                and re.fullmatch(r"/api/runs/[^/]+", request_path)
                and isinstance(status, int)
                and status < 400
            ):
                return
            server_logger.info(
                "request",
                extra={
                    "event": "server.request",
                    "method": getattr(self, "command", ""),
                    "path": request_path,
                    "status": status,
                },
            )

        def log_message(self, fmt: str, *args) -> None:
            server_logger.debug("http server diagnostic", extra={"event": "server.diagnostic"})

        def send_security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            )

        def write_response_body(self, body: bytes) -> bool:
            completed = _write_response_body(self.wfile, body, server_logger, urlparse(self.path).path)
            if not completed:
                self.close_connection = True
            return completed

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            del message, explain
            code_map = {401: "AUTH_REQUIRED", 403: "REQUEST_ORIGIN_REJECTED", 404: "RESOURCE_NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
            self.send_api_error(with_status(user_error(code_map.get(code, "INTERNAL_ERROR")), code))

        def send_api_error(self, error: UserError, *, headers: dict[str, str] | None = None) -> None:
            log_method = server_logger.warning if error.status >= 429 else server_logger.info
            log_method(
                "user-facing request error",
                extra={
                    "event": "server.user_error",
                    "method": getattr(self, "command", ""),
                    "path": urlparse(getattr(self, "path", "") or "").path,
                    "status": error.status,
                    "error_code": error.code,
                    "reference": error.reference,
                },
            )
            response_headers = {
                "X-AuditForge-Reference": error.reference,
                "X-Request-ID": error.reference,
                **(headers or {}),
            }
            if error.retryable and error.status in {429, 503}:
                response_headers.setdefault("Retry-After", "3")
            self.send_json(error_payload(error), status=error.status, headers=response_headers)

        def send_html(self, body: str) -> None:
            bootstrap = csrf_bootstrap_script(self.auth_context.csrf_token if self.auth_context else None)
            if bootstrap:
                body = body.replace("</head>", bootstrap + "</head>", 1)
            encoded = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_security_headers()
            self.end_headers()
            self.write_response_body(encoded)

        def send_json(self, payload: dict, status: int = 200, *, headers: dict[str, str] | None = None) -> None:
            encoded = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_security_headers()
            self.end_headers()
            self.write_response_body(encoded)

    server = BoundedThreadingHTTPServer(
        (host, port),
        Handler,
        max_concurrency=security.max_request_concurrency,
    )
    server.security_config = security  # type: ignore[attr-defined]
    server.token_path = token_path  # type: ignore[attr-defined]
    return server


def serve_workspace(
    workspace: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    security: WebSecurityConfig | None = None,
) -> None:
    server = create_workspace_server(workspace, host, port, security=security)
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    if ":" in display_host and not display_host.startswith("["):
        display_host = f"[{display_host}]"
    logger = contextual_logger(LOGGER, component="web", workspace=str(Path(workspace).resolve()))
    interrupted = recover_interrupted_runs(workspace)
    if interrupted:
        logger.warning(
            "interrupted scan runs recovered after dashboard restart",
            extra={"event": "scan.recovered_after_restart", "runs": interrupted},
        )
    logger.info(
        "dashboard started",
        extra={
            "event": "server.started",
            "host": host,
            "port": server.server_port,
            "url": f"http://{display_host}:{server.server_port}/",
            "token_file": str(server.token_path) if server.token_path else None,  # type: ignore[attr-defined]
        },
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("dashboard stopped by user", extra={"event": "server.stopped", "reason": "keyboard_interrupt"})
    finally:
        server.server_close()


def runs_path(workspace: Path) -> Path:
    return workspace / RUNS_FILE


def run_index_cache_key(path: Path) -> Path:
    """Return a stable cache key even while the registry does not exist yet."""

    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def run_index_signature(path: Path) -> tuple[int, int] | None:
    """Identify a registry revision without opening its potentially large JSON payload."""

    try:
        stat_result = path.stat()
    except OSError:
        return None
    return stat_result.st_mtime_ns, stat_result.st_size


def invalidate_run_index_cache(workspace: Path) -> None:
    """Drop the lightweight registry lookup cache after a local index write."""

    path = runs_path(workspace)
    with RUN_INDEX_CACHE_LOCK:
        RUN_INDEX_CACHE.pop(run_index_cache_key(path), None)


def indexed_run_record(workspace: Path, run_id: str) -> dict | None:
    """Read one indexed run without hydrating every historical result directory.

    The Dashboard polls a single run frequently while an isolated worker writes
    its progress to ``worker_state.json``.  The registry itself changes much
    less often, so cache its decoded records by file revision and let callers
    fall back to full discovery when the index cannot answer the request.
    """

    path = runs_path(workspace)
    cache_key = run_index_cache_key(path)
    signature = run_index_signature(path)
    with RUN_INDEX_CACHE_LOCK:
        if signature is None:
            RUN_INDEX_CACHE.pop(cache_key, None)
            return None

        cached = RUN_INDEX_CACHE.get(cache_key)
        if cached is not None and cached[0] == signature:
            record = cached[1].get(run_id)
            return deepcopy(record) if isinstance(record, dict) else None

        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            RUN_INDEX_CACHE.pop(cache_key, None)
            return None

        runs = payload.get("runs") if isinstance(payload, dict) else payload
        if not isinstance(runs, list):
            RUN_INDEX_CACHE.pop(cache_key, None)
            return None

        records: dict[str, dict] = {}
        for run in runs:
            if not isinstance(run, dict):
                continue
            indexed_id = str(run.get("id") or "")
            if indexed_id:
                records[indexed_id] = dict(run)
        if len(RUN_INDEX_CACHE) >= RUN_INDEX_CACHE_LIMIT:
            RUN_INDEX_CACHE.pop(next(iter(RUN_INDEX_CACHE)))
        RUN_INDEX_CACHE[cache_key] = (signature, records)
        record = records.get(run_id)
        return deepcopy(record) if isinstance(record, dict) else None


def load_runs(workspace: Path) -> list[dict]:
    with RUN_LOCK:
        return _load_runs_unlocked(workspace)


def _load_runs_unlocked(workspace: Path) -> list[dict]:
    path = runs_path(workspace)
    repair_index = False
    if not path.exists():
        indexed_runs = infer_legacy_runs(workspace)
    else:
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            indexed_runs = infer_legacy_runs(workspace)
            repair_index = True
        else:
            runs = payload.get("runs") if isinstance(payload, dict) else payload
            if isinstance(runs, list):
                indexed_runs = runs
            else:
                indexed_runs = infer_legacy_runs(workspace)
                repair_index = True
    merged_runs = merge_run_records(
        [run for run in indexed_runs if isinstance(run, dict)],
        discover_run_directory_records(workspace),
    )
    worker_merged_runs = [normalize_run_failure(merge_worker_state(workspace, run)) for run in merged_runs]
    sorted_runs = sorted(worker_merged_runs, key=lambda item: str(item.get("created_at") or ""), reverse=True)
    result = drop_persisted_legacy_runs(sorted_runs)
    if repair_index:
        repair_runs_index(workspace, path, result)
    return result


def worker_state_for_run(workspace: Path, run: dict) -> dict:
    """Read a worker state only when it belongs to the indexed run.

    Worker state is intentionally a separate, small file so frequent progress
    updates never contend with the Dashboard's run registry.  Treat a malformed
    or mismatched state as absent rather than allowing it to alter a task.
    """

    run_id = str(run.get("id") or "")
    if not run_id:
        return {}
    try:
        state = read_worker_state(run_workspace_path(workspace, run))
    except (OSError, ValueError):
        return {}
    return state if str(state.get("run_id") or "") == run_id else {}


def merge_worker_state(workspace: Path, run: dict) -> dict:
    """Overlay isolated-worker progress and terminal results onto a run record."""

    state = worker_state_for_run(workspace, run)
    worker_status = str(state.get("status") or "").lower()
    if worker_status not in {"starting", "running", "completed", "failed", "cancelled"}:
        return dict(run)

    merged = dict(run)
    verify = str(merged.get("verify") or "none")
    dependency_scan = bool(merged.get("dependency_scan"))
    state_progress = state.get("progress") if isinstance(state.get("progress"), dict) else {}
    stage = str(state_progress.get("stage") or "queued")
    detail = str(state_progress.get("detail") or "")[:2000]
    try:
        percent = max(0, min(100, int(state_progress.get("percent") or 0)))
    except (TypeError, ValueError):
        percent = 0

    if worker_status in {"starting", "running"}:
        # A terminal registry result always wins over a stale worker write.  It
        # prevents a late progress callback from reviving a user-cancelled run.
        if str(merged.get("status") or "") != "running":
            return merged
        if stage in {"inventory", "candidate", "dependencies", "verification", "verification_skipped"}:
            merged["progress"] = apply_progress_event(merged.get("progress"), verify, dependency_scan, stage, percent, detail)
        else:
            progress = normalize_progress(merged.get("progress"), verify, dependency_scan)
            progress.update(
                {
                    "phase": stage,
                    "detail": detail or "isolated scan worker is starting",
                    "updated_at": str(state.get("updated_at") or datetime.now(UTC).isoformat()),
                }
            )
            merged["progress"] = progress
        merged["status"] = "running"
        merged["error"] = None
        merged["failure"] = None
        return merged

    if worker_status == "completed":
        merged["status"] = "completed"
        merged["completed_at"] = str(state.get("completed_at") or merged.get("completed_at") or datetime.now(UTC).isoformat())
        merged["error"] = None
        merged["failure"] = None
        if isinstance(state.get("stats"), dict):
            merged["stats"] = state["stats"]
        if isinstance(state.get("project_inventory"), dict):
            merged["project_inventory"] = state["project_inventory"]
        merged["progress"] = apply_progress_event(
            merged.get("progress"), verify, dependency_scan, "completed", 100, detail or "scan completed; report generated"
        )
        return merged

    state_failure = state.get("failure") if isinstance(state.get("failure"), dict) else {}
    if worker_status == "cancelled":
        public_error = user_error("SCAN_CANCELLED", reference=str(state_failure.get("diagnostic_id") or "") or None)
    else:
        public_error = user_error("SCAN_FAILED", reference=str(state_failure.get("diagnostic_id") or "") or None)
    error = public_error.message
    failure = failure_payload(public_error, stage=stage)
    merged["status"] = "failed"
    merged["completed_at"] = str(state.get("completed_at") or merged.get("completed_at") or datetime.now(UTC).isoformat())
    merged["error"] = error
    merged["failure"] = failure
    merged["progress"] = apply_progress_event(merged.get("progress"), verify, dependency_scan, "failed", 100, error)
    return merged


def normalize_run_failure(run: dict) -> dict:
    """Hide legacy/internal exception text while keeping old run files readable."""

    normalized = dict(run)
    if str(normalized.get("status") or "").lower() != "failed":
        return normalized
    existing_failure = normalized.get("failure") if isinstance(normalized.get("failure"), dict) else {}
    code = str(existing_failure.get("code") or "")
    if code not in {"SCAN_CANCELLED", "SCAN_FAILED", "SCAN_WORKER_START_FAILED", "SCAN_WORKER_EXITED"}:
        legacy_text = str(normalized.get("error") or "").lower()
        code = "SCAN_CANCELLED" if "cancel" in legacy_text or "取消" in legacy_text else "SCAN_FAILED"
    reference = str(existing_failure.get("diagnostic_id") or "").strip()
    if not reference:
        fingerprint = sha256_text(f"{normalized.get('id')}|{normalized.get('error')}")[:10].upper()
        reference = f"AFH-{fingerprint}"
    public_error = user_error(code, reference=reference)
    normalized["error"] = public_error.message
    normalized["failure"] = failure_payload(public_error, stage=str(existing_failure.get("stage") or "scan"))
    normalized["progress"] = apply_progress_event(
        normalized.get("progress"),
        str(normalized.get("verify") or "none"),
        bool(normalized.get("dependency_scan")),
        "failed",
        100,
        public_error.message,
    )
    return normalized


def repair_runs_index(workspace: Path, path: Path, runs: list[dict]) -> None:
    """Recover an unreadable run registry without discarding its original bytes."""

    if path.exists():
        backup = path.with_name(f"{path.stem}.corrupt{path.suffix}")
        if not backup.exists():
            try:
                shutil.copy2(path, backup)
            except OSError:
                pass
    workspace.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, {"runs": runs})
    invalidate_run_index_cache(workspace)


def merge_run_records(indexed_runs: list[dict], discovered_runs: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for run in discovered_runs:
        run_id = str(run.get("id") or "")
        if run_id:
            merged[run_id] = dict(run)
    for run in indexed_runs:
        run_id = str(run.get("id") or "")
        if not run_id:
            continue
        if run_id in merged:
            merged[run_id] = merge_run_record(run, merged[run_id])
        else:
            merged[run_id] = dict(run)
    return list(merged.values())


def merge_run_record(indexed: dict, discovered: dict) -> dict:
    merged = dict(discovered)
    for key, value in indexed.items():
        if has_meaningful_value(value):
            merged[key] = value
    merged.setdefault("workspace", f"{RUNS_DIR}/{merged.get('id')}")
    return merged


def has_meaningful_value(value) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def discover_run_directory_records(workspace: Path) -> list[dict]:
    runs_root = safe_child_path(workspace, RUNS_DIR)
    if not runs_root.exists() or not runs_root.is_dir():
        return []
    records: list[dict] = []
    for run_dir in sorted(runs_root.iterdir(), key=lambda item: item.name):
        if not run_dir.is_dir() or run_dir.is_symlink():
            continue
        if not is_discoverable_run_directory(run_dir):
            continue
        record = run_record_from_directory(workspace, run_dir)
        if record:
            records.append(record)
    return records


def is_discoverable_run_directory(run_dir: Path) -> bool:
    return any(
        (run_dir / name).exists()
        for name in (
            "scan_complete.json",
            "auditforge.db",
            "scan_metadata.json",
            "report.md",
            "report.html",
            "trace_candidates.json",
            "result_sections.json",
            "dependency_findings.json",
            WORKER_JOB_FILE,
            WORKER_STATE_FILE,
        )
    )


def run_record_from_directory(workspace: Path, run_dir: Path) -> dict | None:
    try:
        relative = run_dir.resolve().relative_to((workspace / RUNS_DIR).resolve())
    except ValueError:
        return None
    if len(relative.parts) != 1:
        return None
    run_id = relative.parts[0]
    metadata = read_json_file(run_dir / "scan_metadata.json", {})
    metadata = metadata if isinstance(metadata, dict) else {}
    completion = read_json_file(run_dir / "scan_complete.json", {})
    completion = completion if isinstance(completion, dict) else {}
    scan = read_run_summary(run_dir)

    stats = dict_value(metadata.get("stats"))
    if isinstance(scan, dict):
        db_stats = parse_json_value(scan.get("stats_json"), {})
        if isinstance(db_stats, dict) and db_stats:
            stats.update(db_stats)
    if dict_value(completion.get("stats")):
        stats = dict_value(completion.get("stats"))

    repo_path = str(completion.get("repo_path") or metadata.get("repo_path") or "")
    target_url = metadata.get("target_url")
    if isinstance(scan, dict):
        repo_path = str(scan.get("repo_path") or repo_path)
        target_url = scan.get("target_url") if scan.get("target_url") not in {None, ""} else target_url

    project_inventory = dict_value(metadata.get("project_inventory"))
    if not project_inventory:
        project_inventory = dict_value(read_json_file(run_dir / "project_inventory.json", {}))

    dependency_scan = bool(metadata.get("dependency_scan")) or has_dependency_evidence(run_dir, stats)
    deep_verify = has_deep_verification_evidence(run_dir, stats)
    verify = "deep" if deep_verify else ("safe" if int_value(stats.get("verification_results")) > 0 else "none")
    llm_metadata = metadata.get("llm") if isinstance(metadata.get("llm"), dict) else {}
    llm_enabled = bool(llm_metadata.get("enabled")) or has_llm_evidence(run_dir)
    generated_at = str(completion.get("completed_at") or metadata.get("generated_at") or "") or mtime_iso(run_dir)
    source_type = "upload" if repo_path and is_path_under(repo_path, workspace / REPOS_DIR) else "path"
    marker_path = run_dir / "scan_complete.json"
    marker_complete = bool(completion.get("completed_at"))
    legacy_complete = not marker_path.exists() and all(
        (run_dir / name).exists() for name in ("auditforge.db", "scan_metadata.json", "report.html")
    )
    completed = marker_complete or legacy_complete
    worker_state = read_worker_state(run_dir)
    worker_status = str(worker_state.get("status") or "").lower()
    if str(worker_state.get("run_id") or "") != run_id:
        worker_status = ""
    progress = apply_progress_event(
        initial_scan_progress(verify, dependency_scan, project_inventory),
        verify,
        dependency_scan,
        "completed" if completed or worker_status == "completed" else "failed",
        100,
        "扫描完成，历史记录已从结果目录恢复" if completed else "扫描目录不完整：缺少有效完成标记",
    )
    record = {
        "id": run_id,
        "name": recovered_run_name(run_id, repo_path),
        "status": "completed" if completed or worker_status == "completed" else "failed",
        "source_type": source_type,
        "source_label": Path(repo_path).name if repo_path else "",
        "repo_path": repo_path,
        "target_url": target_url,
        "verify": verify,
        "llm_enabled": llm_enabled,
        "deep_verify": deep_verify,
        "dependency_scan": dependency_scan,
        "workspace": f"{RUNS_DIR}/{run_id}",
        "created_at": generated_at,
        "completed_at": generated_at if completed or worker_status == "completed" else None,
        "stats": stats,
        "project_inventory": project_inventory,
        "error": None if completed or worker_status == "completed" else "incomplete scan artifacts; completion marker missing or invalid",
        "progress": progress,
    }
    if worker_status in {"starting", "running"}:
        record["status"] = "running"
        record["completed_at"] = None
        record["error"] = None
    return merge_worker_state(workspace, record)


def read_run_summary(run_dir: Path) -> dict | None:
    """Load only scan metadata while discovering every historical run."""

    if not (run_dir / "auditforge.db").exists():
        return None
    try:
        return read_dashboard_summary(run_dir).get("scan")
    except Exception:  # noqa: BLE001 - recovery must tolerate partial or old run artifacts
        return None


def parse_json_value(value, default):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value if value is not None else default


def dict_value(value) -> dict:
    return value if isinstance(value, dict) else {}


def int_value(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def has_dependency_evidence(run_dir: Path, stats: dict) -> bool:
    return (
        int_value(stats.get("dependency_manifests")) > 0
        or int_value(stats.get("dependencies")) > 0
        or int_value(stats.get("dependency_findings")) > 0
        or (run_dir / "dependency_inventory.json").exists()
        or (run_dir / "dependency_findings.json").exists()
    )


def has_deep_verification_evidence(run_dir: Path, stats: dict) -> bool:
    diagnostics = read_json_file(run_dir / "llm_diagnostics.json", {})
    deep = diagnostics.get("deep_verification") if isinstance(diagnostics, dict) else None
    return bool(deep) or int_value(stats.get("sandbox_executed")) > 0 or int_value(stats.get("sandbox_confirmed")) > 0


def has_llm_evidence(run_dir: Path) -> bool:
    diagnostics = read_json_file(run_dir / "llm_diagnostics.json", {})
    if not isinstance(diagnostics, dict):
        return False
    taint = diagnostics.get("llm") if isinstance(diagnostics.get("llm"), dict) else diagnostics
    return bool(taint.get("enabled") or taint.get("accepted") or taint.get("error"))


def is_path_under(value: str, root: Path) -> bool:
    try:
        Path(value).resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def recovered_run_name(run_id: str, repo_path: str) -> str:
    if repo_path:
        return f"恢复任务 · {Path(repo_path).name or run_id}"
    return f"恢复任务 · {run_id}"


def mtime_iso(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()
    except OSError:
        return datetime.now(UTC).isoformat()


def save_runs(workspace: Path, runs: list[dict]) -> None:
    with RUN_LOCK:
        workspace.mkdir(parents=True, exist_ok=True)
        atomic_write_json(runs_path(workspace), {"runs": drop_persisted_legacy_runs(runs)})
        invalidate_run_index_cache(workspace)


def drop_persisted_legacy_runs(runs: list[dict]) -> list[dict]:
    if not any(not is_legacy_run(run) for run in runs):
        return runs
    return [run for run in runs if not is_legacy_run(run)]


def is_legacy_run(run: dict) -> bool:
    return str(run.get("id") or "") == "legacy"


def infer_legacy_runs(workspace: Path) -> list[dict]:
    if not (workspace / "auditforge.db").exists():
        return []
    metadata = read_json_file(workspace / "scan_metadata.json", {})
    stats = metadata.get("stats") if isinstance(metadata, dict) else {}
    return [
        {
            "id": "legacy",
            "name": "当前工作区扫描",
            "status": "completed",
            "source_type": "workspace",
            "repo_path": metadata.get("repo_path", "") if isinstance(metadata, dict) else "",
            "target_url": metadata.get("target_url") if isinstance(metadata, dict) else None,
            "verify": "none",
            "llm_enabled": bool((metadata.get("llm") or {}).get("enabled")) if isinstance(metadata, dict) else False,
            "workspace": ".",
            "created_at": metadata.get("generated_at", "") if isinstance(metadata, dict) else "",
            "completed_at": metadata.get("generated_at", "") if isinstance(metadata, dict) else "",
            "stats": stats if isinstance(stats, dict) else {},
            "project_inventory": metadata.get("project_inventory", {}) if isinstance(metadata, dict) else {},
            "error": None,
        }
    ]


def list_runs(workspace: Path) -> list[dict]:
    return [public_run(run) for run in load_runs(workspace)]


def public_run(run: dict) -> dict:
    return redact_public_payload(normalize_run_failure(run))


def redact_public_payload(value):
    if isinstance(value, dict):
        redacted: dict = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if normalized_key in {"api_key", "response_file"}:
                continue
            if normalized_key.endswith("_url") or normalized_key in {"url", "base_url", "target_url"}:
                redacted[key] = redact_url(str(item or ""))
            else:
                redacted[key] = redact_public_payload(item)
        return redacted
    if isinstance(value, list):
        return [redact_public_payload(item) for item in value]
    if isinstance(value, tuple):
        return [redact_public_payload(item) for item in value]
    return value


def public_log_entry(entry: dict) -> dict:
    core_keys = {"sequence", "timestamp", "level", "event", "message"}
    result = {key: entry.get(key) for key in core_keys if key in entry}
    protected_keys = {"exception", "stack", "exc_info", "exc_text", "error_type"}
    context = {key: value for key, value in entry.items() if key not in core_keys and key != "context" and key not in protected_keys}
    existing_context = entry.get("context")
    if isinstance(existing_context, dict):
        context = {**existing_context, **context}
    elif existing_context is not None and existing_context != "":
        context["context"] = existing_context
    result["context"] = redact_public_payload(context)
    return result


def triage_path(run_workspace: Path) -> Path:
    return run_workspace.resolve() / TRIAGE_FILE


def load_triage_notes(run_workspace: Path) -> dict:
    path = triage_path(run_workspace)
    with locked_path(path):
        if not path.exists():
            return {"items": {}}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"items": {}}
    items = payload.get("items") if isinstance(payload, dict) else {}
    if not isinstance(items, dict):
        items = {}
    normalized: dict[str, dict] = {}
    for candidate_id, item in items.items():
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "needs_review")
        if status not in TRIAGE_STATUS_OPTIONS:
            status = "needs_review"
        normalized[str(candidate_id)] = {
            "candidate_id": str(candidate_id),
            "status": status,
            "note": clean_triage_note(item.get("note")),
            "updated_at": str(item.get("updated_at") or ""),
        }
    return {"items": normalized}


def save_candidate_triage(run_workspace: Path, payload: dict) -> dict:
    candidate_id = clean_label(str(payload.get("candidate_id") or ""))[:160]
    if not candidate_id:
        raise ValueError("candidate_id 不能为空")
    status = str(payload.get("status") or "needs_review")
    if status not in TRIAGE_STATUS_OPTIONS:
        raise ValueError("复核状态非法")
    item = {
        "candidate_id": candidate_id,
        "status": status,
        "note": clean_triage_note(payload.get("note")),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    path = triage_path(run_workspace)
    with locked_path(path):
        data = load_triage_notes(run_workspace)
        data.setdefault("items", {})[candidate_id] = item
        atomic_write_json(path, data)
    return item


def clean_triage_note(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:1000]


EXPORT_FILE_NAMES = {
    "scan_complete.json",
    "report.html",
    "report.md",
    "scan_metadata.json",
    "project_inventory.json",
    "analysis_coverage.json",
    "trace_candidates.json",
    "verification_plans.json",
    "verification_results.json",
    "dependency_inventory.json",
    "dependency_findings.json",
    "sbom.cdx.json",
    "llm_diagnostics.json",
    "code_graph.json",
    "auditforge.db",
    "result_sections.json",
    TRIAGE_FILE,
}
EXPORT_DIRECTORY_NAMES = {"result_sections", GRAPH_DIRECTORY}


def build_run_export_zip(run_workspace: Path, run: dict) -> bytes:
    run_workspace = run_workspace.resolve()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "run_metadata.json",
            json.dumps(public_run(run), indent=2, ensure_ascii=False),
        )
        for path in exportable_run_files(run_workspace):
            archive.write(path, normalize_export_arcname(run_workspace, path))
    return buffer.getvalue()


def exportable_run_files(run_workspace: Path) -> list[Path]:
    files: list[Path] = []
    if not run_workspace.exists():
        return files
    for name in sorted(EXPORT_FILE_NAMES):
        path = (run_workspace / name).resolve()
        if is_safe_export_file(run_workspace, path):
            files.append(path)
    for directory_name in sorted(EXPORT_DIRECTORY_NAMES):
        directory = (run_workspace / directory_name).resolve()
        if directory.exists() and directory.is_dir():
            for path in sorted(directory.rglob("*")):
                resolved = path.resolve()
                if is_safe_export_file(run_workspace, resolved):
                    files.append(resolved)
    return files


def parse_graph_page_query(raw_query: str) -> dict:
    query = parse_qs(raw_query, keep_blank_values=False, max_num_fields=6)
    kind = str((query.get("kind") or ["nodes"])[0]).strip().lower()
    file_path = str((query.get("file") or [""])[0]).strip() or None
    try:
        offset = int((query.get("offset") or ["0"])[0])
        limit = int((query.get("limit") or ["200"])[0])
    except (TypeError, ValueError) as exc:
        raise ValueError("graph offset and limit must be integers") from exc
    if offset < 0 or limit < 1:
        raise ValueError("graph offset must be non-negative and limit must be positive")
    if file_path and len(file_path) > 1200:
        raise ValueError("graph file filter is too long")
    return {"kind": kind, "offset": offset, "limit": limit, "file_path": file_path}


def is_safe_export_file(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return path.is_file() and not path.is_symlink()


def normalize_export_arcname(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    parts = [safe_filename(part) for part in relative.parts if part not in {"", ".", ".."}]
    return "/".join(parts)


def find_run(workspace: Path, run_id: str) -> dict | None:
    indexed_run = indexed_run_record(workspace, run_id)
    if indexed_run is not None:
        return normalize_run_failure(merge_worker_state(workspace, indexed_run))
    for run in load_runs(workspace):
        if str(run.get("id")) == run_id:
            return run
    return None


def update_run(workspace: Path, run_id: str, **changes) -> dict:
    with RUN_LOCK, locked_path(runs_path(workspace)):
        runs = load_runs(workspace)
        for index, run in enumerate(runs):
            if run.get("id") == run_id:
                run.update(changes)
                runs[index] = run
                save_runs(workspace, runs)
                return run
        raise ValueError(f"scan run not found: {run_id}")


def delete_scan_run(workspace: Path, run_id: str) -> dict:
    with RUN_LOCK, locked_path(runs_path(workspace)):
        runs = load_runs(workspace)
        selected_index = next((index for index, run in enumerate(runs) if str(run.get("id")) == run_id), None)
        if selected_index is None:
            raise LookupError("扫描任务不存在")
        run = runs[selected_index]
        if str(run.get("id")) == "legacy":
            raise ValueError("legacy 工作区不能从历史列表删除")
        if str(run.get("status") or "") == "running":
            raise ValueError("扫描任务仍在运行，完成后再删除")

        removed: list[str] = []
        for target in cleanup_targets_for_run(workspace, run):
            if remove_workspace_artifact(workspace, target):
                removed.append(str(target.resolve()))

        remaining = [item for index, item in enumerate(runs) if index != selected_index]
        save_runs(workspace, remaining)
        return {"run": run, "removed": removed}


def worker_pid_is_alive(state: dict) -> bool:
    """Return whether the PID recorded by an isolated worker is still alive."""

    try:
        pid = int(state.get("pid") or 0)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        # Unlike POSIX, ``os.kill(pid, 0)`` is not a harmless probe on
        # Windows: it maps to TerminateProcess and can kill the scan worker.
        process_query_limited_information = 0x1000
        still_active = 259
        handle = ctypes.windll.kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            # Access denied normally means the process exists at another
            # integrity level; conservatively keep the task active.
            return ctypes.get_last_error() == 5
        try:
            exit_code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == still_active
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # The worker can be owned by a different integrity level on Windows;
        # lack of permission is still evidence that the process exists.
        return True
    except OSError:
        return False
    return True


def worker_startup_in_progress(state: dict) -> bool:
    """Allow the tiny interval before a freshly spawned worker records its PID."""

    if str(state.get("status") or "").lower() != "starting":
        return False
    try:
        updated_at = datetime.fromisoformat(str(state.get("updated_at") or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=UTC)
    return (datetime.now(UTC) - updated_at).total_seconds() <= WORKER_STARTUP_GRACE_SECONDS


def active_worker_count(workspace: Path) -> int:
    """Count live isolated workers, including workers started before a restart."""

    with RUN_LOCK:
        runs = _load_runs_unlocked(workspace)
    return sum(
        1
        for run in runs
        if str(run.get("status") or "") == "running"
        and str((state := worker_state_for_run(workspace, run)).get("status") or "") in {"starting", "running"}
        and (worker_pid_is_alive(state) or worker_startup_in_progress(state))
    )


def request_worker_termination(state: dict) -> None:
    """Best-effort termination after the durable cancellation marker is written."""

    try:
        pid = int(state.get("pid") or 0)
    except (TypeError, ValueError):
        return
    if pid <= 0 or not worker_pid_is_alive(state):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        # The marker is still sufficient for a cooperative cancellation when
        # the next pipeline progress callback runs.
        return


def cancel_scan_run(workspace: Path, run_id: str) -> dict:
    """Cancel an active isolated scan and expose a terminal failed task state."""

    terminal_at = datetime.now(UTC).isoformat()
    public_error = user_error("SCAN_CANCELLED")
    reason = public_error.message
    worker_state: dict = {}
    with RUN_LOCK, locked_path(runs_path(workspace)):
        runs = _load_runs_unlocked(workspace)
        selected_index = next((index for index, item in enumerate(runs) if str(item.get("id")) == run_id), None)
        if selected_index is None:
            raise LookupError("scan run not found")
        run = runs[selected_index]
        if str(run.get("status") or "") != "running":
            raise ValueError("scan task is not running")

        run_dir = run_workspace_path(workspace, run)
        worker_state = worker_state_for_run(workspace, run)
        atomic_write_json(
            cancel_request_path(run_dir),
            {"requested_at": terminal_at, "reason": reason, "run_id": run_id},
        )
        write_worker_state(
            run_dir,
            {
                **worker_state,
                "run_id": run_id,
                "status": "cancelled",
                "completed_at": terminal_at,
                "error": reason,
                "failure": failure_payload(public_error, stage="cancelled"),
            },
        )
        verify = str(run.get("verify") or "none")
        dependency_scan = bool(run.get("dependency_scan"))
        run.update(
            {
                "status": "failed",
                "completed_at": terminal_at,
                "error": reason,
                "failure": failure_payload(public_error, stage="cancelled"),
                "progress": apply_progress_event(run.get("progress"), verify, dependency_scan, "failed", 100, reason),
            }
        )
        runs[selected_index] = run
        save_runs(workspace, runs)
    request_worker_termination(worker_state)
    return run


def cleanup_targets_for_run(workspace: Path, run: dict) -> list[Path]:
    targets = [run_workspace_path(workspace, run)]
    run_id = str(run.get("id") or "")
    if str(run.get("source_type") or "") == "upload" and run_id:
        targets.append(safe_child_path(workspace, f"{REPOS_DIR}/{run_id}"))
        upload_dir = safe_child_path(workspace, UPLOADS_DIR)
        if upload_dir.exists():
            targets.extend(upload_dir.glob(f"{run_id}-*"))
    return dedupe_paths(targets)


def dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    deduped: list[Path] = []
    for path in paths:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def remove_workspace_artifact(workspace: Path, target: Path) -> bool:
    root = workspace.resolve()
    resolved = target.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"拒绝删除平台工作区外的路径：{resolved}") from exc
    if resolved == root:
        raise ValueError("拒绝删除平台工作区根目录")
    if not resolved.exists() and not resolved.is_symlink():
        return False
    if resolved.is_symlink() or resolved.is_file():
        resolved.unlink()
    elif resolved.is_dir():
        shutil.rmtree(resolved)
    else:
        resolved.unlink(missing_ok=True)
    return True


def run_workspace_path(workspace: Path, run: dict) -> Path:
    relative = str(run.get("workspace") or f"{RUNS_DIR}/{run.get('id')}")
    return safe_child_path(workspace, relative)


def enabled_llm_config(config: LLMConfig) -> LLMConfig:
    return LLMConfig(
        enabled=True,
        provider=config.provider,
        model=config.model,
        base_url=config.base_url,
        api_key=config.api_key,
        api_key_env=config.api_key_env,
        response_file=config.response_file,
        timeout_seconds=config.timeout_seconds,
        max_prompt_chars=config.max_prompt_chars,
        max_candidates=config.max_candidates,
        concurrency=config.concurrency,
        system_prompt=config.system_prompt,
        user_prompt=config.user_prompt,
    )


def create_scan_run(
    workspace: Path,
    form: dict[str, object],
    *,
    allowed_repo_roots: tuple[Path, ...] | None = None,
) -> dict:
    prepared = prepare_scan_run(workspace, form, allowed_repo_roots=allowed_repo_roots)
    return execute_scan_run(workspace, prepared)


def start_scan_run(
    workspace: Path,
    form: dict[str, object],
    *,
    scan_semaphore: threading.BoundedSemaphore | None = None,
    max_scan_concurrency: int | None = None,
    allowed_repo_roots: tuple[Path, ...] | None = None,
) -> dict:
    limiter = scan_semaphore or DEFAULT_SCAN_SEMAPHORE
    if max_scan_concurrency is not None and active_worker_count(workspace) >= max(1, int(max_scan_concurrency)):
        raise UserFacingError("SCAN_CONCURRENCY_LIMIT")
    if not limiter.acquire(blocking=False):
        raise UserFacingError("SCAN_CONCURRENCY_LIMIT")
    try:
        prepared = prepare_scan_run(workspace, form, allowed_repo_roots=allowed_repo_roots)
    except Exception:
        limiter.release()
        raise
    try:
        process = start_scan_worker(workspace, prepared)
    except Exception as exc:
        limiter.release()
        reference = new_reference("AFW")
        public_error = user_error("SCAN_WORKER_START_FAILED", reference=reference)
        progress = apply_progress_event(
            prepared["run"].get("progress"),
            str(prepared.get("verify") or "none"),
            bool(prepared.get("dependency_scan")),
            "failed",
            100,
            public_error.message,
        )
        update_run(
            workspace,
            str(prepared["run_id"]),
            status="failed",
            completed_at=datetime.now(UTC).isoformat(),
            error=public_error.message,
            failure=failure_payload(public_error, stage="starting"),
            progress=progress,
        )
        raise UserFacingError("SCAN_WORKER_START_FAILED", reference=reference) from exc
    thread = threading.Thread(
        target=_wait_for_worker_release,
        args=(workspace, str(prepared["run_id"]), process, limiter),
        name=f"auditforge-worker-watch-{prepared['run']['id']}",
        daemon=True,
    )
    thread.start()
    return dict(prepared["run"])


def start_scan_worker(workspace: Path, prepared: dict) -> subprocess.Popen:
    """Start a scan in a separate interpreter without serialising API secrets."""

    run_dir = Path(prepared["run_dir"])
    run_id = str(prepared["run_id"])
    job_path = write_worker_job(run_dir, scan_job_payload(workspace, prepared))
    write_worker_state(
        run_dir,
        {
            "run_id": run_id,
            "status": "starting",
            "started_at": datetime.now(UTC).isoformat(),
            "progress": {"stage": "queued", "percent": 0, "detail": "独立扫描进程正在启动"},
            "error": None,
            "failure": None,
        },
    )
    stdout_path = run_dir / WORKER_STDOUT_FILE
    stderr_path = run_dir / WORKER_STDERR_FILE
    environment = dict(os.environ)
    environment["PYTHONUNBUFFERED"] = "1"
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
        process = subprocess.Popen(
            [sys.executable, "-m", "auditforge.web.scan_worker", "--job", str(job_path)],
            cwd=str(Path(__file__).resolve().parents[2]),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=environment,
            creationflags=creationflags,
        )
    return process


def _wait_for_worker_release(
    workspace: Path,
    run_id: str,
    process: subprocess.Popen,
    limiter: threading.BoundedSemaphore,
) -> None:
    try:
        process.wait()
        reconcile_worker_runs(workspace)
    finally:
        limiter.release()


def prepare_scan_run(
    workspace: Path,
    form: dict[str, object],
    *,
    allowed_repo_roots: tuple[Path, ...] | None = None,
) -> dict:
    run_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    source_type = str(first_form_value(form, "sourceType", "path"))
    if source_type not in {"path", "upload"}:
        raise ValueError("sourceType must be path or upload")
    run_name = clean_label(str(first_form_value(form, "name", ""))) or f"扫描 {run_id}"
    verify = str(first_form_value(form, "verify", "none"))
    verify = verify if verify in {"none", "safe", "stateful", "deep", "safe+deep", "stateful+deep"} else "none"
    target_url = clean_optional(str(first_form_value(form, "targetUrl", "")))
    if target_url:
        target_url = validate_target_url(target_url)
    use_llm = parse_bool(first_form_value(form, "useLlm", "false"))
    scan_dependencies = parse_bool(first_form_value(form, "scanDependencies", "false"))
    run_dir = safe_child_path(workspace, f"{RUNS_DIR}/{run_id}")

    repo_path: Path
    source_label = ""
    if source_type == "upload":
        upload = first_form_file(form, "repoZip")
        if not upload:
            raise ValueError("请上传 zip 格式的代码包")
        filename, content = upload
        if not filename.lower().endswith(".zip"):
            raise ValueError("目前 Web 扫描只支持 zip 代码包")
        upload_path = safe_child_path(workspace, f"{UPLOADS_DIR}/{run_id}-{safe_filename(filename)}")
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        destination = safe_child_path(workspace, f"{REPOS_DIR}/{run_id}")
        try:
            upload_path.write_bytes(content)
            repo_path = extract_uploaded_zip(upload_path, destination)
        except Exception:
            upload_path.unlink(missing_ok=True)
            if destination.exists():
                shutil.rmtree(destination, ignore_errors=True)
            shutil.rmtree(run_dir, ignore_errors=True)
            raise
        source_label = filename
    else:
        repo_raw = clean_optional(str(first_form_value(form, "repoPath", "")))
        if not repo_raw:
            raise ValueError("请填写本地代码仓库路径，或切换为上传 zip")
        roots = configured_repo_roots(workspace) if allowed_repo_roots is None else allowed_repo_roots
        repo_path = validate_repo_path(repo_raw, roots)
        if not repo_path.exists() or not repo_path.is_dir():
            raise ValueError(f"代码仓库路径不存在或不是目录：{repo_path}")
        source_label = str(repo_path)

    run_dir.mkdir(parents=True, exist_ok=False)
    workspace_settings = load_workspace_settings(workspace) if use_llm or "deep" in verify or scan_dependencies else {}
    saved_taint_config = llm_config_from_settings(workspace_settings, profile="taint") if use_llm else LLMConfig(enabled=False)
    saved_deep_config = llm_config_from_settings(workspace_settings, profile="deep") if "deep" in verify else LLMConfig(enabled=False)
    saved_dependency_config = (
        llm_config_from_settings(workspace_settings, profile="dependency") if scan_dependencies else LLMConfig(enabled=False)
    )
    llm_config = enabled_llm_config(saved_taint_config) if use_llm else LLMConfig(enabled=False)
    deep_llm_config = enabled_llm_config(saved_deep_config) if "deep" in verify else LLMConfig(enabled=False)
    dependency_llm_config = enabled_llm_config(saved_dependency_config) if scan_dependencies else LLMConfig(enabled=False)
    sandbox_concurrency = sandbox_concurrency_from_settings(workspace_settings, deep_llm_config.concurrency)

    run = {
        "id": run_id,
        "name": run_name,
        "status": "running",
        "source_type": source_type,
        "source_label": source_label,
        "repo_path": str(repo_path),
        "target_url": target_url,
        "verify": verify,
        "llm_enabled": use_llm,
        "deep_verify": "deep" in verify,
        "sandbox_concurrency": sandbox_concurrency,
        "dependency_scan": scan_dependencies,
        "scan_config": build_scan_config_snapshot(
            verify=verify,
            dependency_scan=scan_dependencies,
            taint_config=llm_config,
            dependency_config=dependency_llm_config,
            deep_config=deep_llm_config,
            sandbox_concurrency=sandbox_concurrency,
        ),
        "workspace": f"{RUNS_DIR}/{run_id}",
        "created_at": datetime.now(UTC).isoformat(),
        "completed_at": None,
        "stats": {},
        "project_inventory": {},
        "error": None,
        "progress": initial_scan_progress(verify, scan_dependencies),
    }
    with RUN_LOCK, locked_path(runs_path(workspace)):
        runs = load_runs(workspace)
        runs.insert(0, run)
        save_runs(workspace, runs)
    return {
        "run": run,
        "run_id": run_id,
        "run_dir": run_dir,
        "repo_path": repo_path,
        "target_url": target_url,
        "verify": verify,
        "project_inventory": None,
        "llm_config": llm_config,
        "deep_llm_config": deep_llm_config,
        "dependency_scan": scan_dependencies,
        "dependency_llm_config": dependency_llm_config,
        "sandbox_concurrency": sandbox_concurrency,
    }


def build_scan_config_snapshot(
    *,
    verify: str,
    dependency_scan: bool,
    taint_config: LLMConfig,
    dependency_config: LLMConfig,
    deep_config: LLMConfig,
    sandbox_concurrency: int | None = None,
) -> dict:
    return {
        "verify": verify,
        "dependency_scan": dependency_scan,
        "sandbox_concurrency": int(sandbox_concurrency or deep_config.concurrency),
        "profiles": {
            "taint": llm_profile_snapshot(taint_config),
            "dependency": llm_profile_snapshot(dependency_config),
            "deep": llm_profile_snapshot(deep_config),
        },
    }


def llm_profile_snapshot(config: LLMConfig) -> dict:
    return {
        "enabled": bool(config.enabled),
        "provider": config.provider,
        "model": config.model,
        "base_url": redact_base_url(config.base_url),
        "api_key_env": config.api_key_env,
        "response_file": bool(config.response_file),
        "timeout_seconds": int(config.timeout_seconds),
        "max_candidates": int(config.max_candidates),
        "concurrency": int(config.concurrency),
        "system_prompt": prompt_fingerprint(config.system_prompt),
        "user_prompt": prompt_fingerprint(config.user_prompt),
    }


def prompt_fingerprint(value: str | None) -> dict:
    text = str(value or "")
    return {
        "length": len(text),
        "sha256": sha256_text(text)[:12] if text else "",
    }


def redact_base_url(value: str | None) -> str:
    return redact_url(value)


def execute_scan_run(workspace: Path, prepared: dict) -> dict:
    run_id = str(prepared["run_id"])
    verify = str(prepared["verify"])
    dependency_scan = bool(prepared.get("dependency_scan"))
    logger = contextual_logger(LOGGER, component="web-scan", workspace=str(workspace.resolve()), run_id=run_id)
    try:
        result = run_scan(
            prepared["repo_path"],
            prepared["run_dir"],
            target_url=prepared["target_url"],
            verify=verify,
            llm_config=prepared["llm_config"],
            deep_llm_config=prepared["deep_llm_config"],
            dependency_scan=dependency_scan,
            dependency_llm_config=prepared["dependency_llm_config"],
            sandbox_concurrency=prepared.get("sandbox_concurrency"),
            project_inventory=prepared.get("project_inventory"),
            progress_callback=make_scan_progress_callback(workspace, run_id, verify, dependency_scan),
        )
        current_run = find_run(workspace, run_id)
        progress = apply_progress_event(
            current_run.get("progress") if current_run else None, verify, dependency_scan, "completed", 100, "扫描完成，报告已生成"
        )
        run = update_run(
            workspace,
            run_id,
            status="completed",
            completed_at=datetime.now(UTC).isoformat(),
            stats=result.stats(),
            project_inventory=result.project_inventory,
            error=None,
            progress=progress,
        )
        logger.info("scan completed", extra={"event": "scan.completed", "stats": result.stats()})
    except Exception as exc:  # noqa: BLE001 - keep failed scans visible in history
        reference = new_reference("AFS")
        public_error = classify_error(exc, context="scan", reference=reference)
        current_run = find_run(workspace, run_id)
        progress = apply_progress_event(
            current_run.get("progress") if current_run else None, verify, dependency_scan, "failed", 100, public_error.message
        )
        run = update_run(
            workspace,
            run_id,
            status="failed",
            completed_at=datetime.now(UTC).isoformat(),
            error=public_error.message,
            failure=failure_payload(public_error, stage=str(progress.get("phase") or "scan")),
            progress=progress,
        )
        logger.exception(
            "scan failed",
            extra={"event": "scan.failed", "error_type": type(exc).__name__, "reference": reference},
        )
    return run


def make_scan_progress_callback(workspace: Path, run_id: str, verify: str, dependency_scan: bool):
    logger = contextual_logger(LOGGER, component="web-scan", workspace=str(workspace.resolve()), run_id=run_id)

    def callback(stage: str, percent: int, message: str) -> None:
        update_run_progress(
            workspace, run_id, lambda progress: apply_progress_event(progress, verify, dependency_scan, stage, percent, message)
        )
        logger.info(
            "scan progress",
            extra={
                "event": "scan.progress",
                "stage": stage,
                "percent": max(0, min(100, int(percent))),
                "detail": message,
            },
        )

    return callback


def update_run_progress(workspace: Path, run_id: str, updater) -> dict:
    with RUN_LOCK, locked_path(runs_path(workspace)):
        runs = load_runs(workspace)
        for index, run in enumerate(runs):
            if str(run.get("id")) == run_id:
                run["progress"] = updater(run.get("progress"))
                runs[index] = run
                save_runs(workspace, runs)
                return run
    raise ValueError(f"scan run not found: {run_id}")


def recover_interrupted_runs(workspace: Path) -> int:
    """Recover only orphaned scans; independent live workers survive restarts."""

    return reconcile_worker_runs(
        workspace,
        orphan_reason="Dashboard 重启时扫描尚未完成，任务已中止。",
    )


def reconcile_worker_runs(
    workspace: Path,
    *,
    orphan_reason: str = "独立扫描进程在任务完成前退出。",
) -> int:
    """Persist terminal worker results and mark only truly abandoned runs failed.

    ``worker_state.json`` is the live source of truth.  A Dashboard restart
    must not invalidate a worker that is still running in a separate process,
    while an old thread-backed run or a dead worker should retain the historic
    failure behaviour rather than blocking the scan queue forever.
    """

    orphan_reason = str(orphan_reason or "独立扫描进程在任务完成前退出。")[:1000]
    recovered = 0
    changed = False
    with RUN_LOCK, locked_path(runs_path(workspace)):
        runs = _load_runs_unlocked(workspace)
        for index, run in enumerate(runs):
            state = worker_state_for_run(workspace, run)
            worker_status = str(state.get("status") or "").lower()
            if worker_status in {"completed", "failed", "cancelled"}:
                # _load_runs_unlocked already overlays terminal state.  Save it
                # once here so it remains visible even if the state file is
                # later cleaned up by an operator.
                runs[index] = merge_worker_state(workspace, run)
                changed = True
                continue
            if str(run.get("status") or "") != "running":
                continue
            if worker_status in {"starting", "running"} and (worker_pid_is_alive(state) or worker_startup_in_progress(state)):
                continue

            verify = str(run.get("verify") or "none")
            dependency_scan = bool(run.get("dependency_scan"))
            public_error = user_error("SCAN_WORKER_EXITED")
            reason = public_error.message
            state_progress = state.get("progress") if isinstance(state.get("progress"), dict) else {}
            failure = failure_payload(public_error, stage=str(state_progress.get("stage") or "worker"))
            LOGGER.warning(
                "orphaned scan marked failed",
                extra={
                    "event": "scan.worker_orphaned",
                    "run_id": run.get("id"),
                    "reference": public_error.reference,
                    "reason": orphan_reason,
                },
            )
            run.update(
                {
                    "status": "failed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "error": reason,
                    "failure": failure,
                    "progress": apply_progress_event(run.get("progress"), verify, dependency_scan, "failed", 100, reason),
                }
            )
            runs[index] = run
            recovered += 1
            changed = True
        if changed:
            save_runs(workspace, runs)
    return recovered


def stop_running_runs(workspace: Path, reason: str = "扫描任务已由用户停止。") -> int:
    """Mark active runs as stopped after their worker process has been terminated."""

    public_error = user_error("SCAN_CANCELLED")
    reason = str(reason or public_error.message)[:1000]
    recovered = 0
    with RUN_LOCK, locked_path(runs_path(workspace)):
        runs = load_runs(workspace)
        for index, run in enumerate(runs):
            if str(run.get("status") or "") != "running":
                continue
            verify = str(run.get("verify") or "none")
            dependency_scan = bool(run.get("dependency_scan"))
            run["status"] = "failed"
            run["completed_at"] = datetime.now(UTC).isoformat()
            run["error"] = reason
            run["failure"] = failure_payload(public_error, stage="cancelled")
            run["progress"] = apply_progress_event(run.get("progress"), verify, dependency_scan, "failed", 100, reason)
            runs[index] = run
            recovered += 1
        if recovered:
            save_runs(workspace, runs)
    return recovered


def initial_scan_progress(verify: str, dependency_scan: bool = False, project_inventory: dict | None = None) -> dict:
    verification_status = "pending" if verify != "none" else "skipped"
    verification_detail = "等待候选路径生成完成" if verify != "none" else "未启用二次验证"
    inventory_done = bool(project_inventory)
    stages = [
        {
            "id": "inventory",
            "label": "项目盘点",
            "status": "completed" if inventory_done else "pending",
            "percent": 100 if inventory_done else 0,
            "detail": inventory_summary(project_inventory) if inventory_done else "等待统计代码规模与语言分布",
        },
        {
            "id": "candidate",
            "label": "首次候选生成",
            "status": "pending",
            "percent": 0,
            "detail": "等待项目盘点完成后索引源码并生成 source-to-sink 候选",
        },
    ]
    if dependency_scan:
        stages.append(
            {
                "id": "dependencies",
                "label": "LLM 依赖风险扫描",
                "status": "pending",
                "percent": 0,
                "detail": "等待候选路径生成完成后解析依赖清单",
            }
        )
    stages.append(
        {
            "id": "verification",
            "label": verification_stage_label(verify),
            "status": verification_status,
            "percent": 100 if verify == "none" else 0,
            "detail": verification_detail,
        }
    )
    return {
        "phase": "queued",
        "percent": overall_progress_percent(stages, verify, dependency_scan),
        "detail": f"项目盘点完成：{inventory_summary(project_inventory)}" if inventory_done else "任务已创建，等待扫描启动",
        "updated_at": datetime.now(UTC).isoformat(),
        "stages": stages,
    }


def verification_stage_label(verify: str) -> str:
    if "deep" in verify and ("safe" in verify or "stateful" in verify):
        return "safe + 沙箱组合验证"
    if verify == "deep":
        return "二次深入验证"
    if verify == "safe":
        return "safe 受控验证"
    if verify == "stateful":
        return "stateful 隔离靶场验证"
    return "二次验证"


def apply_progress_event(progress: object, verify: str, dependency_scan: bool, stage: str, percent: int, message: str) -> dict:
    data = normalize_progress(progress, verify, dependency_scan)
    stages = {str(item.get("id")): item for item in data["stages"] if isinstance(item, dict)}
    inventory = stages["inventory"]
    candidate = stages["candidate"]
    dependencies = stages.get("dependencies")
    verification = stages["verification"]
    percent = max(0, min(100, int(percent)))

    if stage == "inventory":
        inventory["percent"] = percent
        inventory["status"] = "completed" if percent >= 100 else "running"
        inventory["detail"] = message
    elif stage == "candidate":
        inventory["percent"] = 100
        inventory["status"] = "completed"
        candidate["percent"] = percent
        candidate["status"] = "completed" if percent >= 100 else "running"
        candidate["detail"] = message
        if verify != "none" and verification.get("status") == "skipped":
            verification["status"] = "pending"
            verification["percent"] = 0
    elif stage == "dependencies" and dependencies:
        inventory["percent"] = 100
        inventory["status"] = "completed"
        candidate["percent"] = 100
        candidate["status"] = "completed"
        dependencies["percent"] = percent
        dependencies["status"] = "completed" if percent >= 100 else "running"
        dependencies["detail"] = message
    elif stage == "verification":
        inventory["percent"] = 100
        inventory["status"] = "completed"
        candidate["percent"] = 100
        candidate["status"] = "completed"
        if dependencies:
            dependencies["percent"] = 100
            dependencies["status"] = "completed"
        verification["percent"] = percent
        verification["status"] = "completed" if percent >= 100 else "running"
        verification["detail"] = message
    elif stage == "verification_skipped":
        inventory["percent"] = 100
        inventory["status"] = "completed"
        candidate["percent"] = 100
        candidate["status"] = "completed"
        if dependencies:
            dependencies["percent"] = 100
            dependencies["status"] = "completed"
        verification["percent"] = 100
        verification["status"] = "skipped"
        verification["detail"] = message
    elif stage == "completed":
        inventory["percent"] = 100
        inventory["status"] = "completed"
        candidate["percent"] = 100
        candidate["status"] = "completed"
        if dependencies:
            dependencies["percent"] = 100
            dependencies["status"] = "completed"
            dependencies["detail"] = dependencies.get("detail") or "依赖扫描完成"
        verification["percent"] = 100
        verification["status"] = "skipped" if verify == "none" else "completed"
        verification["detail"] = verification.get("detail") or ("未启用二次验证" if verify == "none" else "验证完成")
    elif stage == "failed":
        active = (
            verification
            if verification.get("status") == "running"
            else (dependencies if dependencies and dependencies.get("status") == "running" else candidate)
        )
        active["status"] = "failed"
        active["detail"] = message
    data["phase"] = stage
    data["detail"] = message
    data["percent"] = overall_progress_percent(data["stages"], verify, dependency_scan)
    data["updated_at"] = datetime.now(UTC).isoformat()
    return data


def normalize_progress(progress: object, verify: str, dependency_scan: bool = False) -> dict:
    if not isinstance(progress, dict):
        return initial_scan_progress(verify, dependency_scan)
    base = initial_scan_progress(verify, dependency_scan)
    stages_by_id = {str(item.get("id")): item for item in base["stages"]}
    stage_items = progress.get("stages", [])
    if not isinstance(stage_items, list):
        stage_items = []
    provided_stage_ids = {str(item.get("id")) for item in stage_items if isinstance(item, dict)}
    for item in stage_items:
        if isinstance(item, dict) and item.get("id") in stages_by_id:
            stages_by_id[str(item["id"])].update(item)
    base.update({key: value for key, value in progress.items() if key != "stages"})
    base["stages"] = [stage for stage in base["stages"] if str(stage.get("id")) in stages_by_id]
    if "inventory" not in provided_stage_ids and str(base.get("phase") or "") != "queued":
        stages_by_id["inventory"].update(
            {
                "status": "completed",
                "percent": 100,
                "detail": "该历史任务未保存盘点明细",
            }
        )
    return base


def overall_progress_percent(stages: list[dict], verify: str, dependency_scan: bool = False) -> int:
    stage_map = {str(item.get("id")): item for item in stages}
    inventory = int(stage_map.get("inventory", {}).get("percent") or 0)
    candidate = int(stage_map.get("candidate", {}).get("percent") or 0)
    dependencies = int(stage_map.get("dependencies", {}).get("percent") or 0)
    verification = int(stage_map.get("verification", {}).get("percent") or 0)
    if dependency_scan and verify != "none":
        return min(100, round(inventory * 0.08 + candidate * 0.48 + dependencies * 0.19 + verification * 0.25))
    if dependency_scan:
        return min(100, round(inventory * 0.08 + candidate * 0.55 + dependencies * 0.37))
    if verify == "none":
        return min(100, round(inventory * 0.10 + candidate * 0.90))
    return min(100, round(inventory * 0.08 + candidate * 0.57 + verification * 0.35))


def enforce_global_body_limit(handler: BaseHTTPRequestHandler, maximum: int) -> None:
    if handler.headers.get("Transfer-Encoding"):
        raise ValueError("Transfer-Encoding is not supported")
    raw = handler.headers.get("Content-Length")
    if raw is None:
        return
    try:
        length = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid Content-Length") from exc
    if length < 0 or length > maximum:
        raise ValueError(f"request body exceeds the {maximum} byte limit")


def request_content_length(handler: BaseHTTPRequestHandler, maximum: int) -> int:
    if handler.headers.get("Transfer-Encoding"):
        raise ValueError("Transfer-Encoding is not supported")
    raw = handler.headers.get("Content-Length")
    if raw is None:
        raise ValueError("Content-Length is required")
    try:
        length = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid Content-Length") from exc
    if length <= 0:
        raise ValueError("request body cannot be empty")
    if length > maximum:
        raise ValueError(f"request body exceeds the {maximum} byte limit")
    return length


def read_json_request(handler: BaseHTTPRequestHandler, *, max_bytes: int = MAX_JSON_BODY_BYTES) -> dict:
    media_type = str(handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise ValueError("Content-Type must be application/json")
    length = request_content_length(handler, max_bytes)
    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise ValueError("incomplete request body")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("request body must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON request body must be an object")
    return payload


def parse_multipart_form(handler: BaseHTTPRequestHandler) -> dict[str, object]:
    content_type = str(handler.headers.get("Content-Type") or "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type != "multipart/form-data" or "boundary=" not in content_type.lower():
        raise ValueError("Content-Type must be multipart/form-data with a boundary")
    length = request_content_length(handler, MAX_UPLOAD_BYTES)
    body = handler.rfile.read(length)
    if len(body) != length:
        raise ValueError("incomplete request body")
    message = BytesParser(policy=email.policy.default).parsebytes(b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n" + body)
    form: dict[str, object] = {}
    for index, part in enumerate(message.iter_parts(), start=1):
        if index > MAX_MULTIPART_PARTS:
            raise ValueError(f"multipart form exceeds the {MAX_MULTIPART_PARTS} part limit")
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename:
            form[name] = (filename, payload)
        else:
            if len(payload) > MAX_FORM_FIELD_BYTES:
                raise ValueError(f"multipart field {name!r} is too large")
            form.setdefault(name, []).append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    return form


def first_form_value(form: dict[str, object], key: str, default: str = "") -> object:
    value = form.get(key)
    if isinstance(value, list):
        return value[0] if value else default
    if isinstance(value, tuple):
        return default
    return value if value is not None else default


def first_form_file(form: dict[str, object], key: str) -> tuple[str, bytes] | None:
    value = form.get(key)
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[1], bytes):
        return str(value[0]), value[1]
    return None


def extract_uploaded_zip(zip_path: Path, destination: Path) -> Path:
    destination = destination.resolve()
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=False)
    extracted_bytes = 0
    try:
        with zipfile.ZipFile(zip_path) as archive:
            all_infos = archive.infolist()
            if len(all_infos) > MAX_ZIP_ENTRIES:
                raise ValueError(f"zip entry count exceeds limit: {MAX_ZIP_ENTRIES}")
            files = [info for info in all_infos if not info.is_dir()]
            if len(files) > MAX_ZIP_FILES:
                raise ValueError(f"zip file count exceeds limit: {MAX_ZIP_FILES}")
            total_uncompressed = sum(max(0, info.file_size) for info in files)
            total_compressed = sum(max(0, info.compress_size) for info in files)
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise ValueError(f"zip uncompressed size exceeds limit: {MAX_ZIP_UNCOMPRESSED_BYTES // (1024 * 1024)}MB")
            if total_uncompressed and (total_compressed <= 0 or total_uncompressed / total_compressed > MAX_ZIP_COMPRESSION_RATIO):
                raise ValueError("zip aggregate compression ratio exceeds limit")

            validated: list[tuple[zipfile.ZipInfo, Path]] = []
            seen: set[str] = set()
            for info in all_infos:
                normalized = info.filename.replace("\\", "/")
                if not normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
                    raise ValueError("zip contains an absolute or empty path")
                parts = tuple(part for part in normalized.split("/") if part)
                if not parts or any(part in {".", ".."} for part in parts):
                    raise ValueError("zip contains an unsafe relative path")
                if len(parts) > MAX_ZIP_DEPTH:
                    raise ValueError(f"zip path depth exceeds limit: {MAX_ZIP_DEPTH}")
                relative_name = "/".join(parts)
                if any(ord(character) < 32 for character in relative_name):
                    raise ValueError("zip path contains control characters")
                if len(relative_name) > MAX_ZIP_PATH_LENGTH or len(relative_name.encode("utf-8")) > MAX_ZIP_PATH_LENGTH:
                    raise ValueError(f"zip path length exceeds limit: {MAX_ZIP_PATH_LENGTH}")
                collision_key = relative_name.casefold()
                if collision_key in seen:
                    raise ValueError("zip contains duplicate or case-colliding entries")
                seen.add(collision_key)
                if any(_is_windows_reserved_segment(part) for part in parts):
                    raise ValueError("zip contains a Windows reserved path")
                if info.flag_bits & 0x1:
                    raise ValueError("encrypted zip entries are not supported")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise ValueError("zip compression method is not allowed")
                if info.file_size < 0 or info.compress_size < 0:
                    raise ValueError("zip contains an invalid entry size")
                if info.file_size and (info.compress_size <= 0 or info.file_size / info.compress_size > MAX_ZIP_COMPRESSION_RATIO):
                    raise ValueError("zip entry compression ratio exceeds limit")
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(unix_mode)
                if file_type and not (stat.S_ISREG(unix_mode) or stat.S_ISDIR(unix_mode)):
                    raise ValueError("zip links and special files are not allowed")
                target = destination.joinpath(*parts).resolve()
                try:
                    target.relative_to(destination)
                except ValueError as exc:
                    raise ValueError("zip contains a path traversal entry") from exc
                validated.append((info, target))

            for info, target in validated:
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info) as source, target.open("xb") as destination_file:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        extracted_bytes += len(chunk)
                        if written > info.file_size or extracted_bytes > MAX_ZIP_UNCOMPRESSED_BYTES:
                            raise ValueError("zip expanded beyond its declared or global size limit")
                        destination_file.write(chunk)
                if written != info.file_size:
                    raise ValueError("zip entry size does not match its declaration")
        return detect_repo_root(destination)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _is_windows_reserved_segment(value: str) -> bool:
    if value.endswith((" ", ".")) or ":" in value:
        return True
    stem = value.split(".", 1)[0].upper()
    return stem in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def detect_repo_root(destination: Path) -> Path:
    entries = [item for item in destination.iterdir() if item.name not in {"__MACOSX"}]
    dirs = [item for item in entries if item.is_dir()]
    files = [item for item in entries if item.is_file()]
    if len(dirs) == 1 and not files:
        return dirs[0]
    return destination


def safe_child_path(root: Path, relative: str) -> Path:
    root = root.resolve()
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("路径超出平台工作区") from exc
    return target


def safe_filename(filename: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", Path(filename).name).strip(".-")
    return cleaned or "upload.zip"


def clean_label(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()[:120]


def clean_optional(value: str) -> str | None:
    value = value.strip()
    return value or None


def parse_bool(value: object) -> bool:
    return str(value).lower() in {"1", "true", "yes", "on", "enabled"}


def llm_config_from_test_payload(workspace: Path, payload: dict) -> LLMConfig:
    if not isinstance(payload, dict):
        raise ValueError("settings payload must be a JSON object")
    profile = str(payload.get("profile") or "taint") if isinstance(payload, dict) else "taint"
    profile = profile if profile in {"taint", "dependency", "deep"} else "taint"
    saved_settings = load_workspace_settings(workspace)
    saved_config = llm_config_from_settings(saved_settings, profile=profile)
    incoming_llm = payload.get("llm", payload) if isinstance(payload, dict) else {}
    if not isinstance(incoming_llm, dict):
        raise ValueError("settings payload must contain an llm object")
    incoming_connection = incoming_llm.get("connection", incoming_llm)
    if not isinstance(incoming_connection, dict):
        incoming_connection = {}
    if "connection" not in incoming_llm:
        for legacy_profile in ("taint", "deep", "dependency"):
            legacy_payload = incoming_llm.get(legacy_profile)
            if isinstance(legacy_payload, dict) and any(
                key in legacy_payload
                for key in {
                    "provider",
                    "base_url",
                    "api_key",
                    "api_key_env",
                    "response_file",
                    "max_candidates",
                    "timeout_seconds",
                    "concurrency",
                }
            ):
                incoming_connection = legacy_payload
                break
    incoming_prompt = incoming_llm.get(profile, {})
    if not isinstance(incoming_prompt, dict):
        incoming_prompt = {}

    provider = str(incoming_connection.get("provider") or saved_config.provider or "openai-compatible").strip()
    provider = provider if provider in {"openai-compatible", "fixture"} else "openai-compatible"
    model = str(incoming_prompt.get("model") or saved_config.model or DEFAULT_MODEL).strip()[:200]
    saved_base_url = validated_llm_base_url(saved_config.base_url or DEFAULT_BASE_URL)
    base_url = validated_llm_base_url(incoming_connection.get("base_url") or saved_base_url)
    incoming_api_key = str(incoming_connection.get("api_key") or "").strip()
    if incoming_api_key == mask_secret(saved_config.api_key):
        incoming_api_key = ""
    endpoint_changed = endpoint_identity(base_url) != endpoint_identity(saved_base_url)
    if provider == "openai-compatible" and endpoint_changed and not incoming_api_key:
        raise ValueError("changing the LLM base URL requires entering a new API key")
    if provider == "openai-compatible" and incoming_connection.get("clear_api_key"):
        raise ValueError("enter an API key before testing after clearing the saved credential")
    api_key = incoming_api_key or (None if endpoint_changed else saved_config.api_key)
    default_endpoint = endpoint_identity(DEFAULT_BASE_URL)
    if provider == "openai-compatible" and not api_key and endpoint_identity(base_url) != default_endpoint:
        raise ValueError("a custom LLM endpoint requires an API key saved for that endpoint or a newly entered key")
    # The request cannot select an arbitrary process environment variable or local
    # response file. Only the administrator's saved configuration is considered.
    configured_key_env = saved_config.api_key_env or "AUDITFORGE_LLM_API_KEY"
    api_key_env = configured_key_env if configured_key_env in allowed_test_api_key_envs() else "AUDITFORGE_LLM_API_KEY"
    response_file = saved_config.response_file
    try:
        max_candidates = int(incoming_connection.get("max_candidates") or saved_config.max_candidates or 200)
    except (TypeError, ValueError):
        max_candidates = 200
    try:
        timeout_seconds = int(incoming_connection.get("timeout_seconds") or saved_config.timeout_seconds or 60)
    except (TypeError, ValueError):
        timeout_seconds = 60
    try:
        concurrency = int(incoming_connection.get("concurrency") or saved_config.concurrency or 3)
    except (TypeError, ValueError):
        concurrency = 3
    return LLMConfig(
        enabled=True,
        provider=provider,
        model=model or DEFAULT_MODEL,
        base_url=base_url or DEFAULT_BASE_URL,
        api_key=api_key or None,
        api_key_env=api_key_env,
        response_file=response_file,
        timeout_seconds=max(10, min(600, timeout_seconds)),
        max_candidates=max(1, min(500, max_candidates)),
        concurrency=max(1, min(12, concurrency)),
        system_prompt=str(incoming_prompt.get("system_prompt") or saved_config.system_prompt or "")[:12000] or None,
        user_prompt=str(incoming_prompt.get("user_prompt") or saved_config.user_prompt or "")[:12000] or None,
    )


def validated_llm_base_url(value: object) -> str:
    raw = str(value or "").strip().rstrip("/")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid LLM base URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("LLM base URL must use http or https")
    if parsed.scheme == "http" and parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("remote LLM base URL must use HTTPS")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("LLM base URL cannot contain credentials, a query, or a fragment")
    hostname = parsed.hostname.lower()
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority += f":{port}"
    path = "/" + parsed.path.strip("/") if parsed.path.strip("/") else ""
    return f"{parsed.scheme.lower()}://{authority}{path}"


def endpoint_identity(value: str) -> str:
    return validated_llm_base_url(value).lower()


def allowed_test_api_key_envs() -> set[str]:
    allowed = {"AUDITFORGE_LLM_API_KEY", "OPENAI_API_KEY"}
    allowed.update(item.strip() for item in os.getenv("AUDITFORGE_ALLOWED_LLM_KEY_ENVS", "").split(",") if item.strip())
    return allowed


def read_json_file(path: Path, default):
    with locked_path(path):
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return default


_server_ui.configure_backend(
    load_runs=load_runs,
    load_triage_notes=load_triage_notes,
    read_json_file=read_json_file,
    run_workspace_path=run_workspace_path,
    int_value=int_value,
    normalize_progress=normalize_progress,
    confirmed_verification_statuses=CONFIRMED_VERIFICATION_STATUSES,
    max_upload_bytes=MAX_UPLOAD_BYTES,
    max_zip_uncompressed_bytes=MAX_ZIP_UNCOMPRESSED_BYTES,
    triage_status_options=TRIAGE_STATUS_OPTIONS,
)
