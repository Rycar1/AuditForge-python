from __future__ import annotations

import http.client
import json
import os
import re
import stat
import threading
import zipfile
from pathlib import Path

import pytest

from auditforge import web_security
from auditforge.logging_config import configure_logging, get_logger, get_recent_logs, shutdown_logging
from auditforge.scan_worker import cancel_request_path, read_worker_state, write_worker_state
from auditforge.secret_store import secrets_path
from auditforge.server import (
    _write_response_body,
    cancel_scan_run,
    create_workspace_server,
    extract_uploaded_zip,
    llm_config_from_test_payload,
    load_runs,
    load_triage_notes,
    prepare_scan_run,
    public_run,
    recover_interrupted_runs,
    save_candidate_triage,
    save_runs,
)
from auditforge.settings import default_settings, load_workspace_settings, public_settings, save_workspace_settings, settings_path
from auditforge.web_security import WebSecurityConfig, atomic_write_json, validate_repo_path


def request(server, method: str, path: str, *, headers: dict[str, str] | None = None, body: bytes | None = None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    request_headers = {"Host": f"127.0.0.1:{server.server_port}", **(headers or {})}
    connection.request(method, path, body=body, headers=request_headers)
    response = connection.getresponse()
    payload = response.read()
    result = response.status, dict(response.getheaders()), payload
    connection.close()
    return result


def test_client_disconnect_during_response_is_logged_without_raising() -> None:
    class AbortedStream:
        def write(self, body: bytes) -> None:
            del body
            raise ConnectionAbortedError(10053, "client disconnected")

    configure_logging(level="DEBUG", console=False)

    assert _write_response_body(AbortedStream(), b"response", get_logger("server-test"), "/api/runs/run-1") is False
    assert any(item.get("event") == "server.client_disconnected" for item in get_recent_logs())


def test_atomic_json_write_retries_transient_windows_replace_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    original_replace = web_security.os.replace
    attempts = 0

    def transient_replace(source, destination) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError(13, "temporarily locked")
        original_replace(source, destination)

    monkeypatch.setattr(web_security.os, "replace", transient_replace)

    atomic_write_json(target, {"ok": True})

    assert attempts == 3
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True}


def test_dashboard_requires_session_and_enforces_host_origin_csrf(tmp_path: Path) -> None:
    token = "test-admin-token-that-is-long-enough"
    security = WebSecurityConfig(
        bind_host="127.0.0.1",
        admin_token=token,
        allowed_hosts=("127.0.0.1", "localhost"),
        allowed_origins=(),
        allowed_repo_roots=(),
        max_request_concurrency=4,
        max_scan_concurrency=1,
        socket_timeout_seconds=5,
    )
    server = create_workspace_server(tmp_path, port=0, security=security)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = request(server, "GET", "/")
        assert status == 401
        document = body.decode("utf-8")
        assert '<form id="login"' in document
        assert "管理员令牌" in document

        status, headers, _ = request(server, "GET", f"/?token={token}")
        assert status == 401
        assert "Set-Cookie" not in headers

        login_body = json.dumps({"token": token}).encode()
        status, _, _ = request(
            server,
            "POST",
            "/api/login",
            headers={"Content-Type": "application/json"},
            body=login_body,
        )
        assert status == 403

        origin = f"http://127.0.0.1:{server.server_port}"
        status, _, _ = request(
            server,
            "POST",
            "/api/login",
            headers={"Content-Type": "application/json", "Origin": origin},
            body=json.dumps({"token": "wrong-token"}).encode(),
        )
        assert status == 401

        status, headers, _ = request(
            server,
            "POST",
            "/api/login",
            headers={"Content-Type": "application/json", "Origin": origin},
            body=login_body,
        )
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        assert token not in headers["Set-Cookie"]

        status, headers, body = request(server, "GET", "/settings", headers={"Cookie": cookie})
        assert status == 200
        assert headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert "object-src 'none'" in headers["Content-Security-Policy"]
        assert headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
        csrf_match = re.search(rb'auditforge-csrf-token" content="([^"]+)"', body)
        assert csrf_match
        csrf = csrf_match.group(1).decode("ascii")

        payload = json.dumps({"language": "en-US", "llm": {}}).encode()
        status, _, _ = request(
            server,
            "POST",
            "/api/settings",
            headers={"Cookie": cookie, "Content-Type": "application/json"},
            body=payload,
        )
        assert status == 403

        status, _, _ = request(
            server,
            "POST",
            "/api/settings",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
            body=b"{}",
        )
        assert status == 400

        status, _, _ = request(
            server,
            "POST",
            "/api/settings",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Content-Length": str(300 * 1024),
            },
            body=b"",
        )
        assert status == 413

        status, _, body = request(
            server,
            "POST",
            "/api/settings",
            headers={
                "Cookie": cookie,
                "Content-Type": "application/json",
                "Origin": origin,
                "X-AuditForge-CSRF": csrf,
            },
            body=payload,
        )
        assert status == 200, body.decode(errors="replace")

        status, _, _ = request(
            server,
            "GET",
            "/api/settings",
            headers={"Host": "attacker.example", "Authorization": f"Bearer {token}"},
        )
        assert status == 421

        status, _, _ = request(
            server,
            "POST",
            "/api/settings",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Origin": "https://attacker.example",
            },
            body=b"{}",
        )
        assert status == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_request_logging_never_records_login_tokens(tmp_path: Path) -> None:
    token = "request-log-secret-token-value"
    log_path = tmp_path / "auditforge.log"
    logger = configure_logging(log_file=log_path, json_format=True, console=False)
    security = WebSecurityConfig(
        bind_host="127.0.0.1",
        admin_token=token,
        allowed_hosts=("127.0.0.1",),
        allowed_origins=(),
        allowed_repo_roots=(),
    )
    server = create_workspace_server(tmp_path / "workspace", port=0, security=security)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, _ = request(server, "GET", f"/?token={token}")
        assert status == 401
        status, _, _ = request(
            server,
            "POST",
            "/api/login",
            headers={
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{server.server_port}",
            },
            body=json.dumps({"token": token}).encode(),
        )
        assert status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        shutdown_logging(logger)
    log_text = log_path.read_text(encoding="utf-8")
    assert token not in log_text
    assert "?token=" not in log_text
    assert '"path": "/"' in log_text


def test_dashboard_exposes_authenticated_redacted_live_logs(tmp_path: Path) -> None:
    token = "dashboard-log-admin-token-that-is-long"
    logger = configure_logging(level="DEBUG", console=False, buffer_capacity=20)
    get_logger("ui-test").warning(
        "provider failed password=plain-secret",
        extra={"event": "ui.log.test", "api_key": "sk-live-secret", "safe_value": "visible"},
    )
    security = WebSecurityConfig(
        bind_host="127.0.0.1",
        admin_token=token,
        allowed_hosts=("127.0.0.1",),
        allowed_origins=(),
        allowed_repo_roots=(),
    )
    server = create_workspace_server(tmp_path / "workspace", port=0, security=security)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    auth = {"Authorization": f"Bearer {token}"}
    try:
        status, _, _ = request(server, "GET", "/api/logs?after=0")
        assert status == 401

        status, _, body = request(server, "GET", "/logs", headers=auth)
        assert status == 200
        assert b' id="logsStream"' in body

        status, _, body = request(server, "GET", "/api/logs?after=0&limit=20&level=WARNING", headers=auth)
        assert status == 200
        payload = json.loads(body)
        entry = next(item for item in payload["logs"] if item.get("event") == "ui.log.test")
        serialized = json.dumps(payload, ensure_ascii=False)
        assert entry["level"] == "WARNING"
        assert entry["context"]["safe_value"] == "visible"
        assert "api_key" not in entry["context"]
        assert "plain-secret" not in serialized
        assert "sk-live-secret" not in serialized
        assert not any(item.get("context", {}).get("path") == "/api/logs" for item in payload["logs"])

        cursor = payload["next_after"]
        get_logger("ui-test").error("second event", extra={"event": "ui.log.second"})
        status, _, body = request(server, "GET", f"/api/logs?after={cursor}&limit=20", headers=auth)
        assert status == 200
        incremental = json.loads(body)
        assert any(item.get("event") == "ui.log.second" for item in incremental["logs"])

        status, _, _ = request(server, "GET", "/api/logs?after=-1", headers=auth)
        assert status == 400
        status, _, _ = request(server, "GET", "/api/logs?level=VERBOSE", headers=auth)
        assert status == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        shutdown_logging(logger)


def test_remote_bind_requires_explicit_security(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in (
        "AUDITFORGE_ALLOW_REMOTE",
        "AUDITFORGE_ADMIN_TOKEN",
        "AUDITFORGE_ALLOWED_HOSTS",
        "AUDITFORGE_ALLOWED_ORIGINS",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="refusing non-loopback"):
        WebSecurityConfig.from_environment(tmp_path, "0.0.0.0")

    monkeypatch.setenv("AUDITFORGE_ALLOW_REMOTE", "1")
    monkeypatch.setenv("AUDITFORGE_ADMIN_TOKEN", "a" * 40)
    monkeypatch.setenv("AUDITFORGE_ALLOWED_HOSTS", "audit.example:8765")
    monkeypatch.setenv("AUDITFORGE_ALLOWED_ORIGINS", "https://audit.example")
    config = WebSecurityConfig.from_environment(tmp_path, "0.0.0.0")
    assert config.allowed_hosts == ("audit.example",)
    assert config.allowed_origins == ("https://audit.example",)


def test_default_scan_concurrency_is_serial_for_cpu_bound_analysis() -> None:
    config = WebSecurityConfig(
        bind_host="127.0.0.1",
        admin_token="a" * 40,
        allowed_hosts=("127.0.0.1",),
        allowed_origins=(),
        allowed_repo_roots=(),
    )

    assert config.max_scan_concurrency == 1


def test_task_creation_defers_project_inventory_to_background_scan(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "App.java").write_text("class App {}\n", encoding="utf-8")
    workspace = tmp_path / "workspace"

    prepared = prepare_scan_run(
        workspace,
        {"sourceType": ["path"], "repoPath": [str(repo)]},
        allowed_repo_roots=(tmp_path,),
    )

    assert prepared["project_inventory"] is None
    assert prepared["run"]["project_inventory"] == {}
    assert prepared["run"]["progress"]["phase"] == "queued"


def test_dashboard_restart_marks_orphaned_running_scans_as_failed(tmp_path: Path) -> None:
    run = {
        "id": "orphaned-run",
        "status": "running",
        "verify": "none",
        "dependency_scan": False,
        "progress": {},
    }
    save_runs(tmp_path, [run])

    assert recover_interrupted_runs(tmp_path) == 1

    recovered = next(
        item for item in json.loads((tmp_path / "auditforge_runs.json").read_text(encoding="utf-8"))["runs"] if item["id"] == run["id"]
    )
    assert recovered["status"] == "failed"
    assert recovered["completed_at"]
    assert recovered["error"] == "扫描进程意外退出，任务未完成。"
    assert recovered["failure"]["code"] == "SCAN_WORKER_EXITED"


def test_dashboard_restart_keeps_live_isolated_worker_running(tmp_path: Path) -> None:
    run = {
        "id": "live-worker",
        "status": "running",
        "verify": "none",
        "dependency_scan": False,
        "workspace": "runs/live-worker",
        "progress": {},
    }
    run_dir = tmp_path / "runs" / "live-worker"
    run_dir.mkdir(parents=True)
    write_worker_state(
        run_dir,
        {
            "run_id": run["id"],
            "pid": os.getpid(),
            "status": "running",
            "progress": {"stage": "candidate", "percent": 84, "detail": "LLM audit in progress"},
        },
    )
    save_runs(tmp_path, [run])

    assert recover_interrupted_runs(tmp_path) == 0
    recovered = load_runs(tmp_path)[0]
    assert recovered["status"] == "running"
    assert recovered["progress"]["phase"] == "candidate"
    assert recovered["progress"]["percent"] >= 75


def test_cancel_scan_run_writes_terminal_worker_state(tmp_path: Path) -> None:
    run = {
        "id": "cancel-me",
        "status": "running",
        "verify": "none",
        "dependency_scan": False,
        "workspace": "runs/cancel-me",
        "progress": {},
    }
    run_dir = tmp_path / "runs" / "cancel-me"
    run_dir.mkdir(parents=True)
    write_worker_state(
        run_dir,
        {
            "run_id": run["id"],
            "pid": 0,
            "status": "running",
            "progress": {"stage": "candidate", "percent": 84, "detail": "waiting on provider"},
        },
    )
    save_runs(tmp_path, [run])

    cancelled = cancel_scan_run(tmp_path, run["id"])

    assert cancelled["status"] == "failed"
    assert cancelled["error"] == "扫描任务已取消。"
    assert cancelled["failure"]["code"] == "SCAN_CANCELLED"
    assert cancel_request_path(run_dir).exists()
    assert read_worker_state(run_dir)["status"] == "cancelled"
    assert load_runs(tmp_path)[0]["status"] == "failed"


def test_settings_secret_is_separate_and_endpoint_bound(tmp_path: Path) -> None:
    secret = "unit-test-super-secret-key"
    settings = save_workspace_settings(
        tmp_path,
        {
            "llm": {
                "connection": {
                    "enabled": True,
                    "base_url": "https://saved.example/v1",
                    "api_key": secret,
                    "api_key_env": "SAVED_ENV_NAME",
                    "response_file": "C:/private/fixture.json",
                }
            }
        },
    )
    assert settings["llm"]["connection"]["api_key"] == secret
    assert secret not in settings_path(tmp_path).read_text(encoding="utf-8")
    assert secret not in secrets_path(tmp_path).read_text(encoding="utf-8")
    assert load_workspace_settings(tmp_path)["llm"]["connection"]["api_key"] == secret

    public = public_settings(settings)
    serialized = json.dumps(public)
    assert "C:/private/fixture.json" not in serialized
    assert "response_file" not in public["llm"]["connection"]

    with pytest.raises(ValueError, match="requires entering a new API key"):
        llm_config_from_test_payload(
            tmp_path,
            {
                "llm": {
                    "connection": {
                        "base_url": "https://attacker.example/v1",
                        "api_key_env": "AWS_SECRET_ACCESS_KEY",
                    }
                }
            },
        )

    config = llm_config_from_test_payload(
        tmp_path,
        {
            "llm": {
                "connection": {
                    "base_url": "https://saved.example/v1",
                    "api_key_env": "AWS_SECRET_ACCESS_KEY",
                }
            }
        },
    )
    assert config.api_key == secret
    assert config.api_key_env == "AUDITFORGE_LLM_API_KEY"

    no_key_workspace = tmp_path / "no-key"
    save_workspace_settings(
        no_key_workspace,
        {"llm": {"connection": {"base_url": "https://custom.example/v1", "api_key_env": "AWS_SECRET_ACCESS_KEY"}}},
    )
    with pytest.raises(ValueError, match="custom LLM endpoint requires"):
        llm_config_from_test_payload(no_key_workspace, {"llm": {"connection": {"base_url": "https://custom.example/v1"}}})


def test_public_payloads_remove_url_credentials_queries_and_response_files() -> None:
    settings = default_settings()
    settings["llm"]["connection"].update(
        {
            "base_url": "https://user:password@example.test/v1?token=secret",
            "response_file": "C:/private/fixture.json",
        }
    )
    public = public_settings(settings)
    serialized = json.dumps(public)
    assert "user:password@" not in serialized
    assert "token=secret" not in serialized
    assert "fixture.json" not in serialized
    assert public["llm"]["connection"]["base_url"] == "https://example.test/v1"

    run = public_run(
        {
            "target_url": "https://alice:password@target.test/base?session=secret",
            "scan_config": {"response_file": "C:/private/fixture.json"},
        }
    )
    assert run["target_url"] == "https://target.test/base"
    assert "response_file" not in run["scan_config"]


def write_zip(path: Path, entries: list[tuple[zipfile.ZipInfo | str, bytes]], *, compression=zipfile.ZIP_STORED) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)


@pytest.mark.parametrize(
    "entry",
    [
        "../escape.py",
        "/absolute.py",
        "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/file.py",
    ],
)
def test_zip_rejects_unsafe_paths_and_cleans_destination(tmp_path: Path, entry: str) -> None:
    archive = tmp_path / "payload.zip"
    destination = tmp_path / "out"
    write_zip(archive, [(entry, b"print('unsafe')")])
    with pytest.raises(ValueError):
        extract_uploaded_zip(archive, destination)
    assert not destination.exists()
    assert not (tmp_path / "escape.py").exists()


def test_zip_rejects_bombs_and_links_but_extracts_regular_files(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.zip"
    destination = tmp_path / "bomb-out"
    write_zip(bomb, [("large.txt", b"A" * 500_000)], compression=zipfile.ZIP_DEFLATED)
    with pytest.raises(ValueError, match="compression ratio"):
        extract_uploaded_zip(bomb, destination)
    assert not destination.exists()

    link_info = zipfile.ZipInfo("link")
    link_info.create_system = 3
    link_info.external_attr = (stat.S_IFLNK | 0o777) << 16
    link_archive = tmp_path / "link.zip"
    write_zip(link_archive, [(link_info, b"target")])
    with pytest.raises(ValueError, match="links and special files"):
        extract_uploaded_zip(link_archive, tmp_path / "link-out")

    valid = tmp_path / "valid.zip"
    write_zip(valid, [("repo/main.py", b"print('ok')")])
    root = extract_uploaded_zip(valid, tmp_path / "valid-out")
    assert root.name == "repo"
    assert (root / "main.py").read_bytes() == b"print('ok')"


def test_local_repository_path_requires_an_explicit_root(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    repo = root / "repo"
    outside = tmp_path / "outside"
    repo.mkdir(parents=True)
    outside.mkdir()

    with pytest.raises(ValueError, match="disabled"):
        validate_repo_path(str(repo), ())
    assert validate_repo_path(str(repo), (root,)) == repo.resolve()
    with pytest.raises(ValueError, match="outside"):
        validate_repo_path(str(outside), (root,))
    with pytest.raises(ValueError, match="UNC"):
        validate_repo_path(r"\\server\share\repo", (root,))


def test_concurrent_triage_writes_are_atomic_and_do_not_lose_items(tmp_path: Path) -> None:
    errors: list[Exception] = []

    def save(index: int) -> None:
        try:
            save_candidate_triage(
                tmp_path,
                {"candidate_id": f"candidate-{index}", "status": "needs_review", "note": f"note {index}"},
            )
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=save, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    assert len(load_triage_notes(tmp_path)["items"]) == 20
    json.loads((tmp_path / "triage_notes.json").read_text(encoding="utf-8"))
