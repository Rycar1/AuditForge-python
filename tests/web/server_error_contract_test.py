from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path

import pytest

from auditforge import server as server_module
from auditforge.logging_config import configure_logging, get_logger, get_recent_logs, shutdown_logging
from auditforge.server import create_workspace_server, normalize_run_failure, public_log_entry
from auditforge.user_errors import classify_error, error_payload
from auditforge.web_security import WebSecurityConfig


def request(server, method: str, path: str, *, headers: dict[str, str] | None = None, body: bytes | None = None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


def test_error_payload_is_stable_actionable_and_does_not_echo_exception() -> None:
    secret = "api_key=do-not-return"
    error = classify_error(RuntimeError(secret), context="internal", reference="AF-TEST-001")

    payload = error_payload(error)

    assert payload == {
        "ok": False,
        "error": "系统处理请求时发生内部错误。",
        "error_code": "INTERNAL_ERROR",
        "action": "请根据诊断编号查看日志；若问题持续，请重启服务后重试。",
        "retryable": False,
        "reference": "AF-TEST-001",
    }
    assert secret not in json.dumps(payload, ensure_ascii=False)


def test_api_auth_failure_uses_contract_headers_and_safe_message(tmp_path: Path) -> None:
    security = WebSecurityConfig(
        bind_host="127.0.0.1",
        admin_token="contract-test-admin-token-value",
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
        status, headers, body = request(server, "GET", "/api/settings")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    payload = json.loads(body)
    assert status == 401
    assert payload["ok"] is False
    assert payload["error_code"] == "AUTH_REQUIRED"
    assert payload["action"]
    assert payload["reference"].startswith("AF-")
    assert headers["X-AuditForge-Reference"] == payload["reference"]
    assert headers["X-Request-ID"] == payload["reference"]


def test_legacy_run_exception_is_replaced_with_safe_failure() -> None:
    legacy = {
        "id": "legacy-failed",
        "status": "failed",
        "verify": "none",
        "dependency_scan": False,
        "error": "ValueError: provider failed at C:/private/config with api_key=secret",
        "progress": {},
    }

    normalized = normalize_run_failure(legacy)
    serialized = json.dumps(normalized, ensure_ascii=False)

    assert normalized["error"] == "扫描执行失败。"
    assert normalized["failure"]["code"] == "SCAN_FAILED"
    assert normalized["failure"]["diagnostic_id"].startswith("AFH-")
    assert "ValueError" not in serialized
    assert "C:/private" not in serialized
    assert "secret" not in serialized


def test_unexpected_api_exception_returns_safe_500_and_correlated_log(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    token = "contract-test-admin-token-value"
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

    def fail_settings(*_args, **_kwargs):
        raise RuntimeError("api_key=provider-secret at C:/private/settings.json")

    monkeypatch.setattr(server_module, "save_workspace_settings", fail_settings)
    logger = configure_logging(level="INFO", console=False)
    server = create_workspace_server(tmp_path, port=0, security=security)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    auth = {"Authorization": f"Bearer {token}"}
    try:
        status, headers, body = request(
            server,
            "POST",
            "/api/settings",
            headers={**auth, "Content-Type": "application/json"},
            body=b"{}",
        )
        log_status, _, log_body = request(server, "GET", "/api/logs?limit=100", headers=auth)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        shutdown_logging(logger)

    payload = json.loads(body)
    logs = json.loads(log_body)["logs"]
    serialized = json.dumps({"payload": payload, "logs": logs}, ensure_ascii=False)
    assert status == 500
    assert log_status == 200
    assert payload["error_code"] == "INTERNAL_ERROR"
    assert headers["X-AuditForge-Reference"] == payload["reference"]
    assert any(item.get("context", {}).get("reference") == payload["reference"] for item in logs)
    assert "provider-secret" not in serialized
    assert "C:/private/settings.json" not in serialized
    assert "RuntimeError" not in serialized


def test_public_log_entry_hides_traceback_and_error_type() -> None:
    logger = configure_logging(level="ERROR", console=False)
    try:
        try:
            raise RuntimeError("api_key=private-provider-secret")
        except RuntimeError:
            get_logger("contract").exception(
                "scan failed",
                extra={"event": "scan.failed", "reference": "AF-LOG-001", "error_type": "RuntimeError"},
            )
        raw = get_recent_logs(limit=1)[0]
    finally:
        shutdown_logging(logger)

    public = public_log_entry(raw)
    serialized = json.dumps(public, ensure_ascii=False)
    assert public["context"]["reference"] == "AF-LOG-001"
    assert "exception" not in serialized
    assert "RuntimeError" not in serialized
    assert "private-provider-secret" not in serialized
