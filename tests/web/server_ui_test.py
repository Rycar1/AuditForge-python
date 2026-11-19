from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from auditforge import server, server_ui


def test_server_reexports_presentation_api_without_duplicate_implementations() -> None:
    assert server_ui.__all__
    for name in server_ui.__all__:
        assert getattr(server, name) is getattr(server_ui, name)


def test_page_renderers_live_in_presentation_module() -> None:
    assert server.render_overview_page.__module__ == "auditforge.server_ui"
    assert server.render_settings_page.__module__ == "auditforge.server_ui"
    assert server.render_card.__module__ == "auditforge.server_ui"


def test_logs_page_exposes_filters_controls_and_active_navigation(tmp_path: Path) -> None:
    page = server_ui.render_logs_page(tmp_path)

    assert 'href="/logs" aria-current="page"' in page
    assert 'id="logLevel"' in page
    assert 'id="logSearch"' in page
    assert 'id="logPause"' in page
    assert 'id="logClear"' in page
    assert 'id="logsStream"' in page
    assert server.render_logs_page is server_ui.render_logs_page


def test_logs_script_polls_incrementally_and_builds_untrusted_content_as_text() -> None:
    script = server_ui.LOGS_SCRIPT

    assert "/api/logs?after=" in script
    assert "window.auditforgeRequestJson" in script
    assert "schedulePoll" in script
    assert "window.setTimeout(poll" in script
    assert "pollFailures" in script
    assert "Retry-After" not in script
    assert "record.level" in script
    assert "record.event" in script
    assert "record.message" in script
    assert "record.context" in script
    assert "document.createElement" in script
    assert ".textContent" in script
    assert "replaceChildren(empty)" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script


def test_api_feedback_parser_handles_empty_non_json_and_structured_errors() -> None:
    script = server_ui.ui_pages.API_FEEDBACK_SCRIPT

    assert "await response.text()" in script
    assert "JSON.parse(raw)" in script
    assert "RESPONSE_EMPTY" in script
    assert "RESPONSE_INVALID" in script
    assert "NETWORK_ERROR" in script
    assert "body.error_code" in script
    assert "body.action" in script
    assert "body.reference" in script
    assert "failure.diagnostic_id" in script
    assert "X-AuditForge-Reference" in script
    assert "target.setAttribute('role', 'alert')" in script
    assert "response.json()" not in script


def test_api_feedback_parser_behaviour_in_node(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        return
    source = server_ui.ui_pages.API_FEEDBACK_SCRIPT.strip()
    source = source.removeprefix("<script>").removesuffix("</script>")
    program = f"""
global.window = global;
eval({json.dumps(source)});

function response(status, body, headers = {{}}) {{
  const lowered = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  return {{
    status,
    ok: status >= 200 && status < 300,
    headers: {{get: (name) => lowered[String(name).toLowerCase()] || null}},
    text: async () => body,
  }};
}}

async function capture(item, fallback) {{
  try {{
    return {{ok: true, value: await window.auditforgeParseResponse(item, fallback)}};
  }} catch (error) {{
    return {{
      ok: false,
      message: error.message,
      code: error.code,
      action: error.action,
      reference: error.reference,
      status: error.status,
    }};
  }}
}}

(async () => {{
  const result = {{
    structured: await capture(response(422, JSON.stringify({{
      ok: false,
      error: '设置内容无效。',
      error_code: 'SETTINGS_INVALID',
      action: '检查配置项后重试。',
      reference: 'AFR-TEST-1',
    }})), '保存失败'),
    dataError: await capture(response(200, JSON.stringify({{
      error: '业务处理失败。',
      code: 'BUSINESS_FAILED',
      action: '修正输入后重试。',
      ref: 'AFR-TEST-2',
    }})), '请求失败'),
    nonJson: await capture(response(502, '<html>bad gateway</html>', {{'X-AuditForge-Reference': 'AFR-TEST-3'}}), '读取失败'),
    empty: await capture(response(204, ''), '读取失败'),
    success: await capture(response(200, JSON.stringify({{ok: true, value: 7}})), '读取失败'),
  }};
  process.stdout.write(JSON.stringify(result));
}})().catch((error) => {{
  process.stderr.write(String(error && error.stack || error));
  process.exitCode = 1;
}});
"""
    path = tmp_path / "api-feedback-test.js"
    path.write_text(program, encoding="utf-8")
    completed = subprocess.run([node, str(path)], capture_output=True, text=True, encoding="utf-8", check=True)  # noqa: S603
    result = json.loads(completed.stdout)

    assert result["structured"] == {
        "ok": False,
        "message": "设置内容无效。",
        "code": "SETTINGS_INVALID",
        "action": "检查配置项后重试。",
        "reference": "AFR-TEST-1",
        "status": 422,
    }
    assert result["dataError"]["ok"] is False
    assert result["dataError"]["code"] == "BUSINESS_FAILED"
    assert result["dataError"]["reference"] == "AFR-TEST-2"
    assert result["nonJson"]["code"] == "HTTP_502"
    assert result["nonJson"]["reference"] == "AFR-TEST-3"
    assert result["empty"]["code"] == "RESPONSE_EMPTY"
    assert result["success"] == {"ok": True, "value": {"ok": True, "value": 7}}


def test_request_scripts_use_shared_parser_and_inline_error_regions() -> None:
    scripts = (
        server_ui.SCAN_SCRIPT,
        server_ui.RUN_PROGRESS_SCRIPT,
        server_ui.RUN_DELETE_SCRIPT,
        server_ui.RUN_CANCEL_SCRIPT,
        server_ui.TRIAGE_SCRIPT,
        server_ui.LOGS_SCRIPT,
    )

    assert all("window.auditforgeRequestJson" in script for script in scripts)
    assert all("response.json()" not in script for script in scripts)
    assert "window.alert" not in server_ui.RUN_DELETE_SCRIPT
    assert "window.alert" not in server_ui.RUN_CANCEL_SCRIPT
    assert "window.auditforgeActionFeedback" in server_ui.RUN_DELETE_SCRIPT
    assert "window.auditforgeActionFeedback" in server_ui.RUN_CANCEL_SCRIPT
    assert "window.auditforgeShowError" in server_ui.RUN_PROGRESS_SCRIPT
    assert "progressPollFailures" in server_ui.RUN_PROGRESS_SCRIPT


def test_failed_run_surfaces_action_code_and_reference() -> None:
    run = {
        "id": "run-failed",
        "name": "Failed run",
        "status": "failed",
        "error": "扫描执行失败。",
        "failure": {
            "code": "SCAN_FAILED",
            "action": "请根据诊断编号查看日志后重试。",
            "diagnostic_id": "AFW-20260729-ABCDEF12",
        },
    }

    row = server_ui.render_run_row(run)
    page = server_ui.render_run_status_page(Path.cwd(), run)

    for document in (row, page):
        assert "扫描执行失败。 错误代码：SCAN_FAILED" in document
        assert "处理建议：请根据诊断编号查看日志后重试。" in document
        assert "诊断编号：AFW-20260729-ABCDEF12" in document
        assert 'role="alert"' in document


def test_login_uses_the_same_safe_response_and_error_renderer() -> None:
    document = server_ui.render_login_page(None)

    assert "window.auditforgeRequestJson('/api/login'" in document
    assert "window.auditforgeShowError(error, reason, '登录失败')" in document
    assert "await response.text()" in document
    assert "body.error_code" in document
    assert "body.action" in document
    assert "body.reference" in document
    assert 'id="loginError" role="alert"' in document
    assert "response.json()" not in document
