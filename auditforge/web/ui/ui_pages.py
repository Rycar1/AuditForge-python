"""Greenfield page compositions for the AuditForge forensic console.

These functions deliberately contain no persistence or HTTP logic. The server
presentation module supplies already-sanitized view models and renderer
callbacks, keeping this layer easy to replace without touching the backend.
"""

from __future__ import annotations

import html
from collections.abc import Callable
from pathlib import Path

API_FEEDBACK_SCRIPT = r"""
  <script>
    (() => {
      const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
      const cleanText = (value) => typeof value === 'string' ? value.trim() : '';

      function translate(text) {
        return window.auditforgeTranslate ? window.auditforgeTranslate(text) : text;
      }

      function errorTranslation(code) {
        const language = window.auditforgeLanguage || 'zh-CN';
        const catalog = window.auditforgeErrorTranslations && window.auditforgeErrorTranslations[language];
        const entry = catalog && catalog[cleanText(code)];
        return isObject(entry) ? entry : {};
      }

      function localizedErrorText(code, field, value) {
        const localized = cleanText(errorTranslation(code)[field]);
        return localized || translate(cleanText(value));
      }

      function defaultAction(status) {
        if (status === 401) return translate('请重新登录后重试。');
        if (status === 403 || status === 421) return translate('请刷新页面或重新登录后重试。');
        if (status === 404) return translate('请返回任务列表并刷新页面。');
        if (status === 405) return translate('请刷新页面；若问题持续，请检查客户端版本。');
        if (status === 409) return translate('请刷新任务状态后再试。');
        if (status === 413) return translate('请减小请求或上传文件的体积后重试。');
        if (status === 429) return translate('请稍候几秒后重试。');
        if (status >= 500) return translate('请稍后重试；若问题持续，请根据诊断编号查看运行日志。');
        if (status === 400 || status === 422) return translate('请检查输入内容并重试。');
        return translate('请刷新页面后重试；若问题持续，请查看运行日志。');
      }

      function responseHeader(response, name) {
        try {
          return response && response.headers && typeof response.headers.get === 'function'
            ? cleanText(response.headers.get(name))
            : '';
        } catch (_error) {
          return '';
        }
      }

      function responseReference(response) {
        return responseHeader(response, 'X-AuditForge-Reference') || responseHeader(response, 'X-Request-ID');
      }

      function retryAfterSeconds(value) {
        const numeric = Number(value);
        if (Number.isFinite(numeric) && numeric > 0) return numeric;
        const timestamp = Date.parse(cleanText(value));
        if (!Number.isFinite(timestamp)) return 0;
        return Math.max(0, Math.ceil((timestamp - Date.now()) / 1000));
      }

      function createError(details = {}) {
        const status = Number(details.status || 0);
        const code = cleanText(details.code) || (status ? `HTTP_${status}` : 'REQUEST_FAILED');
        const message = localizedErrorText(code, 'message', cleanText(details.message) || translate('请求失败。'));
        const action = localizedErrorText(code, 'action', cleanText(details.action) || defaultAction(status));
        const error = new Error(message);
        error.name = 'AuditForgeRequestError';
        error.auditforgeUserError = true;
        error.code = code;
        error.action = action;
        error.reference = cleanText(details.reference);
        error.field = cleanText(details.field);
        error.status = status;
        error.retryable = Boolean(details.retryable);
        error.retryAfter = retryAfterSeconds(details.retryAfter);
        return error;
      }

      function detailsFromPayload(payload, response, fallbackMessage) {
        const body = isObject(payload) ? payload : {};
        const nestedError = isObject(body.error) ? body.error : {};
        const failure = isObject(body.failure) ? body.failure : {};
        const status = Number(response && response.status || 0);
        const code = (
          cleanText(body.error_code)
          || cleanText(nestedError.code)
          || cleanText(body.code)
          || cleanText(failure.code)
          || (status ? `HTTP_${status}` : 'REQUEST_FAILED')
        );
        const message = (
          (typeof body.error === 'string' ? cleanText(body.error) : '')
          || cleanText(nestedError.message)
          || cleanText(body.message)
          || cleanText(fallbackMessage)
          || translate('请求失败。')
        );
        const reference = (
          cleanText(body.reference)
          || cleanText(body.diagnostic_id)
          || cleanText(body.ref)
          || cleanText(nestedError.reference)
          || cleanText(nestedError.diagnostic_id)
          || cleanText(failure.diagnostic_id)
          || responseHeader(response, 'X-AuditForge-Reference')
          || responseHeader(response, 'X-Request-ID')
        );
        return {
          message,
          code,
          action: cleanText(body.action) || cleanText(nestedError.action) || cleanText(failure.action) || defaultAction(status),
          reference,
          field: cleanText(body.field) || cleanText(nestedError.field),
          status,
          retryable: Boolean(body.retryable ?? nestedError.retryable ?? failure.retryable),
          retryAfter: responseHeader(response, 'Retry-After'),
        };
      }

      async function parseResponse(response, fallbackMessage = '') {
        const status = Number(response && response.status || 0);
        let raw = '';
        try {
          raw = await response.text();
        } catch (_error) {
          throw createError({
            message: cleanText(fallbackMessage) || translate('无法读取服务响应。'),
            code: 'RESPONSE_READ_FAILED',
            action: defaultAction(status),
            reference: responseReference(response),
            status,
          });
        }

        if (!raw.trim()) {
          throw createError({
            message: cleanText(fallbackMessage) || translate('服务返回了空响应。'),
            code: response && response.ok ? 'RESPONSE_EMPTY' : (status ? `HTTP_${status}` : 'RESPONSE_EMPTY'),
            action: defaultAction(status),
            reference: responseReference(response),
            status,
            retryAfter: responseHeader(response, 'Retry-After'),
          });
        }

        let payload;
        try {
          payload = JSON.parse(raw);
        } catch (_error) {
          throw createError({
            message: cleanText(fallbackMessage) || translate('服务返回了无法识别的响应。'),
            code: response && response.ok ? 'RESPONSE_INVALID' : (status ? `HTTP_${status}` : 'RESPONSE_INVALID'),
            action: defaultAction(status),
            reference: responseReference(response),
            status,
            retryAfter: responseHeader(response, 'Retry-After'),
          });
        }

        if (payload === null || typeof payload !== 'object') {
          throw createError({
            message: cleanText(fallbackMessage) || translate('服务返回了无法识别的响应。'),
            code: 'RESPONSE_INVALID',
            action: defaultAction(status),
            reference: responseReference(response),
            status,
          });
        }

        const body = isObject(payload) ? payload : {};
        const hasError = Object.prototype.hasOwnProperty.call(body, 'error') && Boolean(body.error);
        if (!response.ok || body.ok === false || hasError) {
          throw createError(detailsFromPayload(body, response, fallbackMessage));
        }
        return payload;
      }

      async function requestJson(input, init = {}, fallbackMessage = '') {
        let response;
        try {
          response = await fetch(input, init);
        } catch (_error) {
          throw createError({
            message: cleanText(fallbackMessage) || translate('无法连接服务。'),
            code: 'NETWORK_ERROR',
            action: translate('请检查服务是否可用和网络连接，然后重试。'),
            retryable: true,
          });
        }
        return parseResponse(response, fallbackMessage);
      }

      function normalizeError(reason, fallbackMessage = '') {
        if (reason && reason.auditforgeUserError) return reason;
        return createError({
          message: cleanText(fallbackMessage) || translate('请求失败。'),
          code: reason && reason.name === 'TypeError' ? 'NETWORK_ERROR' : 'CLIENT_REQUEST_FAILED',
          action: reason && reason.name === 'TypeError'
            ? translate('请检查服务是否可用和网络连接，然后重试。')
            : translate('请刷新页面后重试；若问题持续，请查看运行日志。'),
          retryable: reason && reason.name === 'TypeError',
        });
      }

      function formatError(reason, fallbackMessage = '') {
        const error = normalizeError(reason, fallbackMessage);
        const english = window.auditforgeLanguage === 'en-US';
        const colon = english ? ': ' : '：';
        const separator = english ? '; ' : '；';
        const codeLabel = translate('错误代码');
        const actionLabel = translate('处理建议');
        const referenceLabel = translate('诊断编号');
        const fieldLabel = translate('配置项');
        const retryLabel = translate('重试提示');
        const message = localizedErrorText(error.code, 'message', error.message);
        const action = localizedErrorText(error.code, 'action', error.action);
        const parts = [`${message} ${codeLabel}${colon}${error.code}`];
        if (action) parts.push(`${actionLabel}${colon}${action}`);
        if (error.reference) parts.push(`${referenceLabel}${colon}${error.reference}`);
        if (error.field) parts.push(`${fieldLabel}${colon}${error.field}`);
        if (error.retryAfter > 0) {
          parts.push(`${retryLabel}${colon}${translate(`${Math.ceil(error.retryAfter)} 秒后可重试。`)}`);
        } else if (error.retryable) {
          parts.push(`${retryLabel}${colon}${translate('此错误通常可以重试。')}`);
        }
        return {error, text: parts.join(separator)};
      }

      function showError(target, reason, fallbackMessage = '') {
        const formatted = formatError(reason, fallbackMessage);
        if (!target) return formatted.error;
        target.classList.add('status', 'error');
        target.classList.remove('ok');
        target.setAttribute('role', 'alert');
        target.setAttribute('aria-live', 'assertive');
        target.setAttribute('aria-atomic', 'true');
        target.hidden = false;
        if (target.textContent !== formatted.text) target.textContent = formatted.text;
        target.dataset.errorCode = formatted.error.code;
        if (formatted.error.reference) target.dataset.errorReference = formatted.error.reference;
        else delete target.dataset.errorReference;
        return formatted.error;
      }

      function setStatus(target, message = '', state = '') {
        if (!target) return;
        target.classList.add('status');
        target.classList.remove('error', 'ok');
        if (state) target.classList.add(state);
        target.setAttribute('role', 'status');
        target.setAttribute('aria-live', 'polite');
        target.setAttribute('aria-atomic', 'true');
        target.textContent = translate(message);
        delete target.dataset.errorCode;
        delete target.dataset.errorReference;
      }

      function actionFeedback(button) {
        if (!button) return null;
        const owner = button.closest('[data-run-row], .case-workspace') || button.parentElement;
        let target = owner && owner.querySelector('[data-run-action-feedback]');
        if (target) return target;
        target = document.createElement('span');
        target.className = 'status';
        target.dataset.runActionFeedback = '';
        target.setAttribute('role', 'status');
        target.setAttribute('aria-live', 'polite');
        target.hidden = true;
        const container = button.closest('.actions, .case-actions') || button.parentElement;
        if (container) container.append(target);
        return target;
      }

      window.auditforgeCreateError = createError;
      window.auditforgeParseResponse = parseResponse;
      window.auditforgeRequestJson = requestJson;
      window.auditforgeShowError = showError;
      window.auditforgeSetStatus = setStatus;
      window.auditforgeActionFeedback = actionFeedback;
    })();
  </script>
"""


def render_login_document(token_path: Path | None, css: str) -> str:
    token_hint = f"本机凭据文件：{html.escape(str(token_path))}" if token_path else "请使用服务管理员提供的访问令牌。"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="AuditForge 安全审计工作台登录">
  <title>访问控制 | AuditForge</title>
  <style>{css}</style>
</head>
<body class="login-body">
  <main class="login-shell" id="main-content">
    <section class="login-brand" aria-labelledby="loginTitle">
      <div class="brand-lockup"><span class="brand-mark" aria-hidden="true">AF</span><span>AuditForge</span></div>
      <p class="page-kicker">CODE INTELLIGENCE</p>
      <h1 id="loginTitle">进入审计控制台</h1>
      <p>本地优先的代码证据、数据流与验证结果工作台。</p>
      <div class="login-signal" aria-label="安全边界">
        <span>本地会话</span><span>CSRF 防护</span><span>凭据不进入 URL</span>
      </div>
    </section>
    <section class="login-panel" aria-label="管理员认证">
      <div>
        <p class="page-kicker">ADMIN ACCESS</p>
        <h2>管理员令牌</h2>
        <p class="section-copy">令牌仅通过同源请求提交，成功后浏览器保存短期 HttpOnly 会话。</p>
      </div>
      <form id="login" class="login-form">
        <label for="token">访问令牌</label>
        <input id="token" name="token" type="password" autocomplete="off" required autofocus>
        <small>{token_hint}</small>
        <button class="primary" type="submit">验证并进入</button>
        <p class="status error" id="loginError" role="alert"></p>
      </form>
    </section>
  </main>
  {API_FEEDBACK_SCRIPT}
  <script>
    document.getElementById('login').addEventListener('submit', async (event) => {{
      event.preventDefault();
      const input = document.getElementById('token');
      const error = document.getElementById('loginError');
      const button = event.currentTarget.querySelector('button[type="submit"]');
      window.auditforgeSetStatus(error, '');
      button.disabled = true;
      button.textContent = '正在验证';
      try {{
        const data = await window.auditforgeRequestJson('/api/login', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json', 'Accept': 'application/json'}},
          body: JSON.stringify({{token: input.value}}),
        }}, '登录失败');
        if (data.ok !== true) {{
          throw window.auditforgeCreateError({{
            message: '服务返回了无法识别的响应。',
            code: 'RESPONSE_INVALID',
            action: '请刷新页面后重试；若问题持续，请查看运行日志。',
          }});
        }}
        input.value = '';
        window.location.replace('/');
      }} catch (reason) {{
        input.value = '';
        window.auditforgeShowError(error, reason, '登录失败');
        button.disabled = false;
        button.textContent = '验证并进入';
      }}
    }});
  </script>
</body>
</html>"""


def render_overview_body(
    overview: dict,
    runs: list[dict],
    render_run: Callable[[dict], str],
) -> str:
    severity_counts = overview.get("severity_counts") or {}
    total_severity = max(sum(int(severity_counts.get(key) or 0) for key in ("critical", "high", "medium", "low")), 1)
    risk_labels = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
    risk_rows = "".join(
        f"""
        <div class="risk-row risk-{level}">
          <span class="risk-name">{risk_labels[level]}</span>
          <span class="risk-track" aria-hidden="true"><i class="risk-fill" style="width:{round(int(severity_counts.get(level) or 0) / total_severity * 100)}%"></i></span>
          <strong class="risk-value">{int(severity_counts.get(level) or 0)}</strong>
        </div>"""
        for level in ("critical", "high", "medium", "low")
    )
    recent = "".join(render_run(run) for run in runs[:4])
    running = int((overview.get("status_counts") or {}).get("running") or 0)
    failed = int((overview.get("status_counts") or {}).get("failed") or 0)
    confirmed = int(overview.get("confirmed") or 0)
    return f"""
      <section class="forensic-hero">
        <div class="hero-copy">
          <p class="page-kicker">SECURITY OPERATIONS</p>
          <h1>代码审计控制台</h1>
          <p>把静态路径、依赖风险与运行时证据放在同一个可追溯工作区。</p>
        </div>
        <div class="hero-actions">
          <a class="primary-link" href="/scan">启动新扫描</a>
          <a href="/logs">查看运行日志</a>
        </div>
      </section>

      <section class="signal-grid" aria-label="审计概况">
        {stat_cell("累计扫描", overview.get("total_runs", 0), f"{overview.get('completed', 0)} 已完成")}
        {stat_cell("待复核风险", overview.get("total_risks", 0), f"{overview.get('dependency_findings', 0)} 依赖风险")}
        {stat_cell("运行时确认", confirmed, f"{overview.get('sandbox_reviewed', 0)} 沙箱待复核")}
        {stat_cell("平台状态", "运行中" if running else "就绪", f"{failed} 个失败任务")}
      </section>

      <section class="overview-layout">
        <article class="panel risk-board">
          <div class="section-heading">
            <div><p class="page-kicker">RISK QUEUE</p><h3>风险等级分布</h3></div>
            <a href="/history">全部任务</a>
          </div>
          <div class="risk-list">{risk_rows}</div>
        </article>
        <article class="panel command-panel">
          <div class="section-heading"><div><p class="page-kicker">PIPELINE</p><h3>分析模块</h3></div></div>
          <div class="module-list">
            {module_item("AST / DFG", "确定性分析", overview.get("total_candidates", 0))}
            {module_item("LLM", "语义候选", overview.get("llm_candidates", 0))}
            {module_item("SCA", "依赖风险", overview.get("dependency_findings", 0))}
            {module_item("VERIFY", "运行确认", overview.get("runtime_confirmed", 0))}
          </div>
        </article>
      </section>

      <section class="activity-section">
        <div class="section-heading">
          <div><p class="page-kicker">RECENT ACTIVITY</p><h3>最近扫描</h3></div>
          <a class="text-link" href="/history">查看扫描历史</a>
        </div>
        <div class="activity-list">
          {recent or empty_command("尚无扫描任务", "从一个本地仓库或 ZIP 代码包开始首次审计。", "/scan", "创建扫描")}
        </div>
      </section>"""


def render_scan_body(scan_form: str, llm_enabled: bool) -> str:
    llm_label = "已配置" if llm_enabled else "未启用"
    return f"""
      <section class="forensic-hero compact-hero">
        <div class="hero-copy">
          <p class="page-kicker">NEW ANALYSIS</p>
          <h1>创建扫描任务</h1>
          <p>选择代码来源、验证强度与语义分析模块。任务创建后自动进入实时进度页。</p>
        </div>
        <div class="system-signal"><span>LLM</span><strong>{llm_label}</strong></div>
      </section>
      <section class="scan-workbench">
        <article class="panel scan-form-panel">{scan_form}</article>
        <aside class="scan-guidance">
          <div class="section-heading"><div><p class="page-kicker">EXECUTION POLICY</p><h3>验证边界</h3></div></div>
          <div class="module-list">
            {policy_item("none", "只生成静态候选，不连接运行目标。")}
            {policy_item("safe", "仅发送同源 GET/HEAD 探测，不改变目标状态。")}
            {policy_item("stateful", "允许受控写入，仅适用于可丢弃隔离靶场。")}
            {policy_item("deep", "在固定镜像容器中执行代码片段级验证。")}
          </div>
          <p class="form-note">沙箱执行结果只进入待复核区，不会自动升级为已确认漏洞。</p>
        </aside>
      </section>"""


def render_history_body(runs: list[dict], render_run: Callable[[dict], str]) -> str:
    rows = "".join(render_run(run) for run in runs)
    return f"""
      <section class="forensic-hero compact-hero">
        <div class="hero-copy"><p class="page-kicker">CASE ARCHIVE</p><h1>任务档案</h1><p>每次扫描保留独立证据、报告、验证状态与人工处置记录。</p></div>
        <div class="hero-actions"><a class="primary-link" href="/scan">创建扫描</a></div>
      </section>
      <section class="activity-list history-list">
        {rows or empty_command("扫描历史为空", "创建任务后，运行状态和证据入口会出现在这里。", "/scan", "创建扫描")}
      </section>"""


def render_logs_body() -> str:
    return """
      <section class="forensic-hero compact-hero">
        <div class="hero-copy"><p class="page-kicker">LIVE TELEMETRY</p><h1>实时遥测</h1><p>实时观察服务、扫描阶段与失败原因。所有输出先经过敏感信息遮蔽。</p></div>
        <div class="system-signal"><span>BUFFER</span><strong>2,000 EVENTS</strong></div>
      </section>
      <section class="logs-console">
        <div class="logs-toolbar" aria-label="日志筛选和控制">
          <label for="logSearch">搜索日志<input class="search" id="logSearch" type="search" placeholder="event、message 或 context" autocomplete="off"></label>
          <label for="logLevel">最低级别<select id="logLevel"><option value="all">全部级别</option><option value="debug">DEBUG</option><option value="info">INFO</option><option value="warning">WARNING</option><option value="error">ERROR</option><option value="critical">CRITICAL</option></select></label>
          <div class="logs-actions"><button id="logPause" type="button" aria-pressed="false">暂停</button><button id="logClear" type="button">清屏</button></div>
        </div>
        <div class="logs-status-row"><span class="status" id="logsStatus" role="status" aria-live="polite" aria-atomic="true">正在连接日志流</span><span id="logsCount">显示 0 / 0</span></div>
        <div class="logs-stream" id="logsStream" aria-live="polite" aria-label="运行日志"><div class="logs-empty" id="logsEmpty">等待新的日志事件</div></div>
      </section>"""


def stat_cell(label: str, value: object, meta: str) -> str:
    return f'<article class="signal-item"><span class="stat-label">{html.escape(label)}</span><strong class="stat-value">{html.escape(str(value))}</strong><small class="stat-meta">{html.escape(meta)}</small></article>'


def module_item(code: str, label: str, value: object) -> str:
    return f'<div class="module-item"><code>{html.escape(code)}</code><span>{html.escape(label)}</span><strong>{html.escape(str(value))}</strong></div>'


def policy_item(code: str, description: str) -> str:
    return f'<div class="module-item policy-item"><code>{html.escape(code)}</code><span>{html.escape(description)}</span></div>'


def empty_command(title: str, body: str, href: str, action: str) -> str:
    return f'<div class="empty-command"><strong>{html.escape(title)}</strong><p>{html.escape(body)}</p><a href="{html.escape(href, quote=True)}">{html.escape(action)}</a></div>'
