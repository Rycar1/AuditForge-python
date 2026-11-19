"""Pure HTML composition for run status and evidence detail bodies.

Values read from run and scan mappings are always escaped. Arguments ending in
``_html`` are trusted, pre-rendered fragments supplied by the caller so their
interactive ``data-*`` hooks remain intact.
"""

from __future__ import annotations

import html
from collections.abc import Mapping


def render_run_status_body(
    run: Mapping[str, object],
    progress_html: str,
    inventory_html: str,
    delete_html: str,
    cancel_html: str = "",
) -> str:
    """Compose the body for an in-progress or failed audit case."""

    case_id = _text(run.get("id"), "unknown")
    case_name = _text(run.get("name"), case_id)
    status = _text(run.get("status"), "unknown")
    status_token = _status_token(status)
    verification = _text(run.get("verify"), "none")
    source = _text(run.get("source_label") or run.get("repo_path"), "未提供")
    error = _text(run.get("error"), "")
    error_html = f'<p class="case-alert" role="alert">{error}</p>' if error else ""

    return f"""
<article class="case-workspace run-status-case" data-case-id="{case_id}">
  <header class="case-header">
    <div class="case-identity">
      <p class="case-kicker">AUDIT CASE</p>
      <h1 id="case-title">{case_name}</h1>
      <p class="case-reference">任务 {case_id}</p>
    </div>
    <nav class="case-actions" aria-label="任务操作">
      <a href="/history">任务档案</a>
      <a href="/scan">新建扫描</a>
      {cancel_html}
      {delete_html}
    </nav>
  </header>
  <section class="telemetry-strip" aria-label="任务遥测">
    <div class="telemetry-item">
      <span>状态</span>
      <strong id="runStatusText" data-run-state="{status_token}">{status}</strong>
    </div>
    <div class="telemetry-item">
      <span>验证模式</span>
      <strong>{verification}</strong>
    </div>
    <div class="telemetry-item telemetry-wide">
      <span>代码来源</span>
      <strong>{source}</strong>
    </div>
  </section>
  {error_html}
  <section class="evidence-layout" aria-labelledby="case-title">
    <aside class="evidence-rail" aria-label="任务上下文">
      <section class="case-context">
        {inventory_html}
      </section>
      <section class="case-context">
        <h2>任务标识</h2>
        <dl>
          <div><dt>任务 ID</dt><dd>{case_id}</dd></div>
          <div><dt>当前状态</dt><dd>{status}</dd></div>
        </dl>
      </section>
    </aside>
    <section class="evidence-main" aria-labelledby="progress-title">
      <header class="evidence-heading">
        <p class="case-kicker">LIVE TELEMETRY</p>
        <h2 id="progress-title">扫描进度</h2>
      </header>
      <div class="evidence-panel" data-progress-region>
        {progress_html}
      </div>
    </section>
  </section>
</article>"""


def render_run_detail_body(
    run: Mapping[str, object],
    scan: Mapping[str, object],
    metrics_html: str,
    inventory_html: str,
    progress_html: str,
    diagnostics_html: str,
    result_tabs_html: str,
    result_sections_html: str,
    actions_html: str,
) -> str:
    """Compose the evidence workspace for a completed audit case."""

    case_id = _text(run.get("id"), "unknown")
    case_name = _text(run.get("name"), case_id)
    status = _text(run.get("status"), "unknown")
    status_token = _status_token(status)
    repository = _text(scan.get("repo_path") or run.get("repo_path"), "未知仓库")
    target = _text(scan.get("target_url"), "未配置")
    verification = _text(run.get("verify"), "none")

    return f"""
<article class="case-workspace run-detail-case" data-case-id="{case_id}">
  <header class="case-header">
    <div class="case-identity">
      <p class="case-kicker">EVIDENCE WORKSPACE</p>
      <h1 id="case-title">{case_name}</h1>
      <p class="case-reference">{repository}</p>
    </div>
    <nav class="case-actions" aria-label="任务操作">
      {actions_html}
    </nav>
  </header>
  <section class="telemetry-strip" aria-label="任务遥测">
    <div class="telemetry-item">
      <span>状态</span>
      <strong data-run-state="{status_token}">{status}</strong>
    </div>
    <div class="telemetry-item">
      <span>验证模式</span>
      <strong>{verification}</strong>
    </div>
    <div class="telemetry-item telemetry-wide">
      <span>运行目标</span>
      <strong>{target}</strong>
    </div>
  </section>
  <section class="evidence-layout" aria-labelledby="case-title">
    <aside class="evidence-rail" aria-label="任务上下文">
      <section class="case-context">
        <h2>代码仓库</h2>
        <p>{repository}</p>
        <dl>
          <div><dt>任务 ID</dt><dd>{case_id}</dd></div>
          <div><dt>运行目标</dt><dd>{target}</dd></div>
        </dl>
      </section>
      <section class="case-context">
        {inventory_html}
      </section>
      <section class="case-context">
        <h2>扫描指标</h2>
        <div class="case-metrics">{metrics_html}</div>
      </section>
      <section class="case-context">
        <h2>执行进度</h2>
        {progress_html}
      </section>
      <section class="case-context">
        <h2>诊断信息</h2>
        {diagnostics_html}
      </section>
    </aside>
    <section class="evidence-main" aria-labelledby="evidence-title">
      <header class="evidence-heading">
        <p class="case-kicker">COLLECTED FINDINGS</p>
        <h2 id="evidence-title">证据复核</h2>
      </header>
      <section class="evidence-controls" aria-label="证据分区">
        {result_tabs_html}
      </section>
      <section class="evidence-results" aria-live="polite">
        {result_sections_html}
      </section>
    </section>
  </section>
  <div class="finding-drawer" id="findingDrawer" data-finding-drawer hidden>
    <button class="finding-drawer-backdrop" type="button" data-finding-close aria-label="关闭漏洞详情"></button>
    <aside class="finding-drawer-panel" role="dialog" aria-modal="true" aria-labelledby="findingDrawerTitle">
      <header class="finding-drawer-header">
        <div>
          <p class="case-kicker">FINDING DETAIL</p>
          <h2 id="findingDrawerTitle" data-finding-drawer-title>漏洞详情</h2>
        </div>
        <button class="finding-drawer-close" type="button" data-finding-close aria-label="关闭漏洞详情">关闭</button>
      </header>
      <div class="finding-drawer-body" data-finding-drawer-body></div>
    </aside>
  </div>
</article>"""


def _text(value: object, fallback: str) -> str:
    raw = str(value).strip() if value is not None else ""
    return html.escape(raw or fallback, quote=True)


def _status_token(value: str) -> str:
    normalized = html.unescape(value).lower()
    return normalized if normalized in {"pending", "running", "completed", "failed"} else "unknown"
