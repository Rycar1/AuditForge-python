from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from urllib.parse import quote

__all__ = ["SHELL_CSS", "render_navigation", "render_page_header", "render_shell_document"]


PRIMARY_NAVIGATION = (
    ("overview", "概况总览", "/"),
    ("scan", "新建扫描", "/scan"),
    ("history", "扫描历史", "/history"),
    ("logs", "运行日志", "/logs"),
    ("settings", "设置", "/settings"),
)

RUN_STATUS_LABELS = {
    "completed": "已完成",
    "running": "运行中",
    "failed": "失败",
    "pending": "等待中",
    "queued": "等待中",
}

SHELL_CSS = r"""
:root {
  color-scheme: dark;
  --shell-bg: #0b0f12;
  --shell-surface: #101519;
  --shell-surface-raised: #151b20;
  --shell-border: #293138;
  --shell-border-strong: #3a444b;
  --shell-text: #edf2f4;
  --shell-muted: #9aa7ad;
  --shell-accent: #d4a64e;
  --shell-accent-ink: #17130b;
  --command-height: 56px;
  --rail-width: 224px;
  --shell-radius: 4px;
  --font-sans: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
}

* {
  box-sizing: border-box;
}

html {
  min-height: 100%;
  background: var(--shell-bg);
}

body {
  min-width: 320px;
  min-height: 100dvh;
  margin: 0;
  background: var(--shell-bg);
  color: var(--shell-text);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.5;
  text-rendering: optimizeLegibility;
}

a {
  color: inherit;
}

.skip-link {
  position: fixed;
  top: 8px;
  left: 8px;
  z-index: 100;
  padding: 8px 12px;
  border: 1px solid var(--shell-accent);
  border-radius: var(--shell-radius);
  background: var(--shell-accent);
  color: var(--shell-accent-ink);
  font-weight: 700;
  transform: translateY(-160%);
}

.skip-link:focus {
  transform: translateY(0);
}

.app-shell {
  display: grid;
  grid-template-columns: var(--rail-width) minmax(0, 1fr);
  grid-template-rows: var(--command-height) minmax(calc(100dvh - var(--command-height)), auto);
  min-height: 100dvh;
}

.command-bar {
  position: sticky;
  top: 0;
  z-index: 20;
  grid-column: 1 / -1;
  grid-row: 1;
  display: grid;
  grid-template-columns: var(--rail-width) minmax(0, 1fr);
  height: 56px;
  border-bottom: 1px solid var(--shell-border-strong);
  background: #0d1215;
}

.command-brand {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  padding: 0 16px;
  border-right: 1px solid var(--shell-border-strong);
  text-decoration: none;
}

.brand-name {
  color: var(--shell-text);
  font-size: 16px;
  font-weight: 760;
  letter-spacing: -0.02em;
}

.brand-discipline {
  color: var(--shell-accent);
  font-family: var(--font-mono);
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.brand-separator {
  color: var(--shell-border-strong);
  font-family: var(--font-mono);
  font-size: 12px;
}

.command-page {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 12px;
  padding: 0 24px;
}

.command-page span {
  color: var(--shell-muted);
  font-family: var(--font-mono);
  font-size: 10px;
}

.command-page strong {
  overflow: hidden;
  color: var(--shell-text);
  font-size: 13px;
  font-weight: 650;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.side-rail {
  position: sticky;
  top: var(--command-height);
  grid-column: 1;
  grid-row: 2;
  display: flex;
  width: 224px;
  height: calc(100dvh - var(--command-height));
  min-height: 0;
  flex-direction: column;
  overflow-y: auto;
  border-right: 1px solid var(--shell-border-strong);
  background: #0d1215;
  scrollbar-color: var(--shell-border-strong) transparent;
}

.nav-groups {
  display: flex;
  min-height: 0;
  flex: 1;
  flex-direction: column;
}

.nav-primary {
  padding: 14px 12px;
}

.nav-list,
.nav-recent-list {
  display: flex;
  margin: 0;
  padding: 0;
  flex-direction: column;
  gap: 3px;
  list-style: none;
}

.nav-link,
.nav-run {
  display: flex;
  min-width: 0;
  border: 1px solid transparent;
  border-radius: var(--shell-radius);
  color: var(--shell-muted);
  text-decoration: none;
}

.nav-link {
  align-items: center;
  min-height: 38px;
  padding: 8px 10px;
  font-weight: 620;
}

.nav-link:hover,
.nav-run:hover {
  border-color: var(--shell-border);
  background: var(--shell-surface-raised);
  color: var(--shell-text);
}

.nav-link:focus-visible,
.nav-run:focus-visible,
.command-brand:focus-visible,
.page-action:focus-visible {
  outline: 2px solid var(--shell-accent);
  outline-offset: 2px;
}

.nav-link.is-active,
.nav-link.is-parent {
  color: var(--shell-text);
}

.nav-link.is-active {
  border-color: #4f4126;
  background: #211c12;
}

.nav-link.is-active::before {
  width: 2px;
  height: 16px;
  margin-right: 8px;
  background: var(--shell-accent);
  content: "";
}

.nav-recent {
  padding: 14px 12px 18px;
  border-top: 1px solid var(--shell-border);
}

.nav-section-label {
  margin: 0 0 8px;
  color: var(--shell-muted);
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.nav-run {
  flex-direction: column;
  gap: 2px;
  padding: 8px 10px;
}

.nav-run.is-current {
  border-color: var(--shell-border-strong);
  background: var(--shell-surface-raised);
  color: var(--shell-text);
}

.nav-run-name {
  overflow: hidden;
  font-size: 12px;
  font-weight: 620;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.nav-run-meta,
.nav-empty {
  color: var(--shell-muted);
  font-family: var(--font-mono);
  font-size: 10px;
}

.nav-empty {
  margin: 0;
  padding: 8px 10px;
}

.nav-footer {
  padding: 12px 16px;
  border-top: 1px solid var(--shell-border);
  color: var(--shell-muted);
}

.nav-footer span {
  display: block;
  margin-bottom: 3px;
  font-family: var(--font-mono);
  font-size: 9px;
}

.nav-footer code {
  display: block;
  overflow: hidden;
  color: var(--shell-text);
  font-family: var(--font-mono);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.workspace-main {
  grid-column: 2;
  grid-row: 2;
  min-width: 0;
  padding: 30px clamp(20px, 4vw, 56px) 56px;
  background: var(--shell-bg);
}

.workspace-main:focus {
  outline: none;
}

.workspace-frame {
  width: min(100%, 1440px);
  margin: 0 auto;
}

.page-header {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 28px;
  margin-bottom: 28px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--shell-border-strong);
}

.page-header-copy {
  min-width: 0;
}

.page-header h1 {
  margin: 0;
  color: var(--shell-text);
  font-size: clamp(24px, 3vw, 36px);
  font-weight: 720;
  letter-spacing: -0.035em;
  line-height: 1.08;
}

.page-header p {
  max-width: 68ch;
  margin: 9px 0 0;
  color: var(--shell-muted);
}

.page-header-actions {
  display: flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 8px;
}

.page-action {
  display: inline-flex;
  min-height: 36px;
  align-items: center;
  justify-content: center;
  padding: 7px 12px;
  border: 1px solid var(--shell-border-strong);
  border-radius: var(--shell-radius);
  background: var(--shell-surface);
  color: var(--shell-text);
  font-size: 12px;
  font-weight: 680;
  text-decoration: none;
  white-space: nowrap;
}

.page-action:hover {
  border-color: var(--shell-accent);
}

.page-action.is-primary {
  border-color: var(--shell-accent);
  background: var(--shell-accent);
  color: var(--shell-accent-ink);
}

@media (max-width: 760px) {
  .app-shell {
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: var(--command-height) auto minmax(0, 1fr);
  }

  .command-bar {
    grid-template-columns: minmax(0, auto) minmax(0, 1fr);
  }

  .command-brand {
    padding: 0 12px;
  }

  .brand-discipline,
  .brand-separator,
  .command-page span {
    display: none;
  }

  .command-page {
    justify-content: flex-end;
    padding: 0 12px;
  }

  .side-rail {
    position: relative;
    top: auto;
    grid-column: 1;
    grid-row: 2;
    display: block;
    width: 100%;
    height: auto;
    overflow-x: auto;
    overflow-y: hidden;
    border-right: 0;
    border-bottom: 1px solid var(--shell-border-strong);
    white-space: nowrap;
  }

  .nav-groups {
    width: max-content;
    flex-direction: row;
    align-items: stretch;
  }

  .nav-primary,
  .nav-recent {
    padding: 8px 10px;
  }

  .nav-primary .nav-list,
  .nav-recent-list {
    flex-direction: row;
  }

  .nav-recent {
    display: flex;
    align-items: center;
    gap: 8px;
    border-top: 0;
    border-left: 1px solid var(--shell-border);
  }

  .nav-section-label {
    margin: 0 4px 0 0;
  }

  .nav-link {
    min-height: 34px;
    padding: 6px 9px;
  }

  .nav-link.is-active::before {
    display: none;
  }

  .nav-run {
    min-width: 132px;
    max-width: 180px;
    padding: 6px 9px;
  }

  .nav-empty {
    padding: 6px 9px;
  }

  .nav-footer {
    display: none;
  }

  .workspace-main {
    grid-column: 1;
    grid-row: 3;
    padding: 24px 16px 44px;
  }

  .page-header {
    align-items: stretch;
    flex-direction: column;
    gap: 16px;
  }

  .page-header-actions {
    max-width: 100%;
    overflow-x: auto;
  }
}
"""


def render_navigation(
    active_page: str,
    recent_runs: Sequence[Mapping[str, object]] = (),
    *,
    current_run_id: str | None = None,
    max_recent: int = 6,
) -> str:
    """Render primary navigation and the secondary recent-run navigation."""

    active = str(active_page or "overview").strip().lower()
    active_run_id = current_run_id if active == "run" else None
    selected_runs = _select_recent_runs(recent_runs, active_run_id, max_recent=max_recent)
    primary_links: list[str] = []
    for key, label, href in PRIMARY_NAVIGATION:
        is_current = active == key
        is_parent = key == "history" and active == "run"
        classes = "nav-link"
        if is_current:
            classes += " is-active"
        elif is_parent:
            classes += " is-parent"
        current_attribute = ' aria-current="page"' if is_current else ""
        primary_links.append(f'<li><a class="{classes}" href="{href}"{current_attribute}>{_escape_text(label)}</a></li>')

    run_links = "".join(_render_recent_run(run, current_run_id=active_run_id) for run in selected_runs)
    if not run_links:
        run_links = '<li><p class="nav-empty">暂无最近任务</p></li>'

    return f"""<div class="nav-groups">
  <nav class="nav-primary" aria-label="主导航">
    <ul class="nav-list">{"".join(primary_links)}</ul>
  </nav>
  <nav class="nav-recent" aria-labelledby="nav-recent-label">
    <p class="nav-section-label" id="nav-recent-label">最近任务</p>
    <ul class="nav-recent-list">{run_links}</ul>
  </nav>
</div>"""


def render_page_header(
    title: str,
    subtitle: str = "",
    *,
    actions: Sequence[Mapping[str, object]] = (),
) -> str:
    """Render a page heading and structured internal-link actions."""

    safe_title = _escape_text(title, fallback="AuditForge")
    clean_subtitle = _clean_text(subtitle)
    subtitle_html = f"<p>{html.escape(clean_subtitle)}</p>" if clean_subtitle else ""
    actions_html = _render_actions(actions)
    return f"""<header class="page-header">
  <div class="page-header-copy">
    <h1>{safe_title}</h1>
    {subtitle_html}
  </div>
  {actions_html}
</header>"""


def render_shell_document(
    page_title: str,
    body_html: str,
    *,
    active_page: str,
    page_subtitle: str = "",
    actions: Sequence[Mapping[str, object]] = (),
    recent_runs: Sequence[Mapping[str, object]] = (),
    current_run_id: str | None = None,
    workspace_label: str | None = None,
    language: str = "zh-CN",
    extra_head_html: str = "",
    extra_script_html: str = "",
    include_page_header: bool = True,
) -> str:
    """Render a complete self-contained application shell document.

    ``body_html``, ``extra_head_html`` and ``extra_script_html`` are trusted
    integration fragments. All structured shell data is escaped independently.
    """

    clean_title = _clean_text(page_title) or "AuditForge"
    safe_title = html.escape(clean_title)
    safe_language = html.escape(_clean_language(language), quote=True)
    navigation = render_navigation(
        active_page,
        recent_runs,
        current_run_id=current_run_id,
    )
    page_header = render_page_header(clean_title, page_subtitle, actions=actions) if include_page_header else ""
    workspace_footer = ""
    clean_workspace = _clean_text(workspace_label)
    if clean_workspace:
        workspace_footer = (
            '<footer class="nav-footer"><span>工作区</span>'
            f'<code title="{html.escape(clean_workspace, quote=True)}">{html.escape(clean_workspace)}</code></footer>'
        )

    return f"""<!doctype html>
<html lang="{safe_language}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>{safe_title} | AuditForge</title>
  <style>{SHELL_CSS}</style>
  {_without_long_dashes(extra_head_html)}
</head>
<body>
  <a class="skip-link" href="#workspace-main">跳到主要内容</a>
  <div class="app-shell">
    <header class="command-bar">
      <a class="command-brand" href="/" aria-label="AuditForge / CODE INTELLIGENCE 首页">
        <span class="brand-name">AuditForge</span>
        <span class="brand-separator" aria-hidden="true">/</span>
        <span class="brand-discipline">CODE INTELLIGENCE</span>
      </a>
      <div class="command-page" aria-label="当前页面">
        <span>当前页面</span>
        <strong>{safe_title}</strong>
      </div>
    </header>
    <aside class="side-rail" aria-label="应用导航">
      {navigation}
      {workspace_footer}
    </aside>
    <main class="workspace-main" id="workspace-main" tabindex="-1">
      <div class="workspace-frame">
        {page_header}
        {_without_long_dashes(body_html)}
      </div>
    </main>
  </div>
  {_without_long_dashes(extra_script_html)}
</body>
</html>"""


def _render_actions(actions: Sequence[Mapping[str, object]]) -> str:
    links: list[str] = []
    for action in actions:
        if not isinstance(action, Mapping):
            continue
        label = _clean_text(action.get("label"))
        if not label:
            continue
        href = _safe_internal_href(action.get("href"))
        classes = "page-action is-primary" if bool(action.get("primary")) else "page-action"
        links.append(f'<a class="{classes}" href="{href}">{html.escape(label)}</a>')
    if not links:
        return ""
    return f'<nav class="page-header-actions" aria-label="页面快捷操作">{"".join(links)}</nav>'


def _render_recent_run(run: Mapping[str, object], *, current_run_id: str | None) -> str:
    run_id = str(run.get("id") or "").strip()
    if not run_id:
        return ""
    name = _clean_text(run.get("name")) or _clean_text(run_id) or "未命名任务"
    status_value = str(run.get("status") or "").strip().lower()
    status = RUN_STATUS_LABELS.get(status_value, _clean_text(status_value) or "状态未知")
    is_current = run_id == str(current_run_id or "")
    classes = "nav-run is-current" if is_current else "nav-run"
    current_attribute = ' aria-current="page"' if is_current else ""
    safe_data_id = html.escape(_clean_text(run_id), quote=True)
    href = "/runs/" + quote(run_id, safe="")
    aria_label = html.escape(f"{name}, {status}", quote=True)
    return f"""<li><a class="{classes}" href="{href}" data-run-id="{safe_data_id}" aria-label="{aria_label}"{current_attribute}>
  <span class="nav-run-name">{html.escape(name)}</span>
  <span class="nav-run-meta">{html.escape(status)}</span>
</a></li>"""


def _select_recent_runs(
    recent_runs: Sequence[Mapping[str, object]],
    current_run_id: str | None,
    *,
    max_recent: int,
) -> list[Mapping[str, object]]:
    try:
        limit = max(0, min(12, int(max_recent)))
    except (TypeError, ValueError):
        limit = 6
    if not limit:
        return []
    valid_runs = [run for run in recent_runs if isinstance(run, Mapping) and str(run.get("id") or "").strip()]
    current_id = str(current_run_id or "")
    current = next((run for run in valid_runs if str(run.get("id") or "") == current_id), None)
    selected = valid_runs[:limit]
    if current is not None and current not in selected:
        selected = [current, *selected[: limit - 1]]
    return selected


def _clean_language(value: object) -> str:
    language = str(value or "zh-CN").strip()
    if language and all(character.isalnum() or character == "-" for character in language):
        return language
    return "zh-CN"


def _clean_text(value: object) -> str:
    return _without_long_dashes(str(value or "")).strip()


def _escape_text(value: object, *, fallback: str = "") -> str:
    return html.escape(_clean_text(value) or fallback)


def _safe_internal_href(value: object) -> str:
    href = _clean_text(value)
    if any(ord(character) < 32 for character in href) or "\\" in href:
        return "#"
    if href.startswith("/") and not href.startswith("//"):
        return html.escape(href, quote=True)
    if href.startswith("#") and len(href) > 1:
        return html.escape(href, quote=True)
    return "#"


def _without_long_dashes(value: str) -> str:
    return str(value or "").replace("\u2014", "-").replace("\u2013", "-")
