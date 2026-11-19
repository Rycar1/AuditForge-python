from __future__ import annotations

from auditforge.ui_shell import render_navigation, render_page_header, render_shell_document


def test_navigation_keeps_primary_information_architecture_and_active_page() -> None:
    navigation = render_navigation("logs")

    for label in ("概况总览", "新建扫描", "扫描历史", "运行日志", "设置"):
        assert label in navigation
    assert '<a class="nav-link is-active" href="/logs" aria-current="page">运行日志</a>' in navigation
    assert navigation.count('aria-current="page"') == 1
    assert 'class="nav-primary"' in navigation
    assert 'class="nav-recent"' in navigation


def test_navigation_keeps_current_run_visible_and_escapes_run_data() -> None:
    current_id = 'run/"><'
    runs = [
        {"id": "newer", "name": "普通任务", "status": "completed"},
        {"id": current_id, "name": "<script>bad()</script> — review", "status": "running"},
    ]

    navigation = render_navigation("run", runs, current_run_id=current_id, max_recent=1)

    assert 'class="nav-link is-parent" href="/history"' in navigation
    assert 'class="nav-run is-current"' in navigation
    assert 'href="/runs/run%2F%22%3E%3C"' in navigation
    assert 'aria-current="page"' in navigation
    assert "<script>" not in navigation
    assert "&lt;script&gt;bad()&lt;/script&gt; - review" in navigation
    assert "—" not in navigation
    assert "–" not in navigation


def test_navigation_has_an_accessible_empty_recent_tasks_state() -> None:
    navigation = render_navigation("overview", ())

    assert 'id="nav-recent-label">最近任务</p>' in navigation
    assert '<p class="nav-empty">暂无最近任务</p>' in navigation
    assert 'class="nav-run"' not in navigation


def test_page_header_escapes_copy_and_structures_quick_actions() -> None:
    header = render_page_header(
        "<Audit> — logs",
        "one & two – evidence",
        actions=(
            {"label": "新建 <扫描>", "href": "/scan?from=logs&mode=safe", "primary": True},
            {"label": "不安全链接", "href": "javascript:alert(1)"},
        ),
    )

    assert "<h1>&lt;Audit&gt; - logs</h1>" in header
    assert "<p>one &amp; two - evidence</p>" in header
    assert 'class="page-header-actions" aria-label="页面快捷操作"' in header
    assert 'class="page-action is-primary" href="/scan?from=logs&amp;mode=safe"' in header
    assert 'class="page-action" href="#">不安全链接</a>' in header
    assert "javascript:" not in header


def test_shell_document_is_self_contained_responsive_and_semantic() -> None:
    document = render_shell_document(
        "运行日志 — 实时",
        '<section id="trusted-content">证据流 – 当前</section>',
        active_page="logs",
        page_subtitle="查看已脱敏的服务端事件",
        actions=({"label": "新建扫描", "href": "/scan", "primary": True},),
        recent_runs=({"id": "run-1", "name": "审计任务", "status": "completed"},),
        workspace_label="C:/work/<audit>",
        language='zh-CN" onload="bad',
        extra_script_html="<script>window.note = 'safe — copy';</script>",
    )

    assert document.startswith("<!doctype html>")
    assert '<html lang="zh-CN">' in document
    assert 'class="skip-link" href="#workspace-main"' in document
    assert 'class="app-shell"' in document
    assert 'class="command-bar"' in document
    assert 'class="side-rail"' in document
    assert 'class="workspace-main" id="workspace-main" tabindex="-1"' in document
    assert "AuditForge" in document
    assert "CODE INTELLIGENCE" in document
    assert 'aria-label="AuditForge / CODE INTELLIGENCE 首页"' in document
    assert '<span class="brand-separator" aria-hidden="true">/</span>' in document
    assert "height: 56px" in document
    assert "width: 224px" in document
    assert "@media (max-width: 760px)" in document
    assert "overflow-x: auto" in document
    assert '<section id="trusted-content">证据流 - 当前</section>' in document
    assert "C:/work/&lt;audit&gt;" in document
    assert "<link" not in document
    assert "http://" not in document
    assert "https://" not in document
    assert "—" not in document
    assert "–" not in document


def test_shell_document_escapes_structured_title_everywhere() -> None:
    document = render_shell_document(
        '<img src=x onerror="bad">',
        "<p>Trusted body</p>",
        active_page="overview",
    )

    assert "<img" not in document
    assert "&lt;img src=x onerror=&quot;bad&quot;&gt;" in document
    assert "<p>Trusted body</p>" in document
