"""DOM acceptance contract for the upcoming frontend redesign.

These tests intentionally describe the target shell and may remain red until
the production renderers are migrated. Business hooks are asserted separately
so visual work cannot silently break scans, settings, logs, or run triage.
"""

from __future__ import annotations

import json
import sqlite3
from html.parser import HTMLParser
from urllib.parse import urlsplit

import pytest

from auditforge import server, server_ui
from auditforge.store import SCHEMA

CORE_PAGES = ("overview", "scan", "history", "logs", "settings", "run_status", "run_detail")
SHELL_CLASSES = {"app-shell", "command-bar", "side-rail", "workspace-main"}
OLD_THEME_TOKENS = {
    "#f4f5f2",
    "#f9faf8",
    "#20231f",
    "#6f766d",
    "#dfe3dc",
    "#0d7f6e",
    "#07594d",
    "#e2f3ef",
}


class DOMSnapshot(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    @property
    def classes(self) -> set[str]:
        return {class_name for _, attrs in self.elements for class_name in str(attrs.get("class") or "").split() if class_name}

    @property
    def ids(self) -> set[str]:
        return {str(attrs["id"]) for _, attrs in self.elements if attrs.get("id")}

    @property
    def names(self) -> set[str]:
        return {str(attrs["name"]) for _, attrs in self.elements if attrs.get("name")}

    @property
    def data_attributes(self) -> set[str]:
        return {name for _, attrs in self.elements for name in attrs if name.startswith("data-")}


def parse_dom(document: str) -> DOMSnapshot:
    snapshot = DOMSnapshot()
    snapshot.feed(document)
    return snapshot


@pytest.fixture(scope="module")
def rendered_pages(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    assert server.render_overview_page is server_ui.render_overview_page
    workspace = tmp_path_factory.mktemp("frontend-redesign")
    repo = workspace / "repo"
    run_workspace = workspace / "runs" / "run-1"
    repo.mkdir()
    run_workspace.mkdir(parents=True)
    (repo / "app.py").write_text("query = input()\nexecute(query)\n", encoding="utf-8")

    candidate = {
        "id": "INJECTION-TRACE-001",
        "vuln_class": "injection",
        "confidence": "high",
        "source": {
            "file": "app.py",
            "start_line": 1,
            "end_line": 1,
            "snippet_hash": "source-hash",
            "symbol": "http_query",
        },
        "sink": {
            "file": "app.py",
            "start_line": 2,
            "end_line": 2,
            "snippet_hash": "sink-hash",
            "symbol": "raw_sql",
        },
        "steps": [],
        "sanitizers": [],
        "blockers": [],
        "static_evidence": "test evidence",
        "verification_hint": "review in an isolated environment",
        "origin": "deterministic",
    }
    stats = {"files": 1, "candidates": 1, "verification_results": 0}
    con = sqlite3.connect(run_workspace / "auditforge.db")
    try:
        con.executescript(SCHEMA)
        con.execute(
            "INSERT INTO scans (id, repo_path, target_url, stats_json) VALUES (1, ?, NULL, ?)",
            (str(repo), json.dumps(stats)),
        )
        con.execute(
            """
            INSERT INTO candidates
            (id, vuln_class, confidence, source_file, source_line, sink_file, sink_line, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                candidate["id"],
                candidate["vuln_class"],
                candidate["confidence"],
                "app.py",
                1,
                "app.py",
                2,
                json.dumps(candidate),
            ),
        )
        con.execute(
            "INSERT INTO artifacts (name, payload_json) VALUES (?, ?)",
            ("project_inventory", json.dumps({"total_lines": 2, "file_count": 1, "languages": []})),
        )
        con.commit()
    finally:
        con.close()

    (run_workspace / "trace_candidates.json").write_text(json.dumps([candidate]), encoding="utf-8")
    (run_workspace / "verification_results.json").write_text("[]", encoding="utf-8")
    run = {
        "id": "run-1",
        "name": "Contract run",
        "status": "completed",
        "workspace": "runs/run-1",
        "repo_path": str(repo),
        "source_type": "path",
        "source_label": str(repo),
        "verify": "none",
        "dependency_scan": False,
        "created_at": "2026-07-15T00:00:00+00:00",
        "stats": stats,
        "project_inventory": {"total_lines": 2, "file_count": 1, "languages": []},
    }
    (workspace / "auditforge_runs.json").write_text(json.dumps({"runs": [run]}), encoding="utf-8")
    running = {**run, "status": "running", "stats": {}}

    return {
        "overview": server_ui.render_overview_page(workspace),
        "scan": server_ui.render_scan_page(workspace),
        "history": server_ui.render_history_page(workspace),
        "logs": server_ui.render_logs_page(workspace),
        "settings": server_ui.render_settings_page(workspace),
        "run_status": server_ui.render_run_status_page(workspace, running),
        "run_detail": server_ui.render_run_detail_page(workspace, run_workspace, run),
    }


@pytest.mark.parametrize("page_name", CORE_PAGES)
def test_core_pages_use_new_accessible_shell(page_name: str, rendered_pages: dict[str, str]) -> None:
    dom = parse_dom(rendered_pages[page_name])
    problems: list[str] = []
    missing_classes = sorted(SHELL_CLASSES - dom.classes)
    if missing_classes:
        problems.append(f"missing shell classes: {', '.join(missing_classes)}")
    skip_links = [
        attrs
        for tag, attrs in dom.elements
        if tag == "a" and attrs.get("href") == "#workspace-main" and "skip-link" in str(attrs.get("class") or "").split()
    ]
    if not skip_links:
        problems.append("missing .skip-link to #workspace-main")
    if "workspace-main" not in dom.ids:
        problems.append("missing #workspace-main target")
    if not any(attrs.get("aria-current") == "page" for _, attrs in dom.elements):
        problems.append("active navigation lacks aria-current=page")
    assert not problems, f"{page_name}: {'; '.join(problems)}"


@pytest.mark.parametrize("page_name", CORE_PAGES)
def test_core_pages_are_self_contained(page_name: str, rendered_pages: dict[str, str]) -> None:
    dom = parse_dom(rendered_pages[page_name])
    external: list[str] = []
    for tag, attrs in dom.elements:
        candidates: list[str] = []
        if tag in {"script", "img", "iframe", "source", "video", "audio"} and attrs.get("src"):
            candidates.append(str(attrs["src"]))
        if tag == "link" and attrs.get("href"):
            candidates.append(str(attrs["href"]))
        for value in candidates:
            parsed = urlsplit(value)
            if parsed.scheme in {"http", "https"} or value.startswith("//"):
                external.append(value)
    document = rendered_pages[page_name].lower()
    if "url(http://" in document or "url(https://" in document or "@import url" in document:
        external.append("external CSS resource")
    assert not external, f"{page_name} references external resources: {external}"


@pytest.mark.parametrize("page_name", CORE_PAGES)
def test_core_pages_drop_legacy_palette(page_name: str, rendered_pages: dict[str, str]) -> None:
    lowered = rendered_pages[page_name].lower()
    legacy = sorted(token for token in OLD_THEME_TOKENS if token in lowered)
    assert not legacy, f"{page_name} still contains legacy theme tokens: {legacy}"


@pytest.mark.parametrize("page_name", CORE_PAGES)
def test_core_pages_avoid_long_dash_characters(page_name: str, rendered_pages: dict[str, str]) -> None:
    document = rendered_pages[page_name]
    assert "\N{EN DASH}" not in document, f"{page_name} contains an en dash"
    assert "\N{EM DASH}" not in document, f"{page_name} contains an em dash"


def test_business_dom_hooks_survive_visual_redesign(rendered_pages: dict[str, str]) -> None:
    pages = {name: parse_dom(document) for name, document in rendered_pages.items()}

    assert {"scanForm", "sourcePath", "sourceUpload", "scanStatus"} <= pages["scan"].ids
    assert {"name", "sourceType", "repoPath", "repoZip", "verify", "targetUrl", "useLlm", "scanDependencies"} <= pages["scan"].names

    assert {"data-run-row", "data-delete-run", "data-run-id"} <= pages["history"].data_attributes
    assert {"runStatusText"} <= pages["run_status"].ids
    assert {"data-progress-stage", "data-progress-error"} <= pages["run_status"].data_attributes

    assert {"candidateSearch", "emptyState"} <= pages["run_detail"].ids
    assert {
        "data-candidate-toolbar",
        "data-filter",
        "data-result-tab",
        "data-triage-candidate",
        "data-triage-save",
        "data-finding-open",
        "data-finding-detail",
        "data-finding-drawer",
    } <= pages["run_detail"].data_attributes

    assert {
        "settingsForm",
        "connectionProvider",
        "connectionBaseUrl",
        "connectionApiKey",
        "languageSelect",
        "taintModel",
        "dependencyModel",
        "deepModel",
    } <= pages["settings"].ids

    assert {"logLevel", "logSearch", "logPause", "logClear", "logsStream"} <= pages["logs"].ids
    assert {"data-run-row"} <= pages["overview"].data_attributes


def test_run_detail_opens_the_nonempty_candidate_queue(rendered_pages: dict[str, str]) -> None:
    dom = parse_dom(rendered_pages["run_detail"])
    candidate_tab = [attrs for _, attrs in dom.elements if attrs.get("data-result-tab") == "candidate"]
    candidate_panel = [attrs for _, attrs in dom.elements if attrs.get("data-result-panel") == "candidate"]
    toolbar = [attrs for _, attrs in dom.elements if "data-candidate-toolbar" in attrs]

    assert len(candidate_tab) == len(candidate_panel) == len(toolbar) == 1
    assert "active" in str(candidate_tab[0].get("class") or "").split()
    assert candidate_tab[0].get("aria-selected") == "true"
    assert "hidden" not in candidate_panel[0]
    assert "hidden" not in toolbar[0]
    assert "evidence-controls" in dom.classes


def test_redesign_css_has_keyboard_and_motion_accessibility() -> None:
    css = server_ui.APP_CSS.lower()

    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert "@media" in css and "max-width" in css


def test_finding_details_use_one_safe_side_drawer() -> None:
    script = server_ui.FINDING_DRAWER_SCRIPT

    assert "[data-finding-open]" in script
    assert "[data-finding-detail]" in script
    assert "drawerBody.append(detail)" in script
    assert "event.key === 'Escape'" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script


def test_log_dom_contract_remains_xss_safe(rendered_pages: dict[str, str]) -> None:
    script = server_ui.LOGS_SCRIPT
    logs_dom = parse_dom(rendered_pages["logs"])

    assert "/api/logs?after=" in script
    assert "document.createElement" in script
    assert ".textContent" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert {"logLevel", "logSearch", "logPause", "logClear", "logsStream"} <= logs_dom.ids
