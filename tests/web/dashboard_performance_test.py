from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from auditforge.reporting.store import (
    DASHBOARD_DETAIL_ARTIFACTS,
    SCHEMA,
    read_dashboard_data,
    read_dashboard_detail,
    read_dashboard_summary,
)
from auditforge.web import server
from auditforge.web.ui import server_ui


def create_run_store(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(run_dir / "auditforge.db")
    try:
        con.executescript(SCHEMA)
        con.execute(
            "INSERT INTO scans (id, repo_path, target_url, stats_json) VALUES (1, ?, NULL, ?)",
            ("C:/repo", json.dumps({"files": 1, "dependency_findings": 1})),
        )
        for name, payload in {
            "graph": {"nodes": ["large-graph-payload"], "edges": []},
            "facts": {"files": ["large-facts-payload"]},
            "dependency_findings": [{"id": "DEP-001", "severity": "high"}],
            "project_inventory": {"total_lines": 1, "file_count": 1, "languages": []},
        }.items():
            con.execute("INSERT INTO artifacts (name, payload_json) VALUES (?, ?)", (name, json.dumps(payload)))
        con.commit()
    finally:
        con.close()


def test_dashboard_detail_excludes_large_facts_and_graph(tmp_path: Path) -> None:
    create_run_store(tmp_path)

    detail = read_dashboard_detail(tmp_path)
    full = read_dashboard_data(tmp_path)

    assert set(detail["artifacts"]) <= set(DASHBOARD_DETAIL_ARTIFACTS)
    assert "graph" not in detail["artifacts"]
    assert "facts" not in detail["artifacts"]
    assert "graph" in full["artifacts"]
    assert read_dashboard_summary(tmp_path)["scan"]["repo_path"] == "C:/repo"


def test_run_discovery_uses_scan_summary_without_hydrating_graph(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "large-run"
    create_run_store(run_dir)
    (run_dir / "scan_complete.json").write_text(
        json.dumps({"completed_at": "2026-07-16T00:00:00+00:00", "repo_path": "C:/repo", "stats": {"files": 1}}),
        encoding="utf-8",
    )

    record = server.run_record_from_directory(workspace, run_dir)

    assert record is not None
    assert record["stats"]["files"] == 1
    assert record["repo_path"] == "C:/repo"


def test_overview_prefers_dependency_json_before_database_hydration(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "run-1"
    create_run_store(run_dir)
    (run_dir / "dependency_findings.json").write_text(json.dumps([{"id": "DEP-001", "severity": "high"}]), encoding="utf-8")
    run = {"id": "run-1", "workspace": "runs/run-1", "status": "completed", "stats": {"dependency_findings": 1}}

    monkeypatch.setattr(server_ui, "read_dashboard_detail", lambda _workspace: (_ for _ in ()).throw(AssertionError("unexpected db read")))

    findings = server_ui.load_run_dependency_findings(workspace, run)

    assert findings == [{"id": "DEP-001", "severity": "high"}]


def test_invalid_run_registry_is_backed_up_and_rebuilt_from_run_directories(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "recovered-run"
    run_dir.mkdir(parents=True)
    (run_dir / "scan_complete.json").write_text(
        json.dumps({"completed_at": "2026-07-16T00:00:00+00:00", "repo_path": "C:/repo", "stats": {"files": 1}}),
        encoding="utf-8",
    )
    registry = workspace / "auditforge_runs.json"
    registry.write_text('{"runs":[invalid', encoding="utf-8")

    runs = server.load_runs(workspace)

    repaired = json.loads(registry.read_text(encoding="utf-8"))
    assert [run["id"] for run in runs] == ["recovered-run"]
    assert repaired["runs"][0]["id"] == "recovered-run"
    assert (workspace / "auditforge_runs.corrupt.json").read_text(encoding="utf-8") == '{"runs":[invalid'


def test_find_run_uses_registry_fast_path_without_full_history_load(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    server.save_runs(
        workspace,
        [
            {
                "id": "run-1",
                "workspace": "runs/run-1",
                "status": "completed",
                "created_at": "2026-07-31T00:00:00+00:00",
            }
        ],
    )
    monkeypatch.setattr(server, "RUN_INDEX_CACHE", {})
    monkeypatch.setattr(
        server,
        "load_runs",
        lambda _workspace: (_ for _ in ()).throw(AssertionError("fast path unexpectedly loaded all runs")),
    )

    run = server.find_run(workspace, "run-1")

    assert run is not None
    assert run["id"] == "run-1"
    assert len(server.RUN_INDEX_CACHE) == 1


def test_find_run_fast_path_merges_target_worker_progress(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    run = {
        "id": "run-progress",
        "workspace": "runs/run-progress",
        "status": "running",
        "verify": "none",
        "dependency_scan": False,
        "progress": {},
    }
    server.save_runs(workspace, [run])
    run_dir = workspace / "runs" / "run-progress"
    run_dir.mkdir(parents=True)
    server.write_worker_state(
        run_dir,
        {
            "run_id": "run-progress",
            "status": "running",
            "progress": {"stage": "candidate", "percent": 48, "detail": "building data-flow evidence"},
        },
    )
    monkeypatch.setattr(server, "RUN_INDEX_CACHE", {})
    monkeypatch.setattr(
        server,
        "load_runs",
        lambda _workspace: (_ for _ in ()).throw(AssertionError("fast path unexpectedly loaded all runs")),
    )

    current = server.find_run(workspace, "run-progress")

    assert current is not None
    assert current["status"] == "running"
    assert current["progress"]["phase"] == "candidate"
    candidate = next(item for item in current["progress"]["stages"] if item["id"] == "candidate")
    assert candidate["percent"] == 48
    assert candidate["detail"] == "building data-flow evidence"


def test_save_runs_invalidates_cached_registry_lookup(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    first = {"id": "run-before-save", "workspace": "runs/run-before-save", "status": "completed"}
    second = {"id": "run-after-save", "workspace": "runs/run-after-save", "status": "completed"}
    server.save_runs(workspace, [first])
    signature = server.run_index_signature(workspace / "auditforge_runs.json")
    assert signature is not None
    monkeypatch.setattr(server, "RUN_INDEX_CACHE", {})
    monkeypatch.setattr(server, "run_index_signature", lambda _path: signature)

    assert server.find_run(workspace, first["id"]) is not None
    server.save_runs(workspace, [second])
    monkeypatch.setattr(
        server,
        "load_runs",
        lambda _workspace: (_ for _ in ()).throw(AssertionError("cache was not invalidated after save")),
    )

    found = server.find_run(workspace, second["id"])

    assert found is not None
    assert found["id"] == second["id"]


def test_find_run_falls_back_to_full_recovery_when_registry_is_missing(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    expected = {"id": "recovered-run", "status": "completed"}
    calls: list[Path] = []

    def fake_load_runs(argument: Path) -> list[dict]:
        calls.append(argument)
        return [expected]

    monkeypatch.setattr(server, "RUN_INDEX_CACHE", {})
    monkeypatch.setattr(server, "load_runs", fake_load_runs)

    found = server.find_run(workspace, "recovered-run")

    assert found == expected
    assert calls == [workspace]


def test_overview_and_history_reuse_their_loaded_run_list_for_the_navigation_shell(tmp_path: Path, monkeypatch) -> None:
    calls: list[Path] = []
    runs = [{"id": "run-1", "workspace": "runs/run-1", "status": "completed", "stats": {}}]

    def fake_load_runs(workspace: Path) -> list[dict]:
        calls.append(workspace)
        return runs

    monkeypatch.setattr(server_ui, "_server_load_runs", fake_load_runs)
    monkeypatch.setattr(server_ui, "build_home_overview", lambda _workspace, _runs: {})

    server_ui.render_overview_page(tmp_path)
    server_ui.render_history_page(tmp_path)

    assert calls == [tmp_path, tmp_path]


def test_home_overview_reads_each_run_verification_results_once(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []
    run = {"id": "run-1", "workspace": "runs/run-1", "status": "completed", "stats": {}}
    monkeypatch.setattr(server_ui, "load_run_candidates", lambda _workspace, _run: [])
    monkeypatch.setattr(server_ui, "load_run_dependency_findings", lambda _workspace, _run: [])

    def fake_verification_results(_workspace: Path, item: dict) -> list[dict]:
        calls.append(str(item["id"]))
        return [{"status": "confirmed"}, {"status": "sandbox_executed"}]

    monkeypatch.setattr(server_ui, "load_run_verification_results", fake_verification_results)

    overview = server_ui.build_home_overview(tmp_path, [run])

    assert calls == ["run-1"]
    assert overview["runtime_confirmed"] == 1
    assert overview["sandbox_reviewed"] == 1
