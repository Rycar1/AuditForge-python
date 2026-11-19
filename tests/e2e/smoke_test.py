import io
import json
import sqlite3
import zipfile
from pathlib import Path
from types import SimpleNamespace

from auditforge.analysis.candidates import build_trace_candidates
from auditforge.analysis.direct_findings import generate_direct_candidates
from auditforge.analysis.graph import build_graph
from auditforge.analysis.llm_candidates import LLMConfig
from auditforge.analysis.scanner import extract_functions, extract_sinks, extract_sources, index_source_files, scan_repo
from auditforge.engine import run_scan
from auditforge.reporting.report import metric_label, render_analysis_completeness_markdown
from auditforge.reporting.store import SCHEMA
from auditforge.web.server import (
    build_home_overview,
    build_run_export_zip,
    build_scan_config_snapshot,
    count_confirmed_results,
    count_sandbox_reviews,
    default_result_partition,
    delete_scan_run,
    exportable_run_files,
    load_runs,
    load_triage_notes,
    render_card,
    render_i18n_script,
    render_result_partition_tabs,
    render_result_partitions,
    render_scan_diagnostics_panel,
    save_candidate_triage,
    save_runs,
)


def test_polyglot_fixture_scan(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    result = run_scan(repo, tmp_path)
    assert result.stats()["files"] == 3
    assert result.stats()["routes"] == 7
    assert result.stats()["data_flows"] >= 20
    assert result.stats()["candidates"] == 6
    candidates = {
        (item.vuln_class, item.source.file, item.source.start_line, item.sink.file, item.sink.start_line) for item in result.candidates
    }
    assert ("injection", "app.py", 10, "app.py", 12) in candidates
    assert ("xss", "app.py", 18, "app.py", 19) in candidates
    assert ("ssrf", "app.py", 24, "app.py", 25) in candidates
    assert ("injection", "Handler.java", 6, "Handler.java", 7) in candidates
    assert ("injection", "server.ts", 7, "server.ts", 8) in candidates
    assert ("xss", "server.ts", 13, "server.ts", 14) in candidates
    assert ("injection", "app.py", 30, "app.py", 32) not in candidates
    assert ("injection", "server.ts", 18, "server.ts", 19) not in candidates
    first = next(item for item in result.candidates if item.id == "INJECTION-TRACE-001")
    assert any(step.to_anchor and step.to_anchor.start_line == 12 for step in first.steps)
    assert (tmp_path / "auditforge.db").exists()
    assert (tmp_path / "report.html").exists()


def test_sqlalchemy_session_is_not_cookie_or_auth_sink(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from extensions import db\n\ndef save(user):\n    db.session.add(user)\n    db.session.commit()\n",
        encoding="utf-8",
    )
    source_file = index_source_files(tmp_path)[0]

    sources = extract_sources(source_file)
    sinks = extract_sinks(source_file)

    assert not any(source.kind == "cookie" for source in sources)
    assert not any(sink.kind == "auth_primitive" for sink in sinks)


def test_rule_matching_ignores_literals_and_comments_but_keeps_real_calls(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "VULNS = [",
                "    {'summary': 'Weak passwords, cookies, execute and token examples.'},",
                "]",
                "# request.args cookies password execute should not create facts",
                "def real(request, db, session):",
                "    sid = request.cookies.get('sid')",
                "    user_id = session.get('user_id')",
                "    rows = db.execute('select 1').fetchall()",
                "    return rows",
            ]
        ),
        encoding="utf-8",
    )
    source_file = index_source_files(tmp_path)[0]

    sources = extract_sources(source_file)
    sinks = extract_sinks(source_file)

    noisy_lines = {2, 4}
    assert not any(source.anchor.start_line in noisy_lines for source in sources)
    assert not any(sink.anchor.start_line in noisy_lines for sink in sinks)
    assert any(source.kind == "cookie" and source.anchor.start_line == 6 for source in sources)
    assert any(source.kind == "cookie" and source.anchor.start_line == 7 for source in sources)
    assert any(sink.kind == "raw_sql" and sink.anchor.start_line == 8 for sink in sinks)


def test_python_function_extraction_supports_return_annotations(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "def plain(value):",
                "    return value",
                "def typed(value: str) -> str:",
                "    return value",
                "async def async_typed(value: int) -> None:",
                "    return None",
            ]
        ),
        encoding="utf-8",
    )
    source_file = index_source_files(tmp_path)[0]

    functions = extract_functions(source_file)

    assert {item.name for item in functions} == {"plain", "typed", "async_typed"}


def test_runtime_relevant_rules_cover_values_and_admin_bypass(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "from flask import request",
                "import urllib.request",
                "def admin(db):",
                "    allowed = False",
                "    if request.args.get('admin') == 'true':",
                "        allowed = True",
                "    return db.execute('select * from users').fetchall()",
                "def fetch():",
                "    url = request.values.get('url', '')",
                "    return urllib.request.urlopen(url).read()",
            ]
        ),
        encoding="utf-8",
    )
    source_file = index_source_files(tmp_path)[0]

    sources = extract_sources(source_file)
    sinks = extract_sinks(source_file)

    assert any(source.kind == "http_query" and source.anchor.start_line == 5 for source in sources)
    assert any(source.kind == "http_query" and source.anchor.start_line == 9 for source in sources)
    assert any(sink.kind == "authorization_decision" and sink.anchor.start_line == 5 for sink in sinks)
    assert any(sink.kind == "external_request" and sink.anchor.start_line == 10 for sink in sinks)


def test_generated_frontend_assets_are_not_deep_indexed(tmp_path: Path) -> None:
    (tmp_path / "ueditor.all.min.js").write_text("var x='<script>'+location.search+'</script>';\n", encoding="utf-8")
    (tmp_path / "third-party").mkdir()
    (tmp_path / "third-party" / "lib.js").write_text("document.write(location.hash)\n", encoding="utf-8")
    (tmp_path / "app.php").write_text("<?php echo $_GET['name'];\n", encoding="utf-8")

    source_files = index_source_files(tmp_path)
    by_path = {item.file.path: item.file for item in source_files}

    assert by_path["ueditor.all.min.js"].skipped_reason == "minified generated asset"
    assert "third-party/lib.js" not in by_path
    assert by_path["app.php"].skipped_reason is None


def test_direct_findings_cover_route_level_audit_patterns(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "from flask import Flask",
                "app = Flask(__name__)",
                "@app.route('/admin')",
                "def admin(): return 'admin'",
                "@app.route('/profile/<int:user_id>')",
                "def profile(user_id): return 'profile'",
                "@app.route('/config')",
                "def config(): return 'config'",
                "@app.route('/crypto', methods=['GET', 'POST'])",
                "def crypto(): return 'crypto'",
                "@app.route('/reset-password', methods=['GET', 'POST'])",
                "def reset_password(): return 'reset'",
                "@app.route('/notes', methods=['GET', 'POST'])",
                "def notes(): return 'notes'",
                "@app.route('/upload', methods=['GET', 'POST'])",
                "def upload(): return 'upload'",
            ]
        ),
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    graph = build_graph(facts)
    candidates = build_trace_candidates(facts, graph)
    assert generate_direct_candidates(tmp_path, facts, candidates) == []
    direct = generate_direct_candidates(tmp_path, facts, candidates, enabled=True)

    evidence = "\n".join(candidate.static_evidence for candidate in direct)
    assert "remember_user Cookie" in evidence
    assert "对象级越权" in evidence
    assert "配置泄露" in evidence
    assert "弱加密" in evidence
    assert "密码重置" in evidence
    assert "存储型 XSS" in evidence
    assert "不安全文件上传" in evidence


def test_virtualenv_and_workspace_dirs_are_not_indexed(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('app')\n", encoding="utf-8")
    (tmp_path / ".venv" / "Lib" / "site-packages").mkdir(parents=True)
    (tmp_path / ".venv" / "Lib" / "site-packages" / "flask.py").write_text("def route(): pass\n", encoding="utf-8")
    (tmp_path / "workspace-old").mkdir()
    (tmp_path / "workspace-old" / "generated.py").write_text("def noisy(): pass\n", encoding="utf-8")
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "probe.py").write_text("def uploaded(): pass\n", encoding="utf-8")

    source_files = index_source_files(tmp_path)
    paths = {item.file.path for item in source_files}

    assert paths == {"app.py"}


def test_run_detail_result_partitions_follow_requested_order() -> None:
    sections = {"candidate": [], "secondary": [], "confirmed": []}

    tabs_html = render_result_partition_tabs(sections, dependency_findings=[{"package": "demo"}])
    tab_order = [
        tabs_html.index('data-result-tab="dependency"'),
        tabs_html.index('data-result-tab="candidate"'),
        tabs_html.index('data-result-tab="secondary"'),
        tabs_html.index('data-result-tab="confirmed"'),
    ]
    assert tab_order == sorted(tab_order)

    panels_html = render_result_partitions(sections, [], [], {}, {}, False, "")
    panel_order = [
        panels_html.index('data-result-panel="dependency"'),
        panels_html.index('data-result-panel="candidate"'),
        panels_html.index('data-result-panel="secondary"'),
        panels_html.index('data-result-panel="confirmed"'),
    ]
    assert panel_order == sorted(panel_order)


def test_run_detail_defaults_to_the_most_actionable_nonempty_queue() -> None:
    empty = {"candidate": [], "secondary": [], "confirmed": []}

    assert default_result_partition({**empty, "candidate": [(object(), None)]}, [{}]) == "candidate"
    assert default_result_partition({**empty, "secondary": [(object(), None)]}, [{}]) == "secondary"
    assert default_result_partition({**empty, "confirmed": [(object(), None)]}, [{}]) == "confirmed"
    assert default_result_partition(empty, [{}]) == "dependency"
    assert default_result_partition(empty, []) == "candidate"


def test_scan_config_snapshot_redacts_key_and_fingerprints_prompts() -> None:
    snapshot = build_scan_config_snapshot(
        verify="deep",
        dependency_scan=True,
        taint_config=LLMConfig(
            enabled=True,
            provider="openai-compatible",
            model="gpt-test",
            base_url="https://example.test/v1?token=hidden",
            api_key="secret-placeholder-should-not-render",
            system_prompt="system prompt",
            user_prompt="user prompt",
            max_candidates=7,
            concurrency=4,
        ),
        dependency_config=LLMConfig(enabled=True, model="dep-model", system_prompt="dep system", user_prompt="dep user"),
        deep_config=LLMConfig(enabled=True, model="deep-model", system_prompt="deep system", user_prompt="deep user"),
    )
    serialized = str(snapshot)

    assert "secret-placeholder" not in serialized
    assert snapshot["profiles"]["taint"]["base_url"] == "https://example.test/v1"
    assert snapshot["profiles"]["taint"]["system_prompt"]["length"] == len("system prompt")
    assert len(snapshot["profiles"]["taint"]["system_prompt"]["sha256"]) == 12
    assert snapshot["profiles"]["taint"]["max_candidates"] == 7
    assert snapshot["profiles"]["taint"]["concurrency"] == 4


def test_scan_diagnostics_panel_summarizes_llm_stages_without_secrets() -> None:
    run = {
        "llm_enabled": True,
        "dependency_scan": True,
        "verify": "deep",
        "scan_config": build_scan_config_snapshot(
            verify="deep",
            dependency_scan=True,
            taint_config=LLMConfig(
                enabled=True,
                model="taint-model",
                api_key="secret-placeholder-should-not-render",
                system_prompt="taint sys",
                user_prompt="taint user",
            ),
            dependency_config=LLMConfig(enabled=True, model="dep-model", system_prompt="dep sys", user_prompt="dep user"),
            deep_config=LLMConfig(enabled=True, model="deep-model", system_prompt="deep sys", user_prompt="deep user"),
        ),
    }
    artifacts = {
        "llm_diagnostics": {
            "enabled": True,
            "provider": "fixture",
            "model": "taint-model",
            "accepted": 2,
            "rejected": [{"reason": "duplicate"}],
            "dependency_scan": {"enabled": True, "model": "dep-model", "accepted": 1, "chunks": 2},
            "deep_verification": {
                "enabled": True,
                "model": "deep-model",
                "tested": 3,
                "sandbox_passed": 1,
                "container_runtime_ready": False,
                "container_runtime_error": "Docker daemon unavailable",
            },
        }
    }

    html = render_scan_diagnostics_panel(run, artifacts)

    assert "AI 调用诊断" in html
    assert "污点候选" in html
    assert "依赖审计" in html
    assert "二次验证" in html
    assert "taint-model" in html
    assert "dep-model" in html
    assert "deep-model" in html
    assert "拒绝样本：duplicate" in html
    assert "隔离验证环境未完成" in html
    assert "Docker daemon unavailable" not in html
    assert "secret-placeholder" not in html


def test_candidate_triage_notes_round_trip_and_validate_status(tmp_path: Path) -> None:
    saved = save_candidate_triage(
        tmp_path,
        {
            "candidate_id": "INJECTION-TRACE-001",
            "status": "accepted",
            "note": " 已人工复现，需要进入修复流程。\n保留证据。 ",
        },
    )

    loaded = load_triage_notes(tmp_path)

    assert saved["status"] == "accepted"
    assert loaded["items"]["INJECTION-TRACE-001"]["note"] == "已人工复现，需要进入修复流程。 保留证据。"
    assert loaded["items"]["INJECTION-TRACE-001"]["updated_at"]
    try:
        save_candidate_triage(tmp_path, {"candidate_id": "INJECTION-TRACE-001", "status": "invalid"})
    except ValueError as exc:
        assert "复核状态非法" in str(exc)
    else:
        raise AssertionError("invalid triage status should fail")


def test_render_candidate_card_includes_triage_controls(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    result = run_scan(repo, tmp_path)
    candidate = result.candidates[0]
    row = {
        "id": candidate.id,
        "vuln_class": candidate.vuln_class,
        "confidence": candidate.confidence,
        "source_file": candidate.source.file,
        "source_line": candidate.source.start_line,
        "sink_file": candidate.sink.file,
        "sink_line": candidate.sink.start_line,
        "payload_json": json.dumps(candidate.to_dict(), ensure_ascii=False),
    }

    html = render_card(row, None, str(repo), {"status": "fixing", "note": "正在修复参数化查询"})

    assert 'data-triage-candidate="' + candidate.id + '"' in html
    assert "人工复核" in html
    assert "修复中" in html
    assert "正在修复参数化查询" in html
    assert "data-triage-save" in html


def test_run_export_zip_contains_reports_and_audit_artifacts(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    result = run_scan(repo, tmp_path)
    save_candidate_triage(tmp_path, {"candidate_id": result.candidates[0].id, "status": "accepted", "note": "人工确认"})
    run = {
        "id": "run-export",
        "name": "导出测试",
        "status": "completed",
        "repo_path": str(repo),
        "stats": result.stats(),
        "api_key": "secret-placeholder-should-not-export",
    }

    archive_bytes = build_run_export_zip(tmp_path, run)

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        names = set(archive.namelist())
        metadata = json.loads(archive.read("run_metadata.json").decode("utf-8"))
        assert "report.html" in names
        assert "report.md" in names
        assert "trace_candidates.json" in names
        assert "verification_plans.json" in names
        assert "result_sections.json" in names
        assert "result_sections/candidate_vulnerabilities.json" in names
        assert "triage_notes.json" in names
        assert "auditforge.db" in names
        assert metadata["id"] == "run-export"
        assert "api_key" not in metadata
        assert "secret-placeholder" not in archive.read("run_metadata.json").decode("utf-8")


def test_exportable_run_files_ignores_symlink_and_non_whitelisted_files(tmp_path: Path) -> None:
    (tmp_path / "report.md").write_text("# report\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("secret\n", encoding="utf-8")
    outside = tmp_path.parent / "outside-export.txt"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        (tmp_path / "result_sections").mkdir()
        (tmp_path / "result_sections" / "candidate_vulnerabilities.json").write_text("[]", encoding="utf-8")
        try:
            (tmp_path / "result_sections" / "escape.json").symlink_to(outside)
        except OSError:
            pass

        exported = {path.relative_to(tmp_path).as_posix() for path in exportable_run_files(tmp_path)}

        assert "report.md" in exported
        assert "result_sections/candidate_vulnerabilities.json" in exported
        assert "secret.txt" not in exported
        assert "result_sections/escape.json" not in exported
    finally:
        outside.unlink(missing_ok=True)


def test_upload_deep_fixture_has_precise_body_and_authz_flows(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "upload_deep_vuln_service"
    result = run_scan(repo, tmp_path)
    candidates = {(item.vuln_class, item.source.start_line, item.sink.start_line) for item in result.candidates}

    assert ("injection", 60, 61) in candidates
    assert ("injection", 53, 61) not in candidates
    assert ("authz", 75, 77) in candidates
    assert ("authz", 76, 77) in candidates
    assert ("authz", 75, 75) not in candidates

    authz = next(item for item in result.candidates if item.vuln_class == "authz" and item.source.start_line == 75)
    assert any(step.kind == "branch" and step.to_anchor and step.to_anchor.start_line == 77 for step in authz.steps)


def test_delete_scan_run_keeps_external_repo(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    external_repo = tmp_path / "external-repo"
    run_dir = workspace / "runs" / "run-path"
    external_repo.mkdir(parents=True)
    run_dir.mkdir(parents=True)
    (external_repo / "app.py").write_text("print('keep')\n", encoding="utf-8")
    (run_dir / "report.html").write_text("<h1>report</h1>", encoding="utf-8")
    save_runs(
        workspace,
        [
            {
                "id": "run-path",
                "name": "外部路径扫描",
                "status": "completed",
                "source_type": "path",
                "repo_path": str(external_repo),
                "workspace": "runs/run-path",
                "created_at": "2026-06-18T00:00:00+00:00",
            }
        ],
    )

    result = delete_scan_run(workspace, "run-path")

    assert result["run"]["id"] == "run-path"
    assert load_runs(workspace) == []
    assert not run_dir.exists()
    assert external_repo.exists()
    assert (external_repo / "app.py").exists()


def test_delete_scan_run_removes_uploaded_artifacts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "run-upload"
    repo_dir = workspace / "uploaded_repos" / "run-upload"
    uploads_dir = workspace / "uploads"
    run_dir.mkdir(parents=True)
    repo_dir.mkdir(parents=True)
    uploads_dir.mkdir(parents=True)
    (run_dir / "report.md").write_text("# report\n", encoding="utf-8")
    (repo_dir / "app.py").write_text("print('uploaded')\n", encoding="utf-8")
    (uploads_dir / "run-upload-source.zip").write_bytes(b"zip")
    save_runs(
        workspace,
        [
            {
                "id": "run-upload",
                "name": "上传扫描",
                "status": "completed",
                "source_type": "upload",
                "repo_path": str(repo_dir),
                "workspace": "runs/run-upload",
                "created_at": "2026-06-18T00:00:00+00:00",
            }
        ],
    )

    delete_scan_run(workspace, "run-upload")

    assert load_runs(workspace) == []
    assert not run_dir.exists()
    assert not repo_dir.exists()
    assert not (uploads_dir / "run-upload-source.zip").exists()


def test_overview_ignores_persisted_legacy_when_real_runs_exist(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    real_run_dir = workspace / "runs" / "run-real"
    real_run_dir.mkdir(parents=True)
    (workspace / "trace_candidates.json").write_text(
        '[{"id":"legacy-candidate","vuln_class":"xss","confidence":"high"}]',
        encoding="utf-8",
    )
    (real_run_dir / "trace_candidates.json").write_text(
        '[{"id":"real-candidate","vuln_class":"ssrf","confidence":"high"}]',
        encoding="utf-8",
    )
    (workspace / "auditforge_runs.json").write_text(
        """
{
  "runs": [
    {
      "id": "legacy",
      "name": "当前工作区扫描",
      "status": "completed",
      "workspace": ".",
      "created_at": "2026-06-18T00:00:00+00:00",
      "stats": {"candidates": 1}
    },
    {
      "id": "run-real",
      "name": "真实任务",
      "status": "completed",
      "workspace": "runs/run-real",
      "created_at": "2026-06-18T01:00:00+00:00",
      "stats": {"candidates": 1}
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )

    runs = load_runs(workspace)
    overview = build_home_overview(workspace, runs)

    assert [run["id"] for run in runs] == ["run-real"]
    assert overview["total_runs"] == 1
    assert overview["total_candidates"] == 1
    assert overview["severity_counts"]["critical"] == 1


def test_home_overview_includes_dependency_findings_in_risk_totals(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "run-dependency"
    run_dir.mkdir(parents=True)
    (run_dir / "dependency_findings.json").write_text(
        json.dumps(
            [
                {"id": "DEP-001", "package": "log4j-core", "severity": "critical"},
                {"id": "DEP-002", "package": "django", "severity": "high"},
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    runs = [
        {
            "id": "run-dependency",
            "name": "依赖扫描",
            "status": "completed",
            "workspace": "runs/run-dependency",
            "created_at": "2026-06-18T00:00:00+00:00",
            "stats": {"dependency_findings": 2},
        }
    ]

    overview = build_home_overview(workspace, runs)

    assert overview["total_candidates"] == 0
    assert overview["dependency_findings"] == 2
    assert overview["total_risks"] == 2
    assert overview["severity_counts"]["critical"] == 1
    assert overview["severity_counts"]["high"] == 1
    assert overview["vuln_counts"]["dependency"] == 2


def test_home_overview_keeps_sandbox_results_out_of_confirmed_count(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "run-verified"
    run_dir.mkdir(parents=True)
    (run_dir / "verification_results.json").write_text(
        json.dumps(
            [
                {"candidate_id": "SAFE-1", "status": "confirmed"},
                {"candidate_id": "DEEP-1", "status": "sandbox_confirmed"},
                {"candidate_id": "BLOCKED-1", "status": "blocked"},
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    runs = [
        {
            "id": "run-verified",
            "name": "验证任务",
            "status": "completed",
            "workspace": "runs/run-verified",
            "created_at": "2026-06-18T00:00:00+00:00",
            "stats": {"verification_results": 3, "sandbox_confirmed": 1},
        }
    ]

    overview = build_home_overview(workspace, runs)

    assert overview["confirmed"] == 1
    assert overview["runtime_confirmed"] == 1
    assert overview["sandbox_reviewed"] == 1


def test_i18n_script_exposes_dynamic_translation_helpers() -> None:
    script = render_i18n_script("en-US")

    assert "window.auditforgeTranslate" in script
    assert "window.auditforgeTranslateElement" in script
    assert "Delete scan task" in script
    assert "Failed to read progress" in script
    assert "Runtime confirmed" in script


def test_count_confirmed_results_reads_database_when_json_missing(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_dir = workspace / "runs" / "run-db"
    run_dir.mkdir(parents=True)
    con = sqlite3.connect(run_dir / "auditforge.db")
    try:
        con.executescript(SCHEMA)
        con.execute(
            "INSERT INTO verification_results (candidate_id, status, payload_json) VALUES (?, ?, ?)",
            ("SAFE-1", "confirmed", "{}"),
        )
        con.execute(
            "INSERT INTO verification_results (candidate_id, status, payload_json) VALUES (?, ?, ?)",
            ("DEEP-1", "sandbox_confirmed", "{}"),
        )
        con.execute(
            "INSERT INTO verification_results (candidate_id, status, payload_json) VALUES (?, ?, ?)",
            ("NO-1", "not_reproducible", "{}"),
        )
        con.commit()
    finally:
        con.close()

    run = {"id": "run-db", "workspace": "runs/run-db", "stats": {}}

    assert count_confirmed_results(workspace, run) == 1
    assert count_sandbox_reviews(workspace, run) == 1


def test_load_runs_recovers_run_directory_when_index_missing(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    run_dir = workspace / "runs" / "run-recovered"
    run_scan(repo, run_dir)

    runs = load_runs(workspace)

    assert [run["id"] for run in runs] == ["run-recovered"]
    assert runs[0]["status"] == "completed"
    assert runs[0]["workspace"] == "runs/run-recovered"
    assert runs[0]["stats"]["candidates"] == 6
    assert runs[0]["project_inventory"]["total_lines"] > 0


def test_load_runs_merges_index_with_discovered_run_directories(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    indexed_dir = workspace / "runs" / "run-indexed"
    discovered_dir = workspace / "runs" / "run-discovered"
    run_scan(repo, indexed_dir)
    run_scan(repo, discovered_dir)
    (workspace / "auditforge_runs.json").write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "id": "run-indexed",
                        "name": "保留索引名称",
                        "status": "completed",
                        "workspace": "runs/run-indexed",
                        "created_at": "2026-06-18T01:00:00+00:00",
                        "stats": {},
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    runs = load_runs(workspace)
    by_id = {run["id"]: run for run in runs}

    assert set(by_id) == {"run-indexed", "run-discovered"}
    assert by_id["run-indexed"]["name"] == "保留索引名称"
    assert by_id["run-indexed"]["stats"]["candidates"] == 6
    assert by_id["run-discovered"]["status"] == "completed"


def test_save_runs_preserves_recovered_run_records(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    run_scan(repo, workspace / "runs" / "run-recovered")

    save_runs(workspace, load_runs(workspace))
    runs = load_runs(workspace)

    assert [run["id"] for run in runs] == ["run-recovered"]
    assert runs[0]["stats"]["candidates"] == 6


def test_report_makes_incomplete_analysis_explicit() -> None:
    result = SimpleNamespace(
        facts=SimpleNamespace(
            analysis_diagnostics={
                "truncated": True,
                "truncated_files": 3,
                "error_files": 1,
                "skipped_files": 2,
            }
        ),
        project_inventory={},
    )

    rendered = "\n".join(render_analysis_completeness_markdown(result))

    assert "扫描完整性" in rendered
    assert "不完整" in rendered
    assert "3 个源码文件未进入分析" in rendered
    assert metric_label("analysis_truncated") == "扫描是否截断"
