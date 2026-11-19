from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import auditforge.frontends.native_ast_bridge as native_ast_bridge
from auditforge.analysis.scanner import SourceFile, scan_repo
from auditforge.core.models import IndexedFile
from auditforge.frontends.java_go_analysis import analyze_java
from auditforge.frontends.native_ast_bridge import (
    _merge_structural_and_framework_facts,
    analyze_java_batch_with_ast,
    analyze_native_with_ast,
    native_payload_to_result,
)

JAVA_SOURCE = (
    "class Controller {\n"
    "  String search(String q, Statement statement) {\n"
    '    String sql = "SELECT " + q;\n'
    "    return statement.executeQuery(sql).toString();\n"
    "  }\n"
    "}\n"
)

GO_SOURCE = 'package main\n\nfunc search(q string, db DB) string {\n  sql := "SELECT " + q\n  return db.Query(sql)\n}\n'


def source_file(tmp_path: Path, language: str) -> SourceFile:
    name, content = ("Controller.java", JAVA_SOURCE) if language == "java" else ("main.go", GO_SOURCE)
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return SourceFile(
        IndexedFile(f"file:{name}", name, language, len(content.encode()), len(content.splitlines()), "heuristic"),
        path,
        content,
        content.splitlines(),
    )


def structural_payload(language: str) -> dict:
    name = "search"
    qualified = "Controller.search" if language == "java" else "search"
    return {
        "status": "ok",
        "facts": {
            "classes": (
                [{"key": "class:1", "name": "Controller", "qualifiedName": "Controller", "line": 1, "endLine": 6}]
                if language == "java"
                else []
            ),
            "functions": [
                {
                    "key": "function:search",
                    "name": name,
                    "qualifiedName": qualified,
                    "line": 2 if language == "java" else 3,
                    "endLine": 5,
                    "params": ["q", "db"],
                    "classKey": "class:1" if language == "java" else None,
                    "parentKey": None,
                }
            ],
            "assignments": [
                {
                    "target": "sql",
                    "sources": ["q"],
                    "expression": '"SELECT " + q',
                    "line": 3 if language == "java" else 4,
                    "scopeKey": "function:search",
                }
            ],
            "returns": [
                {
                    "expression": "db.Query(sql)",
                    "sources": ["db", "sql"],
                    "line": 4 if language == "java" else 5,
                    "scopeKey": "function:search",
                }
            ],
            "calls": [
                {"callee": "db.Query", "line": 4 if language == "java" else 5, "scopeKey": "function:search", "argumentSources": [["sql"]]}
            ],
            "controls": [
                {
                    "kind": "if",
                    "condition": "q != null",
                    "variables": ["q"],
                    "line": 3 if language == "java" else 4,
                    "scopeKey": "function:search",
                }
            ],
        },
    }


def test_native_payload_marks_structural_facts_as_ast(tmp_path: Path) -> None:
    result = native_payload_to_result(source_file(tmp_path, "java"), structural_payload("java"))

    assert result.functions[0].qualified_name == "Controller.search"
    assert result.functions[0].analysis_method == "ast"
    assert result.call_sites[0].analysis_method == "ast"
    assert result.data_flows[0].analysis_method == "ast"
    assert result.control_flows[0].analysis_method == "ast"


def test_native_ast_keeps_heuristic_structural_facts_that_the_parser_misses(tmp_path: Path) -> None:
    source = source_file(tmp_path, "java")
    structural = native_payload_to_result(source, structural_payload("java"))
    heuristic = source_file(tmp_path, "java")
    heuristic_result = analyze_java(heuristic)
    merged = _merge_structural_and_framework_facts(structural, heuristic_result)

    assert len(merged.functions) >= len(heuristic_result.functions)
    assert len(merged.call_sites) >= len(heuristic_result.call_sites)
    assert len(merged.data_flows) >= len(heuristic_result.data_flows)
    assert {item.id for item in heuristic_result.functions} <= {item.id for item in merged.functions}
    assert {item.id for item in heuristic_result.call_sites} <= {item.id for item in merged.call_sites}
    assert {item.id for item in heuristic_result.data_flows} <= {item.id for item in merged.data_flows}


def test_native_ast_dedupes_only_semantically_identical_structural_facts(tmp_path: Path) -> None:
    source = source_file(tmp_path, "java")
    structural = native_payload_to_result(source, structural_payload("java"))
    heuristic = structural.__class__(
        call_sites=[replace(structural.call_sites[0], id="callsite:heuristic-copy", analysis_method="heuristic")],
        data_flows=[replace(structural.data_flows[0], id="dfg:heuristic-copy", analysis_method="heuristic")],
        control_flows=[replace(structural.control_flows[0], id="cfg:heuristic-copy", analysis_method="heuristic")],
    )

    merged = _merge_structural_and_framework_facts(structural, heuristic)

    assert len(merged.call_sites) == 1
    assert len(merged.data_flows) == len(structural.data_flows)
    assert len(merged.control_flows) == 1
    assert merged.call_sites[0].analysis_method == "ast"


def test_scanner_uses_native_ast_and_retains_heuristic_sink_modelling(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "Controller.java"
    path.write_text(JAVA_SOURCE, encoding="utf-8")

    def fake_native(source: SourceFile):
        result = _merge_structural_and_framework_facts(
            native_payload_to_result(source, structural_payload("java")),
            analyze_java(source),
        )
        return result, {"status": "ok", "reason": "fixture", "used": True, "fallback": False}

    monkeypatch.setattr(
        "auditforge.frontends.native_ast_bridge.analyze_java_batch_with_ast",
        lambda sources: {source.file.path: fake_native(source) for source in sources},
    )
    facts = scan_repo(tmp_path)

    assert facts.files[0].parsed_by == "ast"
    assert facts.analysis_diagnostics["native_ast"]["languages"]["java"]["ast_files"] == 1
    assert facts.analysis_diagnostics["language_frontends"]["java-native-ast"] == 1
    assert any(item.analysis_method == "ast" for item in [*facts.functions, *facts.call_sites, *facts.data_flows])
    assert any(item.analysis_method == "heuristic" for item in [*facts.functions, *facts.call_sites, *facts.data_flows])
    assert any(item.kind == "raw_sql" and item.analysis_method == "heuristic" for item in facts.sinks)


def test_java_batch_returns_a_result_for_each_source_file(tmp_path: Path, monkeypatch) -> None:
    first = source_file(tmp_path / "first", "java")
    second = source_file(tmp_path / "second", "java")
    first = replace(first, file=replace(first.file, id="file:first", path="first/Controller.java"))
    second = replace(second, file=replace(second.file, id="file:second", path="second/Controller.java"))
    monkeypatch.setattr("auditforge.frontends.native_ast_bridge._bridge_command", lambda _language: (["java"], None))
    monkeypatch.setattr(
        "auditforge.frontends.native_ast_bridge._run_java_batch",
        lambda _command, sources, _cwd: ({source.file.path: structural_payload("java") for source in sources}, ""),
    )

    results = analyze_java_batch_with_ast([first, second])

    assert set(results) == {first.file.path, second.file.path}
    assert all(result is not None for result, _diagnostic in results.values())
    assert {diagnostic["mode"] for _result, diagnostic in results.values()} == {"batch"}


def test_java_batch_uses_single_file_fallback_for_absent_batch_result(tmp_path: Path, monkeypatch) -> None:
    first = source_file(tmp_path / "first", "java")
    second = source_file(tmp_path / "second", "java")
    first = replace(first, file=replace(first.file, id="file:first", path="first/Controller.java"))
    second = replace(second, file=replace(second.file, id="file:second", path="second/Controller.java"))
    fallback_paths: list[str] = []

    def fake_single(source: SourceFile):
        fallback_paths.append(source.file.path)
        return native_payload_to_result(source, structural_payload("java")), {"status": "ok", "used": True, "fallback": False}

    class PartialSession:
        def __init__(self, _command, _cwd) -> None:
            pass

        def run_batch(self, sources):
            return {sources[0].file.path: structural_payload("java")}, "partial batch response"

        def close(self) -> None:
            pass

    monkeypatch.setattr("auditforge.frontends.native_ast_bridge._bridge_command", lambda _language: (["java"], None))
    monkeypatch.setattr(native_ast_bridge, "_JavaBridgeSession", PartialSession)
    monkeypatch.setattr(
        "auditforge.frontends.native_ast_bridge._run_java_batch",
        lambda _command, sources, _cwd: ({sources[0].file.path: structural_payload("java")}, "partial batch response"),
    )
    monkeypatch.setattr("auditforge.frontends.native_ast_bridge.analyze_native_with_ast", fake_single)

    results = analyze_java_batch_with_ast([first, second])

    assert fallback_paths == [second.file.path]
    assert all(result is not None for result, _diagnostic in results.values())
    assert results[second.file.path][1]["batch_fallback_reason"] == "partial batch response"


def test_java_batch_reuses_one_persistent_session_for_multiple_batches(tmp_path: Path, monkeypatch) -> None:
    first = source_file(tmp_path / "first", "java")
    second = source_file(tmp_path / "second", "java")
    first = replace(first, file=replace(first.file, id="file:first", path="first/Controller.java"))
    second = replace(second, file=replace(second.file, id="file:second", path="second/Controller.java"))
    sessions: list[object] = []

    class FakeSession:
        def __init__(self, _command, _cwd) -> None:
            self.batches: list[list[str]] = []
            self.closed = False
            sessions.append(self)

        def run_batch(self, sources):
            self.batches.append([source.file.path for source in sources])
            return {source.file.path: structural_payload("java") for source in sources}, ""

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr("auditforge.frontends.native_ast_bridge._bridge_command", lambda _language: (["java"], None))
    monkeypatch.setattr(native_ast_bridge, "_JavaBridgeSession", FakeSession)
    monkeypatch.setattr(native_ast_bridge, "JAVA_BATCH_MAX_FILES", 1)

    results = analyze_java_batch_with_ast([first, second])

    assert set(results) == {first.file.path, second.file.path}
    assert len(sessions) == 1
    assert sessions[0].batches == [[first.file.path], [second.file.path]]
    assert sessions[0].closed is True


def test_native_bridge_falls_back_explicitly_when_go_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("auditforge.frontends.native_ast_bridge.shutil.which", lambda _name: None)
    monkeypatch.delenv("GOROOT", raising=False)

    result, diagnostic = analyze_native_with_ast(source_file(tmp_path, "go"))

    assert result is None
    assert diagnostic["status"] == "go_not_found"
    assert diagnostic["fallback"] is True
