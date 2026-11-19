from __future__ import annotations

from pathlib import Path

from auditforge.models import IndexedFile
from auditforge.scanner import SourceFile, scan_repo
from auditforge.typescript_compiler_bridge import (
    analyze_typescript_with_compiler,
    compiler_payload_to_result,
)

SOURCE = (
    "import express from 'express';\n"
    "const app = express();\n"
    "function runQuery(db: any, term: string) {\n"
    "  const sql = `SELECT * FROM users WHERE name = '${term}'`;\n"
    "  return db.query(sql);\n"
    "}\n"
    "app.get('/search', (req, res) => {\n"
    "  const term = req.query.q;\n"
    "  return runQuery(db, term);\n"
    "});\n"
)


def source_file(tmp_path: Path, name: str = "app.ts") -> SourceFile:
    path = tmp_path / name
    path.write_text(SOURCE, encoding="utf-8")
    return SourceFile(
        file=IndexedFile(
            id=f"file:{name}",
            path=name,
            language="typescript",
            bytes=len(SOURCE.encode("utf-8")),
            lines=len(SOURCE.splitlines()),
            parsed_by="heuristic",
        ),
        absolute_path=path,
        content=SOURCE,
        lines=SOURCE.splitlines(),
    )


def compiler_payload() -> dict:
    return {
        "status": "ok",
        "compiler": {"version": "5.test", "modulePath": "C:/trusted/typescript.js"},
        "facts": {
            "classes": [],
            "functions": [
                {
                    "key": "function:run",
                    "name": "runQuery",
                    "qualifiedName": "runQuery",
                    "line": 3,
                    "endLine": 6,
                    "params": ["db", "term"],
                    "classKey": None,
                    "parentKey": None,
                },
                {
                    "key": "function:route",
                    "name": "callback@7",
                    "qualifiedName": "callback@7",
                    "line": 7,
                    "endLine": 10,
                    "params": ["req", "res"],
                    "classKey": None,
                    "parentKey": None,
                },
            ],
            "assignments": [
                {
                    "target": "sql",
                    "sources": ["term"],
                    "expression": "`SELECT * FROM users WHERE name = '${term}'`",
                    "line": 4,
                    "scopeKey": "function:run",
                },
                {
                    "target": "term",
                    "sources": ["req.query.q"],
                    "expression": "req.query.q",
                    "line": 8,
                    "scopeKey": "function:route",
                },
            ],
            "returns": [
                {"expression": "db.query(sql)", "sources": ["db.query", "sql"], "line": 5, "scopeKey": "function:run"},
                {
                    "expression": "runQuery(db, term)",
                    "sources": ["runQuery", "db", "term"],
                    "line": 9,
                    "scopeKey": "function:route",
                },
            ],
            "calls": [
                {
                    "callee": "db.query",
                    "expression": "db.query(sql)",
                    "line": 5,
                    "scopeKey": "function:run",
                    "argumentTexts": ["sql"],
                    "argumentSources": [["sql"]],
                    "argumentLiterals": [None],
                    "argumentFunctionKeys": [None],
                },
                {
                    "callee": "app.get",
                    "expression": "app.get('/search', (req, res) => {})",
                    "line": 7,
                    "scopeKey": None,
                    "argumentTexts": ["'/search'", "(req, res) => {}"],
                    "argumentSources": [[], []],
                    "argumentLiterals": ["/search", None],
                    "argumentFunctionKeys": [None, "function:route"],
                },
                {
                    "callee": "runQuery",
                    "expression": "runQuery(db, term)",
                    "line": 9,
                    "scopeKey": "function:route",
                    "argumentTexts": ["db", "term"],
                    "argumentSources": [["db"], ["term"]],
                    "argumentLiterals": [None, None],
                    "argumentFunctionKeys": [None, None],
                },
            ],
            "accesses": [
                {
                    "path": "req.query.q",
                    "expression": "req.query.q",
                    "line": 8,
                    "scopeKey": "function:route",
                    "targetVariables": ["term"],
                }
            ],
            "decorators": [],
            "controls": [],
        },
    }


def test_compiler_payload_emits_ast_facts_and_route_binding(tmp_path: Path) -> None:
    result = compiler_payload_to_result(source_file(tmp_path), compiler_payload())

    emitted = [
        *result.functions,
        *result.routes,
        *result.sources,
        *result.sinks,
        *result.call_sites,
        *result.data_flows,
    ]
    assert emitted and all(item.analysis_method == "ast" for item in emitted)
    route = next(item for item in result.routes if item.path == "/search")
    handler = next(item for item in result.functions if item.name == "callback@7")
    assert route.framework == "express"
    assert route.handler_function_id == handler.id
    assert any(item.kind == "http_query" and "term" in item.variables for item in result.sources)
    assert any(item.kind == "raw_sql" and item.enclosing_function_id for item in result.sinks)
    assert any(item.callee == "runQuery" and item.argument_sources == [["db"], ["term"]] for item in result.call_sites)


def test_compiler_payload_does_not_treat_sql_options_as_bindings(tmp_path: Path) -> None:
    payload = compiler_payload()
    payload["facts"]["calls"] = [
        {
            "callee": "db.query",
            "expression": "db.query('SELECT * FROM users WHERE name = ' + term, { timeout: 1000 })",
            "line": 5,
            "scopeKey": "function:run",
            "argumentTexts": ["'SELECT * FROM users WHERE name = ' + term", "{ timeout: 1000 }"],
            "argumentSources": [["term"], []],
            "argumentLiterals": [None, None],
            "argumentFunctionKeys": [None, None],
        }
    ]

    result = compiler_payload_to_result(source_file(tmp_path), payload)

    assert any(item.kind == "raw_sql" for item in result.sinks)
    assert not any(item.kind == "parameterized_query" for item in result.sanitizers)


def test_scanner_uses_compiler_result_and_marks_file_ast(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "app.ts"
    path.write_text(SOURCE, encoding="utf-8")

    def fake_compiler(source: SourceFile):
        return compiler_payload_to_result(source, compiler_payload()), {
            "status": "ok",
            "reason": "fixture compiler",
            "used": True,
            "fallback": False,
            "version": "5.test",
        }

    monkeypatch.setattr("auditforge.typescript_compiler_bridge.analyze_typescript_with_compiler", fake_compiler)
    facts = scan_repo(tmp_path)

    assert facts.files[0].parsed_by == "ast"
    assert facts.analysis_diagnostics["typescript_compiler"]["ast_files"] == 1
    assert facts.analysis_diagnostics["typescript_compiler"]["fallback_files"] == 0
    assert facts.analysis_diagnostics["language_frontends"]["typescript-compiler-api"] == 1
    assert all(item.analysis_method == "ast" for item in [*facts.functions, *facts.sources, *facts.sinks])


def test_scanner_explicitly_falls_back_when_typescript_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "app.ts"
    path.write_text(SOURCE, encoding="utf-8")

    monkeypatch.setattr(
        "auditforge.typescript_compiler_bridge.analyze_typescript_with_compiler",
        lambda _source: (
            None,
            {
                "status": "typescript_not_found",
                "reason": "Cannot find module 'typescript'",
                "used": False,
                "fallback": True,
            },
        ),
    )
    facts = scan_repo(tmp_path)

    diagnostic = facts.analysis_diagnostics["typescript_compiler"]
    assert facts.files[0].parsed_by == "heuristic"
    assert diagnostic["available"] is False
    assert diagnostic["attempted_files"] == 1
    assert diagnostic["ast_files"] == 0
    assert diagnostic["fallback_files"] == 1
    assert diagnostic["statuses"] == {"typescript_not_found": 1}
    assert diagnostic["files"][0]["status"] == "typescript_not_found"
    assert facts.analysis_diagnostics["language_frontends"]["typescript-v1"] == 1
    assert any(item.analysis_method == "heuristic" for item in facts.functions)


def test_bridge_returns_node_not_found_diagnostic_without_running_target(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("auditforge.typescript_compiler_bridge.shutil.which", lambda _name: None)

    result, diagnostic = analyze_typescript_with_compiler(source_file(tmp_path))

    assert result is None
    assert diagnostic["status"] == "node_not_found"
    assert diagnostic["fallback"] is True
