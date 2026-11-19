from __future__ import annotations

from auditforge.analysis.candidates import build_trace_candidates
from auditforge.analysis.graph import build_graph
from auditforge.analysis.scanner import scan_repo


def test_typescript_import_binding_resolves_cross_file_taint_path(tmp_path) -> None:
    (tmp_path / "repository.ts").write_text(
        "export function runQuery(db: any, term: string) {\n"
        "  const sql = `SELECT * FROM users WHERE name = '${term}'`;\n"
        "  return db.query(sql);\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "controller.ts").write_text(
        "import { runQuery } from './repository';\n"
        "import express from 'express';\n"
        "const app = express();\n"
        "app.get('/search', (req, res) => {\n"
        "  const term = req.query.q;\n"
        "  return runQuery(db, term);\n"
        "});\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    graph = build_graph(facts)
    candidates = build_trace_candidates(facts, graph)

    assert any(item.module == "./repository" and item.aliases == {"runQuery": "runQuery"} for item in facts.imports)
    assert any(
        edge.kind == "CALLS" and edge.metadata.get("cross_file") is True and edge.metadata.get("resolved_by") == "import_or_scoped_name"
        for edge in graph.edges
    )
    assert any(
        item.vuln_class == "injection"
        and item.source.file == "controller.ts"
        and item.source.start_line == 5
        and item.sink.file == "repository.ts"
        and item.sink.start_line == 3
        for item in candidates
    )


def test_java_constructor_injected_service_receiver_resolves_across_files(tmp_path) -> None:
    (tmp_path / "UserService.java").write_text(
        "class UserService {\n"
        "  String find(String id, Database db) {\n"
        '    String sql = "SELECT * FROM accounts WHERE id = " + id;\n'
        "    return db.execute(sql);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "AccountController.java").write_text(
        "import example.UserService;\n"
        "class AccountController {\n"
        "  private final UserService userService;\n"
        "  AccountController(UserService userService) { this.userService = userService; }\n"
        '  @GetMapping("/accounts")\n'
        "  String account(@RequestParam String id, Database db) {\n"
        "    return userService.find(id, db);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    candidates = build_trace_candidates(facts, build_graph(facts))

    assert any(
        item.vuln_class == "injection" and item.source.file == "AccountController.java" and item.sink.file == "UserService.java"
        for item in candidates
    )
