from __future__ import annotations

from pathlib import Path

from auditforge.analysis.candidates import build_trace_candidates
from auditforge.analysis.graph import build_graph
from auditforge.analysis.scanner import SourceFile, scan_repo
from auditforge.core.models import CodeFacts, IndexedFile
from auditforge.frontends.javascript_analysis import analyze_javascript_typescript


def source_file(tmp_path: Path, name: str, content: str) -> SourceFile:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    language = "typescript" if path.suffix in {".ts", ".tsx"} else "javascript"
    indexed = IndexedFile(
        id=f"file:{name}",
        path=name.replace("\\", "/"),
        language=language,
        bytes=len(content.encode("utf-8")),
        lines=len(content.splitlines()),
        parsed_by="heuristic",
    )
    return SourceFile(indexed, path, content, content.splitlines())


def code_facts(source: SourceFile) -> CodeFacts:
    result = analyze_javascript_typescript(source)
    return CodeFacts(
        files=[source.file],
        functions=result.functions,
        classes=result.classes,
        routes=result.routes,
        call_sites=result.call_sites,
        data_flows=result.data_flows,
        control_flows=result.control_flows,
        sources=result.sources,
        sinks=result.sinks,
        sanitizers=result.sanitizers,
    )


def test_typescript_express_cross_function_source_reaches_sql_sink(tmp_path: Path) -> None:
    source = source_file(
        tmp_path,
        "app.ts",
        "import express from 'express';\n"
        "const app = express();\n"
        "function runQuery(db: any, term: string) {\n"
        "  const sql = `SELECT * FROM users WHERE name = '${term}'`;\n"
        "  return db.query(sql);\n"
        "}\n"
        "app.get('/search', (req, res) => {\n"
        "  const term = req.query.q;\n"
        "  return runQuery(db, term);\n"
        "});\n",
    )
    facts = code_facts(source)
    candidates = build_trace_candidates(facts, build_graph(facts))

    assert any(route.framework == "express" and route.path == "/search" for route in facts.routes)
    assert any(item.kind == "http_query" and "term" in item.variables for item in facts.sources)
    assert any(item.kind == "raw_sql" and "sql" in item.variables for item in facts.sinks)
    assert any(call.callee == "runQuery" and call.argument_sources[1] == ["term"] for call in facts.call_sites)
    assert any(
        candidate.vuln_class == "injection"
        and candidate.source.start_line == 8
        and candidate.sink.start_line == 5
        and any(step.kind == "call" for step in candidate.steps)
        for candidate in candidates
    )
    emitted = [
        *facts.functions,
        *facts.routes,
        *facts.sources,
        *facts.sinks,
        *facts.call_sites,
        *facts.data_flows,
    ]
    assert emitted and all(item.analysis_method == "heuristic" for item in emitted)


def test_koa_nest_and_next_routes_and_request_sources(tmp_path: Path) -> None:
    koa = code_facts(
        source_file(
            tmp_path,
            "koa.js",
            "import Router from '@koa/router';\n"
            "const router = new Router();\n"
            "router.post('/render', async (ctx) => {\n"
            "  const name = ctx.request.body.name;\n"
            "  ctx.body = `<h1>${name}</h1>`;\n"
            "});\n",
        )
    )
    nest = code_facts(
        source_file(
            tmp_path,
            "users.controller.ts",
            "import { Controller, Get, Param, Req } from '@nestjs/common';\n"
            "@Controller('users')\n"
            "export class UsersController {\n"
            "  @Get(':id')\n"
            "  async find(@Param('id') id: string, @Req() req: Request) {\n"
            "    if (req.user) return this.service.load(id);\n"
            "  }\n"
            "}\n",
        )
    )
    nextjs = code_facts(
        source_file(
            tmp_path,
            "app/api/proxy/route.ts",
            "import { NextRequest } from 'next/server';\n"
            "export async function GET(request: NextRequest) {\n"
            "  const url = request.nextUrl.searchParams.get('url');\n"
            "  return fetch(url);\n"
            "}\n",
        )
    )

    assert any(route.framework == "koa" and route.path == "/render" for route in koa.routes)
    assert any(source.kind == "http_body" for source in koa.sources)
    assert any(sink.kind == "html_output" for sink in koa.sinks)
    assert any(route.framework == "nestjs" and route.path == "/users/:id" for route in nest.routes)
    assert {source.kind for source in nest.sources} >= {"http_path", "http_request"}
    assert any(flow.kind == "if" and "req" in flow.variables for flow in nest.control_flows)
    assert any(route.framework == "nextjs" and route.method == "GET" and route.path == "/api/proxy" for route in nextjs.routes)
    assert any(source.kind == "http_query" and "url" in source.variables for source in nextjs.sources)
    assert any(sink.kind == "external_request" and "url" in sink.variables for sink in nextjs.sinks)


def test_javascript_sink_sanitizer_and_flow_taxonomy(tmp_path: Path) -> None:
    facts = code_facts(
        source_file(
            tmp_path,
            "dangerous.jsx",
            "function dangerous(input) {\n"
            "  const id = parseInt(input, 10);\n"
            "  const safe = DOMPurify.sanitize(input);\n"
            "  if (input) { db.query('SELECT ' + input); }\n"
            "  child_process.exec(input);\n"
            "  fs.readFile(input, callback);\n"
            "  yaml.load(input);\n"
            "  eval(input);\n"
            "  res.send(input);\n"
            "  fetch(input);\n"
            "  element.dangerouslySetInnerHTML = { __html: input };\n"
            "  return safe;\n"
            "}\n",
        )
    )

    assert {sink.kind for sink in facts.sinks} >= {
        "raw_sql",
        "command_execution",
        "file_path",
        "deserialization",
        "code_evaluation",
        "html_output",
        "external_request",
    }
    assert {sanitizer.kind for sanitizer in facts.sanitizers} >= {"type_validation", "html_escape"}
    assert any(flow.kind == "assignment" and flow.target == "safe" for flow in facts.data_flows)
    assert any(flow.kind == "return" and "safe" in flow.sources for flow in facts.data_flows)
    assert any(flow.kind == "if" and "input" in flow.variables for flow in facts.control_flows)
    assert any(call.callee == "fetch" for call in facts.call_sites)


def test_nodegoat_style_eval_of_request_body_is_code_injection(tmp_path: Path) -> None:
    facts = code_facts(
        source_file(
            tmp_path,
            "contributions.js",
            "function update(req) {\n  const preTax = eval(req.body.preTax);\n  return preTax;\n}\n",
        )
    )
    candidates = build_trace_candidates(facts, build_graph(facts))

    sink = next(item for item in facts.sinks if item.kind == "code_evaluation")
    assert sink.taxonomy_id == "code_injection"
    assert sink.cwe_ids == ["CWE-95"]
    assert not any(item.kind == "deserialization" for item in facts.sinks)
    assert any(item.taxonomy_id == "code_injection" and item.sink.start_line == 2 for item in candidates)


def test_scanner_preserves_cross_function_typescript_flow_in_language_lab() -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_language_vuln_lab"
    facts = scan_repo(repo)
    candidates = build_trace_candidates(facts, build_graph(facts))

    assert any(
        candidate.vuln_class == "injection"
        and candidate.source.file == "app.ts"
        and candidate.source.start_line == 10
        and candidate.sink.file == "app.ts"
        and candidate.sink.start_line == 6
        and any(step.kind == "call" for step in candidate.steps)
        for candidate in candidates
    )


def test_parameterized_query_and_rows_response_do_not_create_safe_route_candidate() -> None:
    repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
    facts = scan_repo(repo)
    candidates = build_trace_candidates(facts, build_graph(facts))
    server_candidates = [candidate for candidate in candidates if candidate.source.file == "server.ts"]

    assert {(candidate.vuln_class, candidate.source.start_line, candidate.sink.start_line) for candidate in server_candidates} == {
        ("injection", 7, 8),
        ("xss", 13, 14),
    }
    assert any(item.kind == "parameterized_query" and item.anchor.start_line == 19 for item in facts.sanitizers)
    assert not any(candidate.source.start_line == 18 for candidate in server_candidates)


def test_cve_regression_patterns_detect_dynamic_lodash_template_and_prototype_merge(tmp_path: Path) -> None:
    source = source_file(
        tmp_path,
        "cve-patterns.ts",
        "function render(req, target) {\n"
        "  const template = req.query.template;\n"
        "  const payload = req.body;\n"
        "  _.template(template);\n"
        "  _.merge(target, payload);\n"
        "}\n",
    )
    facts = code_facts(source)
    candidates = build_trace_candidates(facts, build_graph(facts))

    assert {item.taxonomy_id for item in facts.sinks} >= {"template_injection", "prototype_pollution"}
    assert {item.vuln_class for item in candidates} >= {"injection"}
    assert any(item.sink.start_line == 4 and item.sink.symbol == "template_compilation" for item in candidates)
    assert any(item.sink.start_line == 5 and item.sink.symbol == "prototype_mutation" for item in candidates)


def test_sql_sanitizer_requires_matching_placeholder_and_binding(tmp_path: Path) -> None:
    facts = code_facts(
        source_file(
            tmp_path,
            "queries.ts",
            "function queries(db: any, user: string) {\n"
            "  db.query('SELECT * FROM users WHERE id = ' + user, { timeout: 10 });\n"
            "  db.query('SELECT * FROM users WHERE id = :id', { other: user });\n"
            "  db.query('SELECT * FROM users WHERE id = :id', { id: user });\n"
            "}\n",
        )
    )

    parameterized_lines = {item.anchor.start_line for item in facts.sanitizers if item.kind == "parameterized_query"}

    assert parameterized_lines == {4}


def test_second_sql_argument_does_not_hide_concatenated_injection(tmp_path: Path) -> None:
    source = source_file(
        tmp_path,
        "unsafe-options.ts",
        "function handler(req: any, db: any) {\n"
        "  const user = req.query.user;\n"
        "  return db.query('SELECT * FROM users WHERE name = ' + user, { timeout: 10 });\n"
        "}\n",
    )
    facts = code_facts(source)

    candidates = build_trace_candidates(facts, build_graph(facts))

    assert not any(item.kind == "parameterized_query" for item in facts.sanitizers)
    assert any(candidate.source.start_line == 2 and candidate.sink.start_line == 3 for candidate in candidates)


def test_browser_location_flows_to_dom_html_sink(tmp_path: Path) -> None:
    facts = code_facts(
        source_file(
            tmp_path,
            "dom.js",
            "const value = document.location.href.substring(1);\n"
            "document.write('<div>' + value + '</div>');\n",
        )
    )
    candidates = build_trace_candidates(facts, build_graph(facts))

    source = next(item for item in facts.sources if item.kind == "browser_location")
    candidate = next(item for item in candidates if item.taxonomy_id == "cross_site_scripting")
    assert "value" in source.variables
    assert (candidate.source.start_line, candidate.sink.start_line) == (1, 2)
