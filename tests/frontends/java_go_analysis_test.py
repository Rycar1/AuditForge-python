from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from auditforge.candidates import build_trace_candidates
from auditforge.graph import build_graph
from auditforge.java_go_analysis import analyze_go, analyze_java, analyze_java_go
from auditforge.models import IndexedFile
from auditforge.scanner import scan_repo

ROOT = Path(__file__).resolve().parents[1]


def source_file(path: str, language: str, source: str):
    return SimpleNamespace(
        file=IndexedFile(
            id=f"file:{path}",
            path=path,
            language=language,
            bytes=len(source.encode()),
            lines=len(source.splitlines()),
            parsed_by="heuristic",
        ),
        content=source,
        lines=source.splitlines(),
    )


def test_java_spring_bindings_routes_and_security_sinks() -> None:
    source = """package demo;
@RestController
@RequestMapping("/api")
public class AuditController {
    @GetMapping("/search/{id}")
    public String search(@PathVariable String id, @RequestParam("q") String q, @RequestHeader("X-Tenant") String tenant, @CookieValue("sid") String sid) {
        String sql = "select * from users where name='" + q + "'";
        statement.executeQuery(sql);
        return sql;
    }

    @PostMapping("/fetch")
    public String fetch(@RequestBody Payload body) {
        entityManager.createNativeQuery(body.jpql);
        Runtime.getRuntime().exec(body.command);
        new ProcessBuilder(body.command, body.argument).start();
        response.getWriter().write(body.html);
        return restTemplate.getForObject(body.url, String.class);
    }
}
"""

    result = analyze_java(source_file("src/AuditController.java", "java", source))

    assert [(route.method, route.path, route.framework) for route in result.routes] == [
        ("GET", "/api/search/{id}", "spring"),
        ("POST", "/api/fetch", "spring"),
    ]
    assert all(route.handler_function_id for route in result.routes)
    source_kinds = {(item.kind, tuple(item.variables)) for item in result.sources}
    assert ("http_path", ("id",)) in source_kinds
    assert ("http_query", ("q",)) in source_kinds
    assert ("http_header", ("tenant",)) in source_kinds
    assert ("cookie", ("sid",)) in source_kinds
    assert ("http_body", ("body",)) in source_kinds
    sink_kinds = [item.kind for item in result.sinks]
    assert sink_kinds.count("raw_sql") == 2
    assert sink_kinds.count("command_execution") == 2
    assert "html_output" in sink_kinds
    assert "external_request" in sink_kinds
    assert any(flow.target == "sql" and "q" in flow.sources for flow in result.data_flows)
    assert all(item.enclosing_function_id for item in [*result.sources, *result.sinks])


def test_java_servlet_sources_and_http_request_builder_are_modeled() -> None:
    source = """public class ServletHandler {
    public void handle(HttpServletRequest request) {
        String query = request.getParameter("q");
        String tenant = request.getHeader("X-Tenant");
        String body = request.getReader().readLine();
        URI target = URI.create(query);
        httpClient.send(requestObject);
    }
}
"""

    result = analyze_java_go(source_file("ServletHandler.java", "java", source))

    assert {(item.kind, tuple(item.variables)) for item in result.sources} >= {
        ("http_query", ("query",)),
        ("http_header", ("tenant",)),
        ("http_body", ("body",)),
    }
    assert [item.kind for item in result.sinks].count("external_request") == 2


def test_java_frontend_scope_merges_with_generic_facts_for_trace_candidates() -> None:
    facts = scan_repo(ROOT / "fixtures" / "polyglot_language_vuln_lab")

    candidates = build_trace_candidates(facts, build_graph(facts))

    java = [
        candidate for candidate in candidates if candidate.source.file == "Controller.java" and candidate.sink.file == "Controller.java"
    ]
    assert len(java) == 1
    assert (java[0].source.start_line, java[0].sink.start_line) == (4, 5)
    source = next(item for item in facts.sources if item.anchor.file == "Controller.java" and item.anchor.start_line == 4)
    sink = next(item for item in facts.sinks if item.anchor.file == "Controller.java" and item.anchor.start_line == 5)
    assert source.enclosing_function_id == sink.enclosing_function_id


def test_go_framework_routes_bindings_and_security_sinks() -> None:
    source = """package main

func native(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    header := r.Header.Get("X-Tenant")
    fmt.Fprintf(w, query)
    _ = header
}

func ginHandler(c *gin.Context) {
    query := c.Query("q")
    form := c.PostForm("name")
    id := c.Param("id")
    header := c.GetHeader("X-Tenant")
    cookie, _ := c.Cookie("sid")
    var payload Payload
    c.ShouldBindJSON(&payload)
    db.Raw(query).Rows()
    exec.Command(payload.Command, payload.Argument).Run()
    template.HTML(payload.HTML)
    http.Get(payload.URL)
    _ = form
    _ = id
    _ = header
    _ = cookie
}

func echoHandler(c echo.Context) error {
    id := c.Param("id")
    payload := new(Payload)
    c.Bind(payload)
    return c.HTML(200, payload.HTML)
}

func main() {
    http.HandleFunc("GET /native", native)
    r.GET("/gin/:id", ginHandler)
    e.POST("/echo/:id", echoHandler)
}
"""

    result = analyze_go(source_file("handlers.go", "go", source))

    assert {(route.method, route.path, route.framework) for route in result.routes} == {
        ("GET", "/native", "go-net-http"),
        ("GET", "/gin/:id", "gin"),
        ("POST", "/echo/:id", "echo"),
    }
    assert all(route.handler_function_id for route in result.routes)
    source_kinds = {item.kind for item in result.sources}
    assert {"http_query", "http_body", "http_path", "http_header", "cookie"} <= source_kinds
    assert any(item.kind == "http_body" and item.variables == ["payload"] for item in result.sources)
    sink_kinds = {item.kind for item in result.sinks}
    assert {"raw_sql", "command_execution", "html_output", "external_request"} <= sink_kinds
    assert any(item.kind == "raw_sql" and item.variables == ["query"] for item in result.sinks)
    assert any(item.kind == "command_execution" and "payload.Command" in item.variables for item in result.sinks)
    assert all(item.enclosing_function_id for item in [*result.sources, *result.sinks])


def test_go_gorm_group_prefix_and_request_construction() -> None:
    source = """package api

func fetch(c *gin.Context) {
    target := c.Query("url")
    req, _ := http.NewRequest("GET", target, nil)
    client.Do(req)
    db.Where(target).Find(&rows)
}

func routes() {
    api := router.Group("/api")
    api.GET("/fetch", fetch)
}
"""

    result = analyze_java_go(source_file("api.go", "go", source))

    assert [(item.method, item.path) for item in result.routes] == [("GET", "/api/fetch")]
    assert [item.kind for item in result.sinks].count("external_request") == 2
    assert any(item.kind == "raw_sql" and item.variables == ["target"] for item in result.sinks)
