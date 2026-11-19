from __future__ import annotations

from pathlib import Path

from auditforge.analysis.candidates import build_trace_candidates
from auditforge.analysis.graph import build_graph
from auditforge.analysis.scanner import SourceFile, language_for_path
from auditforge.core.models import CodeFacts, IndexedFile
from auditforge.core.utils import line_count, stable_id
from auditforge.frontends.php_analysis import analyze_php


def analyze(tmp_path: Path, content: str, name: str = "app.php"):
    # This is a unit test for the PHP frontend. Avoid the Windows temporary-file
    # share lock that can be held briefly for newly created PHP files by local
    # security scanners; integration coverage exercises index_source_files.
    source_file = SourceFile(
        file=IndexedFile(
            id=stable_id("file", name, 1, name),
            path=name,
            language="php",
            bytes=len(content.encode("utf-8")),
            lines=line_count(content),
            parsed_by="heuristic",
        ),
        absolute_path=tmp_path / name,
        content=content,
        lines=content.splitlines(),
    )
    return analyze_php(source_file)


def code_facts(result) -> CodeFacts:  # noqa: ANN001
    return CodeFacts(
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


def test_php_native_sources_and_dangerous_sinks_create_scoped_facts(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        r"""<?php
function audit(PDO $pdo) {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id=" . $id;
    $pdo->query($sql);
    $pdo->exec($sql);
    $cmd = $_POST['cmd'];
    exec($cmd);
    $path = $_REQUEST['path'];
    include $path;
    $blob = $_COOKIE['blob'];
    unserialize($blob);
    $upload = $_FILES['avatar'];
    $headers = getallheaders();
}
""",
    )
    facts = code_facts(result)
    candidates = build_trace_candidates(facts, build_graph(facts))

    source_kinds = {item.kind for item in result.sources}
    sink_kinds = {item.kind for item in result.sinks}
    assert {"http_query", "http_body", "cookie", "file_upload", "http_header"}.issubset(source_kinds)
    assert {"raw_sql", "command_execution", "file_path", "deserialization"}.issubset(sink_kinds)
    assert sum(item.kind == "raw_sql" for item in result.sinks) == 2
    assert sum(item.kind == "command_execution" for item in result.sinks) == 1
    assert not any(item.anchor.start_line in {5, 6} for item in result.sources)
    assert all(item.enclosing_function_id == result.functions[0].id for item in [*result.sources, *result.sinks])
    assert {item.vuln_class for item in candidates} >= {"injection"}


def test_laravel_request_sources_routes_and_raw_sql(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        r"""<?php
use Illuminate\Http\Request;
class UserController
{
    public function show(
        Request $request,
        $id
    ) {
        $query = $request->query('q');
        $name = $request->input('name');
        $actor = $request->header('X-User');
        $avatar = $request->file('avatar');
        $sql = "SELECT * FROM users WHERE name='" . $query . "'";
        return DB::raw($sql);
    }
}
Route::get('/users/{id}', [UserController::class, 'show']);
""",
    )

    route = result.routes[0]
    handler = next(item for item in result.functions if item.name == "show")
    handler_sources = {(item.kind, tuple(item.variables)) for item in result.sources if item.enclosing_function_id == handler.id}

    assert (route.method, route.path, route.framework) == ("GET", "/users/{id}", "laravel-like")
    assert route.handler_function_id == handler.id
    assert ("http_path", ("$id",)) in handler_sources
    assert ("http_query", ("$query",)) in handler_sources
    assert ("http_body", ("$name",)) in handler_sources
    assert ("http_header", ("$actor",)) in handler_sources
    assert ("file_upload", ("$avatar",)) in handler_sources
    raw_sql = [item for item in result.sinks if item.kind == "raw_sql"]
    assert len(raw_sql) == 1
    assert raw_sql[0].variables == ["$sql"]


def test_symfony_attribute_route_and_request_bags(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        r"""<?php
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
class ProductController {
    #[Route('/products/{id}', methods: ['GET', 'POST'])]
    public function show(Request $request, $id) {
        $filter = $request->query->get('filter');
        $payload = $request->request->get('payload');
        $session = $request->cookies->get('session');
        return $filter . $payload . $session;
    }
}
""",
    )

    route = result.routes[0]
    kinds = {item.kind for item in result.sources}

    assert (route.method, route.path, route.framework) == ("GET,POST", "/products/{id}", "symfony-like")
    assert route.handler_function_id == result.functions[0].id
    assert {"http_query", "http_body", "cookie", "http_path"}.issubset(kinds)


def test_php_curl_and_file_get_contents_model_ssrf_flow(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function fetch_remote() {
    $url = $_GET['url'];
    $handle = curl_init();
    curl_setopt($handle, CURLOPT_URL, $url);
    curl_exec($handle);
    $body = file_get_contents($url);
    return $body;
}
""",
    )

    external = [item for item in result.sinks if item.kind == "external_request"]
    curl_flow = next(item for item in result.data_flows if item.expression == "curl_setopt(CURLOPT_URL)")

    assert {item.expression for item in external} == {"curl_exec", "file_get_contents"}
    assert curl_flow.target == "$handle"
    assert curl_flow.sources == ["$url"]
    assert any(item.kind == "file_path" and item.expression == "file_get_contents" for item in result.sinks)


def test_php_html_outputs_blade_and_sanitizers(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function render_page() {
    $raw = $_GET['bio'];
    $safe = htmlspecialchars($raw, ENT_QUOTES, 'UTF-8');
    echo $safe;
    print($raw);
    <?= $raw ?>
    $cmd = $_POST['cmd'];
    $escaped = escapeshellarg($cmd);
    system($escaped);
}
?>
{!! $raw !!}
{{ $raw }}
""",
        name="profile.blade.php",
    )

    sanitizer_kinds = {item.kind for item in result.sanitizers}
    html_sinks = [item for item in result.sinks if item.kind == "html_output"]

    assert {"html_encoding", "shell_escaping", "blade_html_encoding"}.issubset(sanitizer_kinds)
    assert len(html_sinks) == 4
    assert any("{!!" in item.expression for item in html_sinks)
    assert not any("{{ $raw }}" == item.expression.strip() for item in html_sinks)


def test_blade_suffix_is_recognized_as_php() -> None:
    assert language_for_path(Path("profile.blade.php")) == "php"


def test_laravel_match_route_and_parameterized_helpers(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function update($request) {
    $value = $request->input('value');
    $quoted = htmlspecialchars($value);
    echo $quoted;
}
Route::match(['GET', 'PATCH'], '/settings', 'SettingsController@update');
""",
    )

    assert result.routes[0].method == "GET,PATCH"
    assert result.routes[0].path == "/settings"
    assert result.routes[0].handler_function_id == result.functions[0].id


def test_php_multiline_psr7_sources_http_clients_and_namespaces(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        r"""<?php
namespace App\Http;

interface FetcherContract {}
trait RecordsAudit {}

readonly class ProxyController
{
    public function fetch(
        ServerRequestInterface $request,
        $id
    ) {
        $url = $request
            ->getQueryParams()['url'];
        $response = $client->request(
            'GET',
            $url
        );
        return $response;
    }
}

Route::match(
    ['GET', 'POST'],
    '/proxy/{id}',
    [ProxyController::class, 'fetch']
);
""",
    )

    assert {item.qualified_name for item in result.classes} == {
        r"App\Http\FetcherContract",
        r"App\Http\RecordsAudit",
        r"App\Http\ProxyController",
    }
    handler = next(item for item in result.functions if item.name == "fetch")
    assert handler.qualified_name == r"App\Http\ProxyController.fetch"
    assert result.routes[0].handler_function_id == handler.id
    assert (result.routes[0].method, result.routes[0].path) == ("GET,POST", "/proxy/{id}")
    assert any(item.kind == "http_query" and item.variables == ["$url"] for item in result.sources)
    assert any(item.kind == "external_request" and item.variables == ["$url"] for item in result.sinks)


def test_php_framework_sinks_cover_doctrine_wordpress_process_and_templates(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function dangerous($entityManager, $wpdb, $client) {
    $sql = $_GET['sql'];
    $entityManager->createQuery($sql);
    $wpdb->get_results($sql);
    $url = $_GET['url'];
    Http::get($url);
    $client->request('GET', $url);
    $command = $_POST['command'];
    $process = new Process([$command]);
    $process->run();
    $code = $_POST['code'];
    eval($code);
    $template = $_POST['template'];
    Blade::compileString($template);
}
""",
    )

    sink_kinds = [item.kind for item in result.sinks]
    assert sink_kinds.count("raw_sql") == 2
    assert sink_kinds.count("external_request") == 2
    assert sink_kinds.count("command_execution") == 1
    assert sink_kinds.count("code_evaluation") == 1
    assert sink_kinds.count("template_compilation") == 1


def test_wordpress_and_slim_routes_are_modelled(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function lookup($request, $id) {
    return $id;
}

register_rest_route(
    'audit/v1',
    '/items/(?P<id>\\d+)',
    [
        'methods' => WP_REST_Server::READABLE,
        'callback' => 'lookup',
    ]
);

$app->map(
    ['GET', 'POST'],
    '/slim/{id}',
    'lookup'
);
add_action('wp_ajax_lookup', 'lookup');
""",
    )

    routes = {(item.framework, item.method, item.path): item for item in result.routes}
    assert ("wordpress", "GET", "/audit/v1/items/(?P<id>\\d+)") in routes
    assert ("slim-like", "GET,POST", "/slim/{id}") in routes
    assert ("wordpress", "POST", "/wp-admin/admin-ajax.php?action=lookup") in routes
    assert all(item.handler_function_id == result.functions[0].id for item in routes.values())


def test_parameterized_php_queries_do_not_create_tainted_sql_candidates(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function safe_lookup(PDO $pdo, $wpdb) {
    $id = $_GET['id'];
    $statement = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $statement->bindValue(1, $id, PDO::PARAM_INT);
    $statement->execute();
    $query = $wpdb->prepare('SELECT * FROM users WHERE id = %d', $id);
    return $wpdb->get_row($query);
}
""",
    )
    facts = code_facts(result)
    candidates = build_trace_candidates(facts, build_graph(facts))

    assert any(item.kind == "parameterized_query" for item in result.sanitizers)
    assert not any(item.vuln_class == "injection" and item.sink.kind == "raw_sql" for item in candidates)


def test_php_comments_strings_and_safe_process_arrays_do_not_create_sinks(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function safe($cache) {
    $argument = $_GET['argument'];
    // $client->get($argument);
    $literal = '$wpdb->query($argument)';
    $cache->get($argument);
    $process = new Process(['/usr/bin/tool', $argument]);
    $process->run();
}
""",
    )

    assert not any(item.kind in {"external_request", "raw_sql", "command_execution"} for item in result.sinks)


def test_wordpress_prepare_keeps_dynamic_sql_structure_tainted(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function unsafe($wpdb) {
    $table = $_GET['table'];
    $query = $wpdb->prepare("SELECT * FROM $table WHERE id = %d", 1);
    return $wpdb->get_row($query);
}
""",
    )
    facts = code_facts(result)
    candidates = build_trace_candidates(facts, build_graph(facts))

    assert any(item.expression == "$wpdb->prepare" and item.variables == ["$table"] for item in result.sinks)
    assert any(item.vuln_class == "injection" and item.sink.start_line in {4, 5} for item in candidates)


def test_route_closure_body_keeps_physical_source_and_sink_lines(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
Route::get('/run', function () {
    $command = $_GET['command'];
    exec($command);
});
""",
    )

    assert result.routes[0].anchor.start_line == 2
    assert next(item for item in result.sources if item.kind == "http_query").anchor.start_line == 3
    assert next(item for item in result.sinks if item.kind == "command_execution").anchor.start_line == 4


def test_psr7_body_response_and_laravel_send_url_positions(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function proxy($request, $response) {
    $body = $request->getBody()->getContents();
    $url = $request->getQueryParams()['url'];
    Http::send('GET', $url);
    $response->getBody()->write($body);
}
""",
    )

    assert any(item.kind == "http_body" and item.variables == ["$body"] for item in result.sources)
    assert any(item.kind == "external_request" and item.variables == ["$url"] for item in result.sinks)
    assert any(item.kind == "html_output" and item.variables == ["$body"] for item in result.sinks)


def test_php_response_buffer_detects_reflected_xss_but_respects_html_encoding(tmp_path: Path) -> None:
    vulnerable = analyze(
        tmp_path,
        """<?php
$html .= '<pre>Hello ' . $_GET['name'] . '</pre>';
""",
    )
    safe = analyze(
        tmp_path,
        """<?php
$name = htmlspecialchars($_GET['name']);
$html .= "<pre>Hello {$name}</pre>";
""",
        name="safe.php",
    )

    vulnerable_candidates = build_trace_candidates(code_facts(vulnerable), build_graph(code_facts(vulnerable)))
    safe_candidates = build_trace_candidates(code_facts(safe), build_graph(code_facts(safe)))

    assert any(item.taxonomy_id == "cross_site_scripting" for item in vulnerable_candidates)
    assert not any(item.taxonomy_id == "cross_site_scripting" for item in safe_candidates)


def test_php_session_values_are_persistent_inputs_for_second_order_sqli(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
$id = $_SESSION['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
mysqli_query($db, $query);
""",
    )
    candidates = build_trace_candidates(code_facts(result), build_graph(code_facts(result)))

    assert any(item.kind == "session_data" and item.variables == ["$id"] for item in result.sources)
    assert any(item.taxonomy_id == "sql_injection" for item in candidates)


def test_php_numeric_guard_region_blocks_command_injection_flow(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
$target = $_REQUEST['ip'];
$parts = explode('.', $target);
if (is_numeric($parts[0]) && is_numeric($parts[1])) {
    $target = $parts[0] . '.' . $parts[1];
    shell_exec('ping ' . $target);
}
""",
    )
    candidates = build_trace_candidates(code_facts(result), build_graph(code_facts(result)))
    guard = next(item for item in result.sanitizers if item.anchor.symbol == "guard:type_validation")

    assert (guard.anchor.start_line, guard.anchor.end_line) == (4, 7)
    assert not any(item.taxonomy_id == "command_injection" for item in candidates)


def test_php_embedded_javascript_preserves_dom_xss_anchors(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
$page = <<<EOF
<script>
var lang = document.location.href.substring(1);
document.write("<option>" + lang + "</option>");
</script>
EOF;
""",
    )
    candidates = build_trace_candidates(code_facts(result), build_graph(code_facts(result)))

    dom = next(item for item in candidates if item.taxonomy_id == "cross_site_scripting")
    assert (dom.source.start_line, dom.sink.start_line) == (4, 5)


def test_php_database_rows_are_persistent_xss_sources(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function render_guestbook($result) {
    while ($row = mysqli_fetch_row($result)) {
        $name = $row[0];
        $guestbook .= "<div>{$name}</div>";
    }
}
""",
    )
    candidates = build_trace_candidates(code_facts(result), build_graph(code_facts(result)))

    assert any(item.kind == "database_result" and item.variables == ["$row"] for item in result.sources)
    assert any(item.taxonomy_id == "cross_site_scripting" for item in candidates)


def test_php_input_stream_is_an_http_body_source(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
function connectivity() {
    $input = (array) json_decode(file_get_contents('php://input'), true);
    $target = $input['target'];
    exec('ping -c 1 ' . $target);
}
""",
    )
    candidates = build_trace_candidates(code_facts(result), build_graph(code_facts(result)))

    source = next(item for item in result.sources if item.expression == "php://input")
    assert (source.kind, source.variables, source.anchor.start_line) == ("http_body", ["$input"], 3)
    assert any(item.taxonomy_id == "command_injection" and item.sink.start_line == 5 for item in candidates)


def test_php_sql_escaping_is_not_resurrected_by_sparse_same_scope_solver(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
$message = $_POST['message'];
$message = mysqli_real_escape_string($db, $message);
$query = "INSERT INTO notes(message) VALUES ('$message')";
mysqli_query($db, $query);
""",
    )
    candidates = build_trace_candidates(code_facts(result), build_graph(code_facts(result)))

    assert not any(item.taxonomy_id == "sql_injection" for item in candidates)


def test_php_sql_escaping_does_not_protect_unquoted_numeric_context(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        """<?php
$id = $_POST['id'];
$id = mysqli_real_escape_string($db, $id);
$query = "SELECT * FROM users WHERE id = $id";
mysqli_query($db, $query);
""",
    )
    candidates = build_trace_candidates(code_facts(result), build_graph(code_facts(result)))

    assert any(item.taxonomy_id == "sql_injection" for item in candidates)
