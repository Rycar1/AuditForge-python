from __future__ import annotations

import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread

import pytest

import auditforge.verification.verification as verification
from auditforge.core.models import CodeAnchor, CodeFacts, RouteFact, SourceFact, TraceCandidate
from auditforge.verification.verification import (
    SAFE_UUID_PATH_VALUE,
    HttpResponseRecord,
    build_safe_request_contract,
    execute_safe_request_contract,
    join_url,
    materialize_contract_route_path,
    normalize_http_method,
    parse_route_methods,
    route_allows_safe_probe,
    run_safe_verification,
    safe_http_request,
    validate_target_url,
)


def candidate(route_id: str = "route") -> TraceCandidate:
    anchor = CodeAnchor("app.py", 2, 2, "hash", "request.args.get('q')")
    return TraceCandidate(
        id="SEC-1",
        vuln_class="xss",
        source=anchor,
        sink=CodeAnchor("app.py", 3, 3, "sink", "html_output"),
        steps=[],
        sanitizers=[],
        blockers=[],
        confidence="medium",
        static_evidence="test",
        verification_hint="test",
        route_id=route_id,
    )


def test_target_url_rejects_file_metadata_and_credentials() -> None:
    with pytest.raises(ValueError, match="http"):
        validate_target_url("file:///etc/passwd")
    with pytest.raises(ValueError, match="metadata"):
        validate_target_url("http://169.254.169.254")
    with pytest.raises(ValueError, match="凭据"):
        validate_target_url("https://user:password@example.com")


def test_join_url_rejects_absolute_cross_origin_routes() -> None:
    with pytest.raises(ValueError, match="origin"):
        join_url("http://127.0.0.1:8080", "https://attacker.invalid/collect")
    with pytest.raises(ValueError, match="origin"):
        join_url("http://127.0.0.1:8080", "//attacker.invalid/collect")


def test_safe_mode_does_not_probe_post_only_routes() -> None:
    facts = CodeFacts(routes=[RouteFact("route", "POST", "/notes", "flask-like", CodeAnchor("app.py", 1, 1, "route", "notes"))])

    result = run_safe_verification([candidate()], facts, "http://127.0.0.1:9")

    assert result[0].status == "needs_manual_review"
    assert result[0].request_log == []


def test_safe_verifier_runs_candidates_concurrently_and_preserves_order(monkeypatch: pytest.MonkeyPatch) -> None:
    facts = CodeFacts(
        routes=[
            RouteFact(f"route-{index}", "GET", f"/item/{index}", "test", CodeAnchor("app.py", index, index, f"r{index}"))
            for index in range(1, 5)
        ]
    )
    candidates = [replace(candidate(f"route-{index}"), id=f"candidate-{index}") for index in range(1, 5)]
    lock = Lock()
    active = 0
    maximum = 0

    def fake_reflection(item, *_args, **_kwargs):  # noqa: ANN001, ANN202 - verification test double
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.04)
        with lock:
            active -= 1
        return verification.VerificationResult(item.id, "needs_manual_review", ["probe complete"])

    monkeypatch.setattr(verification, "verify_reflection_candidate", fake_reflection)

    results = run_safe_verification(candidates, facts, "http://127.0.0.1:8080", concurrency=3)

    assert maximum == 3
    assert [item.candidate_id for item in results] == [item.id for item in candidates]


def source(kind: str, expression: str, variable: str) -> SourceFact:
    anchor = CodeAnchor("app.py", 2, 2, "source-hash", variable)
    return SourceFact(
        id=f"source-{kind}",
        kind=kind,
        expression=expression,
        anchor=anchor,
        confidence="high",
        variables=[variable],
        input_variables=[variable],
    )


def test_json_contract_materializes_path_and_body_without_network() -> None:
    route = RouteFact(
        "route",
        "POST",
        "/items/{item_id}",
        "fastapi-like",
        CodeAnchor("app.py", 1, 1, "route-hash", "create_item"),
    )
    body_source = source("http_body", "route parameter payload", "payload")

    contract = build_safe_request_contract(
        candidate(),
        route,
        "http://127.0.0.1:8080",
        body_source,
        "AF_MARKER",
        allow_state_changes=True,
    )

    assert contract.method == "POST"
    assert contract.url == "http://127.0.0.1:8080/items/1"
    assert contract.source_location == "json"
    assert contract.json_body == {"payload": "AF_MARKER"}
    assert contract.form_body is None
    assert contract.query == {}


def test_json_contract_executor_serializes_body_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_exchange(method, url, data=None, headers=None):  # noqa: ANN001, ANN202 - no-network transport double
        captured.update(method=method, url=url, data=data, headers=headers)
        return HttpResponseRecord(method, url, 200, 1, "ok")

    monkeypatch.setattr(verification, "safe_http_exchange", fake_exchange)
    route = RouteFact(
        "route",
        "POST",
        "/items/{item_id}",
        "fastapi-like",
        CodeAnchor("app.py", 1, 1, "route-hash", "create_item"),
    )
    contract = build_safe_request_contract(
        candidate(),
        route,
        "http://127.0.0.1:8080",
        source("http_body", "request.json.get('display_name')", "display_name"),
        "AF_MARKER",
        allow_state_changes=True,
    )

    result = execute_safe_request_contract(contract)

    assert result.status == 200
    assert captured == {
        "method": "POST",
        "url": "http://127.0.0.1:8080/items/1",
        "data": b'{"display_name":"AF_MARKER"}',
        "headers": {"Content-Type": "application/json"},
    }


def test_contract_selects_patch_header_and_typed_uuid_path_without_network() -> None:
    route = RouteFact(
        "route",
        "PATCH",
        "/accounts/<uuid:account_uuid>",
        "flask-like",
        CodeAnchor("app.py", 1, 1, "route-hash", "update_account"),
    )
    header_source = source("http_header", "request.headers.get('X-User')", "current_user")

    contract = build_safe_request_contract(
        candidate(),
        route,
        "http://127.0.0.1:8080",
        header_source,
        "AF_MARKER",
        allow_state_changes=True,
    )

    assert contract.method == "PATCH"
    assert contract.url == f"http://127.0.0.1:8080/accounts/{SAFE_UUID_PATH_VALUE}"
    assert contract.source_location == "header"
    assert contract.headers == {"X-User": "AF_MARKER"}
    assert contract.json_body is None


def test_contract_supports_form_put_and_delete_path_without_network() -> None:
    form_route = RouteFact(
        "form-route",
        "PUT",
        "/profiles/:profile_id",
        "express-like",
        CodeAnchor("app.py", 1, 1, "form-route-hash", "profile"),
    )
    form_source = source("http_body", "request.form.get('nickname')", "nickname")
    form_contract = build_safe_request_contract(
        candidate(),
        form_route,
        "http://127.0.0.1:8080",
        form_source,
        "AF_MARKER",
        allow_state_changes=True,
    )

    delete_route = RouteFact(
        "delete-route",
        "DELETE",
        "/items/:item_id",
        "express-like",
        CodeAnchor("app.py", 1, 1, "delete-route-hash", "delete_item"),
    )
    path_source = source("http_path", "route parameter item_id", "item_id")
    delete_contract = build_safe_request_contract(
        candidate(),
        delete_route,
        "http://127.0.0.1:8080",
        path_source,
        "AF_MARKER",
        allow_state_changes=True,
    )

    assert form_contract.method == "PUT"
    assert form_contract.url == "http://127.0.0.1:8080/profiles/1"
    assert form_contract.source_location == "form"
    assert form_contract.form_body == {"nickname": "AF_MARKER"}
    assert delete_contract.method == "DELETE"
    assert delete_contract.url == "http://127.0.0.1:8080/items/1"
    assert delete_contract.source_location == "path"


def test_contract_method_policy_keeps_write_methods_stateful_only() -> None:
    assert parse_route_methods("GET, post | PATCH / DELETE") == ["GET", "POST", "PATCH", "DELETE"]
    assert route_allows_safe_probe("GET,PATCH") is True
    assert route_allows_safe_probe("PATCH") is False
    assert route_allows_safe_probe("PATCH", allow_state_changes=True) is True
    assert route_allows_safe_probe("TRACE", allow_state_changes=True) is False
    with pytest.raises(ValueError, match="不支持"):
        normalize_http_method("TRACE")


def test_path_contract_encodes_string_markers_and_defaults_typed_values() -> None:
    path = materialize_contract_route_path(
        "/teams/{team_id}/documents/{slug}/revisions/<int:revision>",
        {"team_id": "AF_MARKER", "slug": "AF marker/child", "revision": "not-an-int"},
    )

    assert path == "/teams/1/documents/AF%20marker%2Fchild/revisions/1"


class RedirectFixture(BaseHTTPRequestHandler):
    final_requests = 0

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        type(self).final_requests += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"followed")

    def log_message(self, fmt: str, *args) -> None:
        return


def test_safe_http_does_not_follow_redirects() -> None:
    RedirectFixture.final_requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectFixture)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = safe_http_request(f"http://127.0.0.1:{server.server_port}/redirect")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert response.status == 302
    assert RedirectFixture.final_requests == 0
