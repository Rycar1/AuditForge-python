from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlparse

from auditforge.core.models import CodeAnchor, CodeFacts, FunctionFact, RouteFact, TraceCandidate
from auditforge.engine import run_scan
from auditforge.verification.verification import run_safe_verification


class ReflectionFixture(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/profile":
            body = "<h1>" + query.get("name", [""])[0] + "</h1>"
            self.send_response(200)
        elif parsed.path == "/render":
            body = "<div>" + query.get("msg", [""])[0] + "</div>"
            self.send_response(200)
        elif parsed.path in {"/search", "/orders"}:
            body = "ok"
            self.send_response(200)
        else:
            body = "missing"
            self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


class RuntimeEvidenceFixture(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/search":
            body = "sqlite unrecognized token near quote" if "'" in query.get("q", [""])[0] else "ok"
        elif parsed.path == "/admin":
            body = "Admin Console <table><th>API Key</th><th>Balance</th></table>" if query.get("admin") == ["true"] else "Access denied"
        elif parsed.path in {"/profile/1", "/profile/2"}:
            body = "User Profile Email API Key Balance"
        elif parsed.path == "/fetch":
            body = "Response preview " + query.get("url", [""])[0] + " Vulnerable Flask Lab Components"
        else:
            body = "missing"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


class DirectEndpointEvidenceFixture(BaseHTTPRequestHandler):
    notes: list[str] = []
    uploads: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback
        parsed = urlparse(self.path)
        if parsed.path == "/config":
            body = "SECRET_KEY DEBUG SESSION_COOKIE_HTTPONLY ADMIN_API_KEY"
        elif parsed.path == "/admin" and self.headers.get("Cookie", "").find(base64.b64encode(b"auditforge:admin").decode("ascii")) >= 0:
            body = "Admin Console <table><th>API Key</th><th>Balance</th></table>"
        elif parsed.path == "/notes":
            body = "\n".join(type(self).notes)
        elif parsed.path in type(self).uploads:
            body = type(self).uploads[parsed.path]
        else:
            body = "missing"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback
        parsed = urlparse(self.path)
        size = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(size)
        form = parse_qs(raw_body.decode("utf-8", errors="replace"))
        if parsed.path == "/crypto":
            value = form.get("value", [""])[0]
            body = "Base64 token demo " + hashlib.md5(value.encode("utf-8")).hexdigest()
        elif parsed.path == "/reset-password":
            username = form.get("username", [""])[0]
            body = f"Password changed for {username} without verification."
        elif parsed.path == "/notes":
            body = form.get("body", [""])[0]
            type(self).notes.append(body)
        elif parsed.path == "/deserialize":
            body = "Result {'auditforge': 'safe'}"
        elif parsed.path == "/upload":
            marker = "<af-auditforge-upload></af-auditforge-upload>"
            if b"auditforge_safe_upload_probe.html" in raw_body and marker.encode() in raw_body:
                type(self).uploads["/uploads/auditforge_safe_upload_probe.html"] = marker
                body = "/uploads/auditforge_safe_upload_probe.html"
            else:
                body = "missing"
        elif parsed.path == "/login":
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            body = "sqlite unrecognized token near quote" if "'" in username and "'" not in password else "Invalid credentials"
        else:
            body = "missing"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


def _candidate(
    candidate_id: str,
    vuln_class: str,
    line: int,
    symbol: str,
    sink_symbol: str = "raw_sql",
    route_id: str | None = None,
    sink_line: int | None = None,
) -> TraceCandidate:
    actual_sink_line = sink_line or line + 1
    return TraceCandidate(
        id=candidate_id,
        vuln_class=vuln_class,  # type: ignore[arg-type]
        source=CodeAnchor("app.py", line, line, f"src-{line}", symbol),
        sink=CodeAnchor("app.py", actual_sink_line, actual_sink_line, f"sink-{actual_sink_line}", sink_symbol),
        steps=[],
        sanitizers=[],
        blockers=[],
        confidence="high",
        static_evidence=symbol,
        verification_hint="safe runtime test",
        route_id=route_id,
    )


def test_safe_verifier_uses_real_source_parameters(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReflectionFixture)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        repo = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot_vulnerable"
        result = run_scan(repo, tmp_path, f"http://127.0.0.1:{server.server_port}", "safe")
        candidates = {item.id: item for item in result.candidates}
        confirmed = {
            (candidates[item.candidate_id].source.file, candidates[item.candidate_id].source.start_line)
            for item in result.verification_results
            if item.status == "confirmed" and item.candidate_id in candidates
        }
        urls = [entry["url"] for item in result.verification_results for entry in item.request_log]
        assert ("app.py", 18) in confirmed
        assert ("server.ts", 13) in confirmed
        assert any("/profile?name=" in url for url in urls)
        assert any("/render?msg=" in url for url in urls)
    finally:
        server.shutdown()


def test_safe_verifier_confirms_non_destructive_runtime_evidence() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), RuntimeEvidenceFixture)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        facts = CodeFacts(
            routes=[
                RouteFact("route-search", "GET", "/search", "flask-like", CodeAnchor("app.py", 10, 10, "r1", "search")),
                RouteFact("route-admin", "GET", "/admin", "flask-like", CodeAnchor("app.py", 20, 20, "r2", "admin")),
                RouteFact("route-profile", "GET", "/profile/<int:user_id>", "flask-like", CodeAnchor("app.py", 30, 30, "r3", "profile")),
                RouteFact("route-fetch", "GET", "/fetch", "flask-like", CodeAnchor("app.py", 40, 40, "r4", "fetch")),
            ],
            functions=[
                FunctionFact("fn-admin", "admin", CodeAnchor("app.py", 21, 26, "f1", "admin"), []),
                FunctionFact("fn-profile", "profile", CodeAnchor("app.py", 31, 36, "f2", "profile"), ["user_id"]),
                FunctionFact("fn-fetch", "fetch", CodeAnchor("app.py", 41, 46, "f3", "fetch"), []),
            ],
        )
        candidates = [
            _candidate("SQLI", "injection", 11, "q", route_id="route-search"),
            _candidate("ADMIN", "authz", 22, 'request.args.get("admin")', "authorization_decision"),
            _candidate("IDOR", "authz", 32, "user_id", "render_template"),
            _candidate("SSRF", "ssrf", 42, "url", "urllib.request.urlopen"),
        ]

        results = run_safe_verification(candidates, facts, f"http://127.0.0.1:{server.server_port}")

        assert {item.candidate_id for item in results if item.status == "confirmed"} == {"SQLI", "ADMIN", "IDOR", "SSRF"}
    finally:
        server.shutdown()


def test_safe_verifier_confirms_direct_endpoint_evidence_without_overconfirming_login_password() -> None:
    DirectEndpointEvidenceFixture.notes = []
    DirectEndpointEvidenceFixture.uploads = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), DirectEndpointEvidenceFixture)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        facts = CodeFacts(
            routes=[
                RouteFact("route-config", "GET", "/config", "flask-like", CodeAnchor("app.py", 10, 10, "r1", "config")),
                RouteFact("route-crypto", "GET,POST", "/crypto", "flask-like", CodeAnchor("app.py", 20, 20, "r2", "crypto")),
                RouteFact("route-reset", "GET,POST", "/reset-password", "flask-like", CodeAnchor("app.py", 30, 30, "r3", "reset")),
                RouteFact("route-notes", "GET,POST", "/notes", "flask-like", CodeAnchor("app.py", 40, 40, "r4", "notes")),
                RouteFact("route-deserialize", "GET,POST", "/deserialize", "flask-like", CodeAnchor("app.py", 50, 50, "r5", "deserialize")),
                RouteFact("route-login", "GET,POST", "/login", "flask-like", CodeAnchor("app.py", 60, 60, "r6", "login")),
                RouteFact("route-admin", "GET", "/admin", "flask-like", CodeAnchor("app.py", 70, 70, "r7", "admin")),
                RouteFact("route-upload", "GET,POST", "/upload", "flask-like", CodeAnchor("app.py", 80, 80, "r8", "upload")),
            ],
            functions=[
                FunctionFact("fn-login", "login", CodeAnchor("app.py", 61, 69, "f1", "login"), []),
            ],
        )
        candidates = [
            _candidate("DIRECT-CONFIG", "auth", 10, "config", "render_template(config)", "route-config"),
            _candidate("DIRECT-CRYPTO", "auth", 20, "value", "weak crypto output", "route-crypto"),
            _candidate("DIRECT-RESET", "auth", 30, "reset form", "password update", "route-reset"),
            _candidate("DIRECT-NOTES", "xss", 40, "note body", "notes template", "route-notes"),
            _candidate("DIRECT-ADMIN", "authz", 70, "remember_user cookie", "admin authorization", "route-admin"),
            _candidate("DIRECT-UPLOAD", "injection", 80, "uploaded filename", "uploaded.save", "route-upload"),
            _candidate("DESER", "injection", 51, "request.form.get('payload')", "deserialization", "route-deserialize"),
            _candidate("LOGIN-USER", "injection", 61, "request.form.get('username')", "raw_sql", "route-login"),
            _candidate("LOGIN-PASSWORD", "injection", 62, "request.form.get('password')", "raw_sql", "route-login"),
            _candidate("LOGIN-CROSS", "injection", 61, "request.form.get('username')", "raw_sql", "route-login", sink_line=25),
        ]

        safe_results = run_safe_verification(candidates, facts, f"http://127.0.0.1:{server.server_port}")
        safe_by_id = {item.candidate_id: item for item in safe_results}

        assert {item.candidate_id for item in safe_results if item.status == "confirmed"} == {
            "DIRECT-CONFIG",
            "DIRECT-ADMIN",
        }
        for candidate_id in {"DIRECT-CRYPTO", "DIRECT-RESET", "DIRECT-NOTES", "DIRECT-UPLOAD", "DESER", "LOGIN-USER"}:
            assert safe_by_id[candidate_id].status != "confirmed"

        stateful_results = run_safe_verification(
            candidates,
            facts,
            f"http://127.0.0.1:{server.server_port}",
            allow_state_changes=True,
        )
        stateful_by_id = {item.candidate_id: item for item in stateful_results}
        assert {
            "DIRECT-CONFIG",
            "DIRECT-CRYPTO",
            "DIRECT-RESET",
            "DIRECT-NOTES",
            "DIRECT-ADMIN",
            "DIRECT-UPLOAD",
            "DESER",
            "LOGIN-USER",
        }.issubset({item.candidate_id for item in stateful_results if item.status == "confirmed"})
        assert stateful_by_id["LOGIN-PASSWORD"].status != "confirmed"
        assert stateful_by_id["LOGIN-CROSS"].status != "confirmed"
    finally:
        server.shutdown()
