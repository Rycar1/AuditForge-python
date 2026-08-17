from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from benchmarks.dvwa_dynamic_smoke import (
    COMMAND_MARKER,
    DOM_XSS_MARKER,
    FILE_READ_PAYLOAD,
    REFLECTED_XSS_PAYLOAD,
    SQLI_PAYLOAD,
    STORED_XSS_PAYLOAD,
    DvwaSmokeHarness,
    HttpExchange,
    HttpResult,
    extract_user_token,
    redact_exchange,
    validate_loopback_base_url,
)


def _exchange(method: str, url: str, body: str, response_body: str) -> HttpExchange:
    return HttpExchange(
        request_method=method,
        request_url=url,
        request_headers=[("Host", "127.0.0.1:4280"), ("Cookie", "PHPSESSID=secret-session")],
        request_body=body,
        response_status=200,
        response_reason="OK",
        response_headers=[("Content-Type", "text/html"), ("Set-Cookie", "PHPSESSID=new-secret; HttpOnly")],
        response_body=response_body,
    )


def _result(method: str, path: str, body: str, response_body: str) -> HttpResult:
    url = f"http://127.0.0.1:4280/{path.lstrip('/')}"
    exchange = _exchange(method, url, body, response_body)
    return HttpResult(200, "OK", url, exchange.response_headers, response_body, [exchange])


class FakeDvwaClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str] | None]] = []
        self.stored_message = ""

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        del headers
        self.calls.append((method, path, data))
        request_body = "&".join(f"{key}={value}" for key, value in (data or {}).items())
        response_body = ""
        result_path = path
        if path == "setup.php" and method == "GET":
            response_body = '<input name="user_token" value="setup-secret">'
        elif path == "setup.php":
            response_body = '<input name="user_token" value="post-setup-secret">'
        elif path == "login.php" and method == "GET":
            response_body = '<input value="login-secret" name="user_token">'
        elif path == "login.php":
            response_body = "Welcome to Damn Vulnerable Web Application"
            result_path = "index.php"
        elif path == "security.php" and method == "GET":
            response_body = '<input name="user_token" value="security-secret">'
        elif path == "security.php":
            response_body = "Security level is currently: <em>low</em>"
        elif path.startswith("vulnerabilities/sqli/"):
            query = parse_qs(urlsplit(path).query)
            count = 2 if query.get("id") == [SQLI_PAYLOAD] else 1
            response_body = "".join("First name: Test<br>" for _ in range(count))
        elif path == "vulnerabilities/exec/":
            response_body = COMMAND_MARKER
        elif path.startswith("vulnerabilities/xss_r/"):
            response_body = REFLECTED_XSS_PAYLOAD
        elif path == "vulnerabilities/xss_s/" and method == "POST":
            self.stored_message = (data or {}).get("mtxMessage", "")
            response_body = self.stored_message
        elif path == "vulnerabilities/xss_s/":
            response_body = self.stored_message
        elif path.startswith("vulnerabilities/xss_d/"):
            response_body = "document.location.href; document.write('x'); decodeURI(lang)"
        elif path.startswith("vulnerabilities/fi/"):
            assert parse_qs(urlsplit(path).query)["page"] == [FILE_READ_PAYLOAD]
            response_body = "User-agent: *\nDisallow: /"
        else:
            raise AssertionError(f"unexpected request: {method} {path}")
        return _result(method, result_path, request_body, response_body)


@pytest.mark.parametrize(
    "url,canonical",
    [
        ("http://127.0.0.1:4280/", "http://127.0.0.1:4280"),
        ("http://localhost:4280/dvwa/", "http://localhost:4280/dvwa"),
        ("http://[::1]:4280", "http://[::1]:4280"),
    ],
)
def test_validate_loopback_base_url_accepts_only_local_forms(url: str, canonical: str) -> None:
    assert validate_loopback_base_url(url) == canonical


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.10:4280",
        "https://dvwa.example.test",
        "http://admin:password@127.0.0.1:4280",
        "ftp://127.0.0.1/dvwa",
        "http://127.0.0.1:4280/?next=external",
    ],
)
def test_validate_loopback_base_url_rejects_non_loopback_or_ambiguous_urls(url: str) -> None:
    with pytest.raises(ValueError):
        validate_loopback_base_url(url)


def test_extract_user_token_supports_attribute_order_and_html_escaping() -> None:
    assert extract_user_token('<input value="a&amp;b" type="hidden" name="user_token">') == "a&b"


def test_redact_exchange_removes_cookies_passwords_and_tokens_from_all_evidence() -> None:
    exchange = _exchange(
        "POST",
        "http://127.0.0.1:4280/login.php?user_token=query-secret",
        "username=admin&password=credential-secret&user_token=body-secret",
        '<input name="user_token" value="response-secret">',
    )
    evidence = redact_exchange(exchange)
    serialized = str(evidence)
    for secret in ("secret-session", "new-secret", "credential-secret", "query-secret", "body-secret", "response-secret"):
        assert secret not in serialized
    assert serialized.count("[REDACTED]") >= 6
    assert "POST /login.php?user_token=[REDACTED] HTTP/1.1" in evidence["request"]["packet"]
    assert "HTTP/1.1 200 OK" in evidence["response"]["packet"]


def test_harness_runs_setup_and_all_six_point_to_proof_checks() -> None:
    client = FakeDvwaClient()
    report = DvwaSmokeHarness(client, "http://127.0.0.1:4280").run()

    assert report["summary"] == {"passed": 6, "total": 6, "all_passed": True}
    assert {item["name"] for item in report["checks"]} == {
        "sqli",
        "command_injection",
        "reflected_xss",
        "stored_xss",
        "dom_xss",
        "file_inclusion",
    }
    assert client.stored_message == STORED_XSS_PAYLOAD
    assert any(data and data.get("ip", "").endswith(f"echo {COMMAND_MARKER}") for _, _, data in client.calls)
    assert DOM_XSS_MARKER in next(path for _, path, _ in client.calls if "xss_d" in path)


def test_harness_can_skip_database_reset() -> None:
    client = FakeDvwaClient()
    report = DvwaSmokeHarness(client, "http://127.0.0.1:4280", reset_database=False).run()

    assert report["summary"]["all_passed"] is True
    assert all(path != "setup.php" for _, path, _ in client.calls)
    assert report["safety"]["database_reset"] is False
