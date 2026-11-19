from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from auditforge.llm_candidates import LLMConfig, validate_llm_base_url
from auditforge.llm_candidates import test_llm_connection as check_connection


def test_remote_llm_requires_https_and_rejects_embedded_credentials() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        validate_llm_base_url("http://example.com/v1")
    with pytest.raises(ValueError, match="credentials"):
        validate_llm_base_url("https://user:secret@example.com/v1")
    with pytest.raises(ValueError, match="query"):
        validate_llm_base_url("https://example.com/v1?token=secret")
    assert validate_llm_base_url("http://127.0.0.1:11434/v1") == "http://127.0.0.1:11434/v1"


class RedirectingLLM(BaseHTTPRequestHandler):
    redirected_requests = 0

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/chat/completions":
            self.send_response(307)
            self.send_header("Location", "/capture")
            self.end_headers()
            return
        type(self).redirected_requests += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"choices":[{"message":{"content":"ok"}}]}')

    def log_message(self, fmt: str, *args) -> None:
        return


def test_llm_transport_does_not_follow_redirect_with_authorization() -> None:
    RedirectingLLM.redirected_requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectingLLM)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = LLMConfig(
            enabled=True,
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            api_key="secret-key",
            timeout_seconds=5,
        )
        with pytest.raises(ValueError, match="HTTP 307"):
            check_connection(config)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert RedirectingLLM.redirected_requests == 0
