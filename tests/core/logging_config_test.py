from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from auditforge.logging_config import (
    MAX_LOG_QUERY_LIMIT,
    RingBufferHandler,
    configure_logging,
    contextual_logger,
    get_recent_logs,
    parse_level,
    redact,
    shutdown_logging,
)


@pytest.fixture(autouse=True)
def clean_auditforge_logging() -> None:
    shutdown_logging()
    yield
    shutdown_logging()


def test_redact_handles_nested_secrets_and_bearer_tokens() -> None:
    payload = {
        "api_key": "sk-secret",
        "nested": {"Authorization": "Bearer token-value", "safe": "visible"},
        "message": "password=hunter2 access_token=abc Bearer xyz",
    }

    result = redact(payload)

    assert result["api_key"] == "[REDACTED]"
    assert result["nested"]["Authorization"] == "[REDACTED]"
    assert result["nested"]["safe"] == "visible"
    assert "hunter2" not in result["message"]
    assert "abc" not in result["message"]
    assert "xyz" not in result["message"]


def test_json_file_logging_redacts_extras_and_supports_context(tmp_path: Path) -> None:
    log_path = tmp_path / "auditforge.jsonl"
    logger = configure_logging(level="DEBUG", log_file=log_path, json_format=True, console=False)
    contextual_logger(logger, run_id="run-123", candidate_id="cand-1").info(
        "request Authorization: Bearer top-secret",
        extra={"api_key": "sk-live", "event": "scan.started"},
    )
    for handler in logger.handlers:
        handler.flush()

    payload = json.loads(log_path.read_text(encoding="utf-8").strip())
    shutdown_logging(logger)
    assert payload["run_id"] == "run-123"
    assert payload["candidate_id"] == "cand-1"
    assert payload["event"] == "scan.started"
    assert payload["api_key"] == "[REDACTED]"
    assert "top-secret" not in payload["message"]


def test_rotating_file_logging_keeps_bounded_backups(tmp_path: Path) -> None:
    log_path = tmp_path / "auditforge.log"
    logger = configure_logging(
        level="INFO",
        log_file=log_path,
        json_format=False,
        console=False,
        max_bytes=180,
        backup_count=2,
    )
    for index in range(40):
        logger.info("rotation event %s %s", index, "x" * 40)
    for handler in logger.handlers:
        handler.flush()

    assert log_path.exists()
    assert len(list(tmp_path.glob("auditforge.log.*"))) <= 2
    shutdown_logging(logger)


def test_text_logging_redacts_exception_messages(tmp_path: Path) -> None:
    log_path = tmp_path / "auditforge.log"
    logger = configure_logging(level="ERROR", log_file=log_path, json_format=False, console=False)
    try:
        raise RuntimeError("request failed: api_key=sk-exception-secret")
    except RuntimeError:
        logger.exception("provider failed")
    shutdown_logging(logger)

    rendered = log_path.read_text(encoding="utf-8")
    assert "RuntimeError" in rendered
    assert "sk-exception-secret" not in rendered
    assert "api_key=[REDACTED]" in rendered


def test_console_omits_traceback_while_protected_file_keeps_it(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log_path = tmp_path / "auditforge.log"
    logger = configure_logging(level="ERROR", log_file=log_path, json_format=False, console=True)
    try:
        raise RuntimeError("private implementation detail")
    except RuntimeError:
        logger.exception("operation failed", extra={"diagnostic_id": "AF-TEST"})
    shutdown_logging(logger)

    console = capsys.readouterr().err
    protected = log_path.read_text(encoding="utf-8")
    assert "operation failed" in console
    assert "Traceback" not in console
    assert "private implementation detail" not in console
    assert "Traceback" in protected
    assert "private implementation detail" in protected


def test_text_logging_uses_portable_iso_timezone_offset(tmp_path: Path) -> None:
    log_path = tmp_path / "auditforge.log"
    logger = configure_logging(level="INFO", log_file=log_path, json_format=False, console=False)
    logger.info("timestamp check")
    shutdown_logging(logger)

    timestamp = log_path.read_text(encoding="utf-8").split(" ", 1)[0]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}", timestamp)


def test_environment_configuration(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "env.jsonl"
    monkeypatch.setenv("AUDITFORGE_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("AUDITFORGE_LOG_FILE", str(path))
    monkeypatch.setenv("AUDITFORGE_LOG_FORMAT", "json")

    logger = configure_logging(console=False)
    logger.info("hidden")
    logger.warning("visible")
    for handler in logger.handlers:
        handler.flush()

    assert logger.level == logging.WARNING
    assert json.loads(path.read_text(encoding="utf-8"))["message"] == "visible"
    shutdown_logging(logger)


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid log level"):
        parse_level("verbose")


def test_ring_buffer_capacity_sequence_cursor_and_copy_isolation() -> None:
    logger = configure_logging(level="DEBUG", console=False, buffer_capacity=3)
    for index in range(5):
        logger.info("event %s", index)

    recent = get_recent_logs(limit=10)
    assert [item["sequence"] for item in recent] == [3, 4, 5]
    assert [item["message"] for item in recent] == ["event 2", "event 3", "event 4"]
    assert [item["sequence"] for item in get_recent_logs(after_sequence=3, limit=10)] == [4, 5]

    recent[0]["message"] = "caller mutation"
    assert get_recent_logs(limit=10)[0]["message"] == "event 2"


def test_ring_buffer_level_filter_and_hard_query_limit() -> None:
    logger = configure_logging(level="DEBUG", console=False, buffer_capacity=MAX_LOG_QUERY_LIMIT + 20)
    logger.debug("debug")
    logger.info("info")
    logger.warning("warning")
    logger.error("error")

    assert [item["level"] for item in get_recent_logs(level="WARNING")] == ["WARNING", "ERROR"]
    assert [item["message"] for item in get_recent_logs(level=logging.WARNING, limit=1)] == ["error"]
    assert [item["message"] for item in get_recent_logs(after_sequence=0, level="WARNING", limit=1)] == ["warning"]

    for index in range(MAX_LOG_QUERY_LIMIT + 5):
        logger.info("bounded %s", index)
    assert len(get_recent_logs(limit=MAX_LOG_QUERY_LIMIT * 10)) == MAX_LOG_QUERY_LIMIT
    assert len(get_recent_logs(after_sequence=0, limit=MAX_LOG_QUERY_LIMIT * 10)) == MAX_LOG_QUERY_LIMIT

    with pytest.raises(ValueError, match="limit must be a positive integer"):
        get_recent_logs(limit=0)
    with pytest.raises(ValueError, match="after_sequence must be a non-negative integer"):
        get_recent_logs(after_sequence=-1)


def test_ring_buffer_redacts_exception_secrets_and_non_json_extras() -> None:
    class SecretValue:
        def __str__(self) -> str:
            return "password=object-secret"

    logger = configure_logging(level="ERROR", console=False)
    try:
        raise RuntimeError("request failed: api_key=exception-secret")
    except RuntimeError:
        logger.exception(
            "request Authorization: Bearer message-secret",
            extra={
                "api_key": "extra-secret",
                "details": {"access_token": "nested-secret", "value": SecretValue()},
                "sequence": 999,
            },
        )

    entry = get_recent_logs(limit=1)[0]
    rendered = json.dumps(entry, ensure_ascii=False)
    assert entry["sequence"] == 1
    assert entry["api_key"] == "[REDACTED]"
    assert entry["details"]["access_token"] == "[REDACTED]"
    assert "RuntimeError" in entry["exception"]
    for secret in ("object-secret", "exception-secret", "message-secret", "extra-secret", "nested-secret"):
        assert secret not in rendered


def test_ring_buffer_is_safe_for_basic_concurrent_logging() -> None:
    workers = 8
    per_worker = 50
    logger = configure_logging(level="INFO", console=False, buffer_capacity=workers * per_worker)

    def emit(worker: int) -> None:
        for index in range(per_worker):
            logger.info("worker %s event %s", worker, index, extra={"worker": worker})

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(emit, range(workers)))

    entries = get_recent_logs(after_sequence=0, limit=MAX_LOG_QUERY_LIMIT)
    sequences = [item["sequence"] for item in entries]
    assert len(entries) == workers * per_worker
    assert sequences == list(range(1, workers * per_worker + 1))
    assert len({item["message"] for item in entries}) == workers * per_worker


def test_reconfigure_replaces_the_ring_buffer_instead_of_duplicating_it() -> None:
    logger = configure_logging(level="INFO", console=False)
    logger.info("before reconfigure")
    logger = configure_logging(level="INFO", console=False)
    logger.info("after reconfigure")

    buffers = [handler for handler in logger.handlers if isinstance(handler, RingBufferHandler)]
    assert len(buffers) == 1
    assert [item["message"] for item in get_recent_logs()] == ["after reconfigure"]
