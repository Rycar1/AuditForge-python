from __future__ import annotations

import json
import logging
import os
import re
import threading
from collections import deque
from collections.abc import Mapping
from copy import copy, deepcopy
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

LOGGER_NAME = "auditforge"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 3
DEFAULT_LOG_BUFFER_CAPACITY = 2000
MAX_LOG_BUFFER_CAPACITY = 10000
DEFAULT_LOG_QUERY_LIMIT = 100
MAX_LOG_QUERY_LIMIT = 500

_STANDARD_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)
_CONFIGURATION_LOCK = threading.RLock()
_OWNED_HANDLER_ATTRIBUTE = "_auditforge_owned_handler"
_SENSITIVE_KEY = re.compile(
    r"(?:api[-_]?key|authorization|password|passwd|secret|access[-_]?token|refresh[-_]?token|id[-_]?token|cookie|session)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)(\bBearer\s+)[^\s,;\]\[{}]+")
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:api[-_]?key|authorization|password|passwd|secret|access[-_]?token|refresh[-_]?token|id[-_]?token|cookie|session)\b\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}&]+)"
)
_URL_USERINFO = re.compile(r"(?i)(https?://)[^/@\s]+@")


def redact(value: Any) -> Any:
    """Return a logging-safe copy of *value* without changing caller-owned objects."""

    if isinstance(value, Mapping):
        return {str(key): "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, set):
        return sorted((redact(item) for item in value), key=str)
    if isinstance(value, str):
        text = _BEARER.sub(r"\1[REDACTED]", value)
        text = _KEY_VALUE.sub(r"\1[REDACTED]", text)
        return _URL_USERINFO.sub(r"\1[REDACTED]@", text)
    return value


def _json_safe_redacted(value: Any) -> Any:
    """Return a redacted value containing JSON-compatible primitives only."""

    safe = redact(value)
    if safe is None or isinstance(safe, (bool, int, float, str)):
        return safe
    if isinstance(safe, Mapping):
        return {str(key): _json_safe_redacted(item) for key, item in safe.items()}
    if isinstance(safe, (tuple, list, set)):
        return [_json_safe_redacted(item) for item in safe]
    return redact(str(safe))


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.msg)
        if record.args:
            record.args = redact(record.args)
        for key, value in list(record.__dict__.items()):
            if key in _STANDARD_RECORD_FIELDS:
                continue
            record.__dict__[key] = "[REDACTED]" if _SENSITIVE_KEY.search(key) else redact(value)
        return True


class PlatformTimeFormatter(logging.Formatter):
    """Render timestamps without relying on platform ``strftime`` timezone support."""

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:  # noqa: N802 - stdlib hook name
        del datefmt
        return datetime.fromtimestamp(record.created, tz=UTC).astimezone().isoformat(timespec="seconds")


class JsonFormatter(PlatformTimeFormatter):
    def payload(self, record: logging.LogRecord) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": _json_safe_redacted(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_FIELDS or key.startswith("_") or key in payload:
                continue
            payload[key] = "[REDACTED]" if _SENSITIVE_KEY.search(key) else _json_safe_redacted(value)
        if record.exc_info:
            payload["exception"] = _json_safe_redacted(self.formatException(record.exc_info))
        if record.stack_info:
            payload["stack"] = _json_safe_redacted(record.stack_info)
        return payload

    def format(self, record: logging.LogRecord) -> str:
        payload = self.payload(record)
        return json.dumps(payload, ensure_ascii=False, default=str)


class RingBufferHandler(logging.Handler):
    """Store a bounded, redacted stream of structured log records in memory."""

    def __init__(self, capacity: int = DEFAULT_LOG_BUFFER_CAPACITY) -> None:
        super().__init__()
        self.capacity = _bounded_positive_int(capacity, name="buffer capacity", maximum=MAX_LOG_BUFFER_CAPACITY)
        self._entries: deque[tuple[int, int, dict[str, Any]]] = deque(maxlen=self.capacity)
        self._sequence = 0
        self._buffer_lock = threading.RLock()
        self._payload_formatter = JsonFormatter()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            payload = self._payload_formatter.payload(record)
            with self._buffer_lock:
                self._sequence += 1
                sequence = self._sequence
                payload = {**payload, "sequence": sequence}
                self._entries.append((sequence, record.levelno, payload))
        except Exception:  # noqa: BLE001 - logging handlers must never break the caller
            self.handleError(record)

    def recent(
        self,
        *,
        after_sequence: int | None = None,
        limit: int = DEFAULT_LOG_QUERY_LIMIT,
        level: str | int | None = None,
    ) -> list[dict[str, Any]]:
        """Return logs in chronological order.

        With no cursor, the newest ``limit`` matching records are returned. With
        ``after_sequence``, the oldest retained records after that cursor are
        returned so callers can poll without skipping entries.
        """

        bounded_limit = _bounded_positive_int(limit, name="limit", maximum=MAX_LOG_QUERY_LIMIT)
        cursor = _optional_non_negative_int(after_sequence, name="after_sequence")
        minimum_level = _optional_level(level)
        with self._buffer_lock:
            matches = [
                payload
                for sequence, level_number, payload in self._entries
                if (cursor is None or sequence > cursor) and (minimum_level is None or level_number >= minimum_level)
            ]
            selected = matches[-bounded_limit:] if cursor is None else matches[:bounded_limit]
            return deepcopy(selected)


class RedactingTextFormatter(PlatformTimeFormatter):
    """Redact the fully rendered line, including exception tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return str(redact(super().format(record)))


class SafeConsoleFormatter(logging.Formatter):
    """Keep tracebacks in protected sinks without printing them to the terminal."""

    def __init__(self, delegate: logging.Formatter) -> None:
        super().__init__()
        self.delegate = delegate

    def format(self, record: logging.LogRecord) -> str:
        public_record = copy(record)
        public_record.exc_info = None
        public_record.exc_text = None
        public_record.stack_info = None
        return self.delegate.format(public_record)


class ContextLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg: Any, kwargs: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        call_extra = kwargs.get("extra") or {}
        kwargs["extra"] = {**self.extra, **call_extra}
        return msg, kwargs


def parse_level(value: str | int | None) -> int:
    if isinstance(value, int):
        return value
    normalized = str(value or DEFAULT_LOG_LEVEL).strip().upper()
    level = logging.getLevelNamesMapping().get(normalized)
    if not isinstance(level, int):
        choices = ", ".join(("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"))
        raise ValueError(f"invalid log level {value!r}; choose one of {choices}")
    return level


def _bounded_positive_int(value: int, *, name: str, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if parsed < 1:
        raise ValueError(f"{name} must be a positive integer")
    return min(parsed, maximum)


def _optional_non_negative_int(value: int | None, *, name: str) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return parsed


def _optional_level(value: str | int | None) -> int | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return parse_level(value)


def configure_logging(
    *,
    level: str | int | None = None,
    log_file: str | Path | None = None,
    json_format: bool | None = None,
    console: bool = True,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
    buffer_capacity: int = DEFAULT_LOG_BUFFER_CAPACITY,
) -> logging.Logger:
    """Configure the isolated ``auditforge`` logger and return it.

    Repeated calls replace only AuditForge-owned handlers, so embedding
    applications keep control of their root logging configuration.
    """

    env_level = os.getenv("AUDITFORGE_LOG_LEVEL")
    env_file = os.getenv("AUDITFORGE_LOG_FILE")
    env_format = os.getenv("AUDITFORGE_LOG_FORMAT", "").strip().lower()
    resolved_level = parse_level(level or env_level)
    resolved_file = str(log_file or env_file or "").strip()
    use_json = json_format if json_format is not None else env_format == "json"

    with _CONFIGURATION_LOCK:
        logger = logging.getLogger(LOGGER_NAME)
        logger.setLevel(resolved_level)
        logger.propagate = False
        shutdown_logging(logger)

        redactor = RedactingFilter()
        formatter: logging.Formatter
        if use_json:
            formatter = JsonFormatter()
        else:
            formatter = RedactingTextFormatter(
                fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )

        def attach(handler: logging.Handler, *, handler_formatter: logging.Formatter | None = None) -> None:
            handler.setLevel(resolved_level)
            handler.addFilter(redactor)
            handler.setFormatter(handler_formatter or formatter)
            setattr(handler, _OWNED_HANDLER_ATTRIBUTE, True)
            logger.addHandler(handler)

        # Attach the memory handler first so every configured output receives a
        # record that has already passed through the redacting filter.
        attach(RingBufferHandler(buffer_capacity))
        if console:
            attach(logging.StreamHandler(), handler_formatter=SafeConsoleFormatter(formatter))
        if resolved_file:
            path = Path(resolved_file).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            attach(
                RotatingFileHandler(
                    path,
                    maxBytes=max(1, int(max_bytes)),
                    backupCount=max(0, int(backup_count)),
                    encoding="utf-8",
                )
            )
        return logger


def shutdown_logging(logger: logging.Logger | None = None) -> None:
    with _CONFIGURATION_LOCK:
        target = logger or logging.getLogger(LOGGER_NAME)
        for handler in list(target.handlers):
            if not getattr(handler, _OWNED_HANDLER_ATTRIBUTE, False):
                continue
            handler.flush()
            handler.close()
            target.removeHandler(handler)


def get_recent_logs(
    *,
    after_sequence: int | None = None,
    limit: int = DEFAULT_LOG_QUERY_LIMIT,
    level: str | int | None = None,
) -> list[dict[str, Any]]:
    """Query the configured in-memory AuditForge log buffer.

    ``limit`` is clamped to ``MAX_LOG_QUERY_LIMIT``. An unconfigured or shut
    down logger returns an empty list.
    """

    with _CONFIGURATION_LOCK:
        logger = logging.getLogger(LOGGER_NAME)
        handler = next((item for item in logger.handlers if isinstance(item, RingBufferHandler)), None)
        if handler is None:
            return []
        return handler.recent(after_sequence=after_sequence, limit=limit, level=level)


def get_logger(name: str | None = None) -> logging.Logger:
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(LOGGER_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def contextual_logger(logger: logging.Logger, **context: Any) -> logging.LoggerAdapter:
    safe_context = {key: redact(value) for key, value in context.items() if value is not None}
    return ContextLoggerAdapter(logger, safe_context)
