from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

ADMIN_TOKEN_ENV = "AUDITFORGE_ADMIN_TOKEN"
ALLOW_REMOTE_ENV = "AUDITFORGE_ALLOW_REMOTE"
ALLOWED_HOSTS_ENV = "AUDITFORGE_ALLOWED_HOSTS"
ALLOWED_ORIGINS_ENV = "AUDITFORGE_ALLOWED_ORIGINS"
ALLOWED_REPO_ROOTS_ENV = "AUDITFORGE_ALLOWED_REPO_ROOTS"
SESSION_COOKIE = "auditforge_session"
SESSION_TTL_SECONDS = 12 * 60 * 60


_PATH_LOCKS: dict[str, threading.RLock] = {}
_PATH_LOCKS_GUARD = threading.Lock()
_HELD_LOCKS = threading.local()


def _lock_for(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.resolve()))
    with _PATH_LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.RLock())


@contextmanager
def locked_path(path: Path) -> Iterator[None]:
    path = path.resolve()
    lock = _lock_for(path)
    with lock:
        held = getattr(_HELD_LOCKS, "paths", None)
        if held is None:
            held = {}
            _HELD_LOCKS.paths = held
        key = os.path.normcase(str(path))
        depth = held.get(key, 0)
        held[key] = depth + 1
        try:
            if depth:
                yield
            else:
                with _interprocess_lock(path):
                    yield
        finally:
            if depth:
                held[key] = depth
            else:
                held.pop(key, None)


@contextmanager
def _interprocess_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            deadline = time.monotonic() + 10
            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out acquiring file lock for {path}") from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def atomic_write_json(path: Path, payload: Any, *, mode: int = 0o600) -> None:
    """Atomically replace a JSON file while serializing writers for that path."""

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with locked_path(path):
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            try:
                os.chmod(temporary, mode)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            # Windows can transiently reject a replacement while antivirus,
            # indexing, or another process has just observed the destination.
            # The surrounding per-path lock still serializes AuditForge writers;
            # retrying the platform-level rename keeps that harmless race from
            # turning a scan progress update into a failed task.
            deadline = time.monotonic() + 1.0
            while True:
                try:
                    os.replace(temporary, path)
                    break
                except PermissionError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
            try:
                os.chmod(path, mode)
            except OSError:
                pass
        finally:
            temporary.unlink(missing_ok=True)


def is_loopback_host(host: str) -> bool:
    value = str(host or "").strip().strip("[]").lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _split_csv_env(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, "").split(",") if item.strip())


def configured_repo_roots(workspace: Path) -> tuple[Path, ...]:
    raw = os.getenv(ALLOWED_REPO_ROOTS_ENV, "")
    roots: list[Path] = []
    for value in raw.split(os.pathsep):
        value = value.strip()
        if not value:
            continue
        if is_unc_or_device_path(value):
            raise ValueError(f"{ALLOWED_REPO_ROOTS_ENV} cannot contain UNC or device paths")
        root = Path(value).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"configured repository root does not exist or is not a directory: {root}")
        roots.append(root)
    return tuple(dict.fromkeys(roots))


@dataclass(frozen=True)
class WebSecurityConfig:
    bind_host: str
    admin_token: str
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    allowed_repo_roots: tuple[Path, ...]
    max_request_concurrency: int = 32
    max_scan_concurrency: int = 1
    socket_timeout_seconds: float = 15.0

    @classmethod
    def from_environment(cls, workspace: Path, host: str) -> WebSecurityConfig:
        loopback = is_loopback_host(host)
        configured_token = os.getenv(ADMIN_TOKEN_ENV, "").strip()
        allowed_hosts = tuple(_normalize_allowed_host(item) for item in _split_csv_env(ALLOWED_HOSTS_ENV))
        allowed_origins = tuple(normalize_origin(item) for item in _split_csv_env(ALLOWED_ORIGINS_ENV))

        if not loopback:
            if os.getenv(ALLOW_REMOTE_ENV, "").strip().lower() not in {"1", "true", "yes", "on"}:
                raise ValueError(
                    f"refusing non-loopback bind; set {ALLOW_REMOTE_ENV}=1 and configure an admin token, allowed hosts and origins"
                )
            if len(configured_token) < 32:
                raise ValueError(f"{ADMIN_TOKEN_ENV} must contain at least 32 characters for a non-loopback bind")
            if not allowed_hosts:
                raise ValueError(f"{ALLOWED_HOSTS_ENV} is required for a non-loopback bind")
            if not allowed_origins:
                raise ValueError(f"{ALLOWED_ORIGINS_ENV} is required for a non-loopback bind")
        else:
            defaults = ("localhost", "127.0.0.1", "::1", host.strip("[]").lower())
            allowed_hosts = tuple(dict.fromkeys((*allowed_hosts, *defaults)))

        return cls(
            bind_host=host,
            admin_token=configured_token or secrets.token_urlsafe(32),
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            allowed_repo_roots=configured_repo_roots(workspace),
            max_request_concurrency=_bounded_env_int("AUDITFORGE_MAX_REQUESTS", 32, 1, 128),
            max_scan_concurrency=_bounded_env_int("AUDITFORGE_MAX_SCANS", 1, 1, 8),
            socket_timeout_seconds=float(_bounded_env_int("AUDITFORGE_SOCKET_TIMEOUT", 15, 3, 120)),
        )


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class AuthContext:
    kind: str
    csrf_token: str | None = None


class SessionStore:
    def __init__(self, admin_token: str, *, ttl_seconds: int = SESSION_TTL_SECONDS, max_sessions: int = 64) -> None:
        self._admin_token = admin_token
        self._ttl_seconds = ttl_seconds
        self._max_sessions = max_sessions
        self._sessions: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def valid_admin_token(self, candidate: str | None) -> bool:
        return bool(candidate) and hmac.compare_digest(str(candidate), self._admin_token)

    def create(self) -> tuple[str, str]:
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._purge(now)
            if len(self._sessions) >= self._max_sessions:
                oldest = min(self._sessions, key=lambda key: self._sessions[key][1])
                self._sessions.pop(oldest, None)
            self._sessions[session_id] = (csrf_token, now + self._ttl_seconds)
        return session_id, csrf_token

    def authenticate(self, headers: Mapping[str, str]) -> AuthContext | None:
        authorization = str(headers.get("Authorization") or "")
        if authorization.startswith("Bearer ") and self.valid_admin_token(authorization[7:].strip()):
            return AuthContext("bearer")
        cookies = parse_cookie_header(str(headers.get("Cookie") or ""))
        session_id = cookies.get(SESSION_COOKIE)
        if not session_id:
            return None
        now = time.time()
        with self._lock:
            self._purge(now)
            session = self._sessions.get(session_id)
            if not session:
                return None
            csrf_token, _ = session
            self._sessions[session_id] = (csrf_token, now + self._ttl_seconds)
        return AuthContext("session", csrf_token)

    def _purge(self, now: float) -> None:
        for session_id, (_, expires_at) in list(self._sessions.items()):
            if expires_at <= now:
                self._sessions.pop(session_id, None)


def parse_cookie_header(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in value.split(";"):
        if "=" not in item:
            continue
        name, raw = item.split("=", 1)
        cookies[name.strip()] = raw.strip()
    return cookies


def parse_host_header(value: str) -> str | None:
    raw = str(value or "").strip()
    if not raw or any(character in raw for character in "\r\n/\\"):
        return None
    try:
        parsed = urlsplit(f"//{raw}")
        return parsed.hostname.lower() if parsed.hostname else None
    except ValueError:
        return None


def _normalize_allowed_host(value: str) -> str:
    normalized = parse_host_header(value)
    if normalized:
        return normalized
    raw = str(value or "").strip().strip("[]").lower()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ValueError(f"invalid allowed host: {value}") from exc


def host_is_allowed(host_header: str, config: WebSecurityConfig) -> bool:
    hostname = parse_host_header(host_header)
    if not hostname:
        return False
    return any(hmac.compare_digest(hostname, allowed.strip("[]").lower()) for allowed in config.allowed_hosts)


def normalize_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"invalid web origin: {value}")
    hostname = parsed.hostname.lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        host += f":{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), host, "", "", ""))


def origin_is_allowed(origin: str | None, host_header: str, config: WebSecurityConfig) -> bool:
    if not origin:
        return True
    try:
        normalized = normalize_origin(origin)
    except (ValueError, TypeError):
        return False
    if normalized in config.allowed_origins:
        return True
    if not is_loopback_host(config.bind_host):
        return False
    parsed = urlsplit(normalized)
    return parsed.hostname == parse_host_header(host_header) and is_loopback_host(parsed.hostname or "")


def csrf_is_valid(context: AuthContext, supplied_token: str | None) -> bool:
    if context.kind == "bearer":
        return True
    return bool(context.csrf_token and supplied_token) and hmac.compare_digest(context.csrf_token, str(supplied_token))


def session_cookie(session_id: str, *, secure: bool = False) -> str:
    suffix = "; Secure" if secure else ""
    return f"{SESSION_COOKIE}={session_id}; Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Strict{suffix}"


def csrf_bootstrap_script(csrf_token: str | None) -> str:
    if not csrf_token:
        return ""
    encoded = json.dumps(csrf_token)
    return f"""<meta name=\"auditforge-csrf-token\" content={json.dumps(csrf_token)}>
<script>
(() => {{
  const csrfToken = {encoded};
  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, init = {{}}) => {{
    const url = new URL(typeof input === 'string' ? input : input.url, window.location.href);
    const method = String(init.method || (typeof input !== 'string' && input.method) || 'GET').toUpperCase();
    if (url.origin === window.location.origin && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {{
      const headers = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined));
      headers.set('X-AuditForge-CSRF', csrfToken);
      init = {{...init, headers}};
    }}
    return originalFetch(input, init);
  }};
}})();
</script>"""


def redact_url(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    fallback = raw.split("?", 1)[0].split("#", 1)[0]
    if "@" in fallback:
        fallback = fallback.rsplit("@", 1)[-1]
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return fallback
    if not parsed.scheme or not parsed.hostname:
        return fallback
    hostname = parsed.hostname
    host = f"[{hostname}]" if ":" in hostname else hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        host += f":{port}"
    return urlunsplit((parsed.scheme, host, parsed.path.rstrip("/"), "", ""))


def is_unc_or_device_path(value: str) -> bool:
    raw = str(value or "").strip().replace("/", "\\")
    lowered = raw.lower()
    return raw.startswith("\\\\") or lowered.startswith(("\\??\\", "\\\\?\\", "\\\\.\\"))


def validate_repo_path(value: str, roots: tuple[Path, ...]) -> Path:
    if is_unc_or_device_path(value):
        raise ValueError("UNC and Windows device paths are not allowed")
    if not roots:
        raise ValueError(f"local repository paths are disabled; configure one or more roots in {ALLOWED_REPO_ROOTS_ENV}")
    candidate = Path(value).expanduser().resolve()
    if not candidate.exists() or not candidate.is_dir():
        raise ValueError(f"repository path does not exist or is not a directory: {candidate}")
    for root in roots:
        try:
            candidate.relative_to(root.resolve())
            return candidate
        except ValueError:
            continue
    raise ValueError("repository path is outside the configured allowed roots")
