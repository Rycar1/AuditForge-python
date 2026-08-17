from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .web_security import atomic_write_json, locked_path, redact_url

SECRETS_FILE = ".auditforge_secrets.json"


def secrets_path(workspace: Path) -> Path:
    return workspace.resolve() / SECRETS_FILE


def endpoint_fingerprint(base_url: str | None) -> str:
    normalized = redact_url(base_url).lower().rstrip("/")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def save_llm_api_key(workspace: Path, api_key: str, base_url: str | None) -> None:
    key = str(api_key or "").strip()
    if not key:
        clear_llm_api_key(workspace)
        return
    fingerprint = endpoint_fingerprint(base_url)
    secret_payload = json.dumps(
        {"api_key": key, "endpoint_sha256": fingerprint},
        separators=(",", ":"),
    ).encode("utf-8")
    protected, scheme = _protect(secret_payload)
    payload = {
        "version": 2,
        "llm_api_key": {
            "scheme": scheme,
            "endpoint_sha256": fingerprint,
            "value": base64.b64encode(protected).decode("ascii"),
        },
    }
    atomic_write_json(secrets_path(workspace), payload, mode=0o600)


def load_llm_api_key(workspace: Path, base_url: str | None) -> str | None:
    path = secrets_path(workspace)
    if not path.exists():
        return None
    with locked_path(path):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            record = payload.get("llm_api_key") if isinstance(payload, dict) else None
            if not isinstance(record, dict):
                return None
            if record.get("endpoint_sha256") != endpoint_fingerprint(base_url):
                return None
            raw = base64.b64decode(str(record.get("value") or ""), validate=True)
            cleartext = _unprotect(raw, str(record.get("scheme") or "")).decode("utf-8")
            if int(payload.get("version") or 1) >= 2:
                secret_payload = json.loads(cleartext)
                if not isinstance(secret_payload, dict):
                    return None
                if secret_payload.get("endpoint_sha256") != endpoint_fingerprint(base_url):
                    return None
                value = secret_payload.get("api_key")
                return str(value) if value else None
            return cleartext
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            return None


def clear_llm_api_key(workspace: Path) -> None:
    path = secrets_path(workspace)
    with locked_path(path):
        path.unlink(missing_ok=True)


def _protect(value: bytes) -> tuple[bytes, str]:
    if os.name == "nt":
        return _crypt_protect(value), "windows-dpapi-v1"
    # Portable fallback: the secret is isolated from the normal settings document and
    # protected by owner-only permissions. DPAPI is used automatically on Windows.
    return value, "restricted-file-v1"


def _unprotect(value: bytes, scheme: str) -> bytes:
    if scheme == "windows-dpapi-v1":
        if os.name != "nt":
            raise ValueError("Windows DPAPI secret cannot be decrypted on this platform")
        return _crypt_unprotect(value)
    if scheme == "restricted-file-v1":
        return value
    raise ValueError("unsupported secret storage scheme")


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(value: bytes) -> tuple[_DATA_BLOB, Any]:
    buffer = ctypes.create_string_buffer(value)
    blob = _DATA_BLOB(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    return blob, buffer


def _crypt_protect(value: bytes) -> bytes:
    source, source_buffer = _blob(value)
    destination = _DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    if not crypt32.CryptProtectData(
        ctypes.byref(source),
        "AuditForge LLM API key",
        None,
        None,
        None,
        0x1,
        ctypes.byref(destination),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(destination.pbData, wintypes.HLOCAL))
        del source_buffer


def _crypt_unprotect(value: bytes) -> bytes:
    source, source_buffer = _blob(value)
    destination = _DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        0x1,
        ctypes.byref(destination),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(destination.pbData, wintypes.HLOCAL))
        del source_buffer
