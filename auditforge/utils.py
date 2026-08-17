from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def stable_id(prefix: str, *parts: object) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{prefix}:{sha256_text(raw)[:16]}"


def normalize_path(path: str | Path) -> str:
    return str(path).replace(os.sep, "/")


def dedupe_by(items: Iterable[T], key) -> list[T]:
    seen: set[object] = set()
    out: list[T] = []
    for item in items:
        marker = key(item)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


def write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False))


def atomic_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            newline="",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink(missing_ok=True)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def line_count(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + 1


def clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(upper, value))
