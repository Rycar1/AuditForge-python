from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

MAX_SNIPPET_LINE_CHARS = 520
SNIPPET_CACHE_SIZE = 2048


@dataclass(frozen=True)
class CodeLine:
    number: int
    text: str
    highlighted: bool


@dataclass(frozen=True)
class CodeSnippet:
    file: str
    start_line: int
    end_line: int
    symbol: str | None
    lines: list[CodeLine]
    error: str | None = None


def code_window(repo_path: str | Path, anchor: Any, context: int = 2) -> CodeSnippet:
    file = anchor_value(anchor, "file") or ""
    start_line = int(anchor_value(anchor, "start_line") or 1)
    end_line = int(anchor_value(anchor, "end_line") or start_line)
    symbol = anchor_value(anchor, "symbol")
    repo = Path(repo_path).resolve()
    target = (repo / file).resolve()

    try:
        target.relative_to(repo)
    except ValueError:
        return CodeSnippet(file, start_line, end_line, symbol, [], "代码锚点不在扫描仓库内")

    if not target.exists():
        return CodeSnippet(file, start_line, end_line, symbol, [], "源码文件不存在")

    lower = max(1, start_line - context)
    upper = max(lower, end_line + context)
    try:
        stat = target.stat()
        window = read_code_window(str(target), lower, upper, stat.st_mtime_ns, stat.st_size)
    except OSError as exc:
        return CodeSnippet(file, start_line, end_line, symbol, [], f"读取源码失败：{exc}")
    rendered = [CodeLine(number=line_no, text=text, highlighted=start_line <= line_no <= end_line) for line_no, text in window]
    return CodeSnippet(file, start_line, end_line, symbol, rendered, None)


@lru_cache(maxsize=SNIPPET_CACHE_SIZE)
def read_code_window(path: str, lower: int, upper: int, mtime_ns: int, size: int) -> tuple[tuple[int, str], ...]:
    del mtime_ns, size  # cache-busting inputs; values are intentionally unused.
    rows: list[tuple[int, str]] = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, raw in enumerate(handle, start=1):
            if line_no < lower:
                continue
            if line_no > upper:
                break
            rows.append((line_no, truncate_code_line(raw.rstrip("\r\n"))))
    return tuple(rows)


def truncate_code_line(text: str) -> str:
    if len(text) <= MAX_SNIPPET_LINE_CHARS:
        return text
    head = max(0, MAX_SNIPPET_LINE_CHARS // 2 - 24)
    tail = max(0, MAX_SNIPPET_LINE_CHARS - head - 64)
    omitted = len(text) - head - tail
    return f"{text[:head]} ... [已截断 {omitted:,} 字符] ... {text[-tail:] if tail else ''}"


def anchor_value(anchor: Any, key: str) -> Any:
    if isinstance(anchor, dict):
        return anchor.get(key)
    return getattr(anchor, key, None)


def anchor_key(anchor: Any) -> tuple[str, int, int]:
    return (
        str(anchor_value(anchor, "file") or ""),
        int(anchor_value(anchor, "start_line") or 0),
        int(anchor_value(anchor, "end_line") or 0),
    )


def format_anchor(anchor: Any) -> str:
    file = anchor_value(anchor, "file") or "unknown"
    line = anchor_value(anchor, "start_line") or "?"
    return f"{file}:{line}"


def candidate_flow_nodes(candidate_payload: dict[str, Any]) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    source = candidate_payload.get("source")
    sink = candidate_payload.get("sink")
    if source:
        nodes.append({"role": "source", "title": "Source", "anchor": source, "edge": None})

    for step in candidate_payload.get("steps") or []:
        from_anchor = step.get("from_anchor") or step.get("from")
        to_anchor = step.get("to_anchor") or step.get("to")
        if from_anchor and (not nodes or anchor_key(nodes[-1]["anchor"]) != anchor_key(from_anchor)):
            nodes.append({"role": "step", "title": step_title(step), "anchor": from_anchor, "edge": step})
        if to_anchor:
            nodes.append({"role": "step", "title": step_title(step), "anchor": to_anchor, "edge": step})

    if sink and (not nodes or anchor_key(nodes[-1]["anchor"]) != anchor_key(sink)):
        nodes.append({"role": "sink", "title": "Sink", "anchor": sink, "edge": None})
    elif nodes and sink and anchor_key(nodes[-1]["anchor"]) == anchor_key(sink):
        nodes[-1]["role"] = "sink"
        nodes[-1]["title"] = "Sink"

    deduped: list[dict[str, Any]] = []
    for node in nodes:
        if deduped and anchor_key(deduped[-1]["anchor"]) == anchor_key(node["anchor"]) and deduped[-1]["role"] == node["role"]:
            continue
        deduped.append(node)
    return deduped


def step_title(step: dict[str, Any]) -> str:
    labels = {
        "assignment": "赋值传播",
        "call": "函数调用",
        "return": "返回值",
        "branch": "条件分支",
        "framework_binding": "框架绑定",
        "llm_inferred": "语义推断",
    }
    return labels.get(str(step.get("kind") or ""), str(step.get("kind") or "传播步骤"))
