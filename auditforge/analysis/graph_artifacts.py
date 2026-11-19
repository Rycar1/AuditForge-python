"""Compressed, pageable persistence for large evidence graphs.

The scan engine needs the complete graph in memory for candidate generation,
but the Dashboard does not.  Persisting the same graph as one ordinary JSON
file and again inside SQLite makes large runs expensive to finish, copy and
open.  This module writes one compressed evidence bundle that can be read a
page at a time or as a source-file slice.
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

from ..core.models import CodeFacts, CodeGraph
from ..core.utils import atomic_write_text, sha256_text

GRAPH_INDEX_FILE = "code_graph.json"
GRAPH_DIRECTORY = "code_graph"
GRAPH_MANIFEST_FILE = "manifest.json"
GRAPH_SCHEMA_VERSION = 2
NODE_CHUNK_SIZE = 12000
EDGE_CHUNK_SIZE = 24000
MAX_GRAPH_PAGE_SIZE = 1000


def write_graph_artifacts(workspace: Path, facts: CodeFacts, graph: CodeGraph) -> dict[str, Any]:
    """Write a transactional compressed graph bundle and a lightweight index."""

    workspace.mkdir(parents=True, exist_ok=True)
    target = workspace / GRAPH_DIRECTORY
    staging = Path(tempfile.mkdtemp(prefix=f".{GRAPH_DIRECTORY}.", dir=workspace))
    try:
        _write_gzip_json(staging / "facts.json.gz", facts.to_dict())
        nodes = [node.to_dict() for node in graph.nodes]
        edges = [edge.to_dict() for edge in graph.edges]
        node_files = {node["id"]: _node_file(node) for node in nodes}
        manifest = {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "compression": "gzip",
            "facts": {"file": "facts.json.gz"},
            "graph": {
                "nodes": _write_chunks(staging, "nodes", nodes, NODE_CHUNK_SIZE),
                "edges": _write_chunks(staging, "edges", edges, EDGE_CHUNK_SIZE),
            },
            "files": _write_file_slices(staging, nodes, edges, node_files),
        }
        _write_json(staging / GRAPH_MANIFEST_FILE, manifest)
        _replace_directory(staging, target)
        staging = None  # ownership moved to target
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)

    index = {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "storage": GRAPH_DIRECTORY,
        "manifest": f"{GRAPH_DIRECTORY}/{GRAPH_MANIFEST_FILE}",
        "compression": "gzip",
        "facts": {"file": f"{GRAPH_DIRECTORY}/facts.json.gz"},
        "graph": {
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "nodes_endpoint": "graph?kind=nodes",
            "edges_endpoint": "graph?kind=edges",
            "files_endpoint": "graph?kind=files",
        },
    }
    atomic_write_text(workspace / GRAPH_INDEX_FILE, json.dumps(index, ensure_ascii=False, indent=2))
    return index


def graph_summary(workspace: Path) -> dict[str, Any]:
    """Return the lightweight graph index without loading graph payloads."""

    index_path = workspace / GRAPH_INDEX_FILE
    try:
        data = json.loads(index_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    graph = data.get("graph") if isinstance(data.get("graph"), dict) else {}
    if data.get("schema_version") == GRAPH_SCHEMA_VERSION and data.get("storage") == GRAPH_DIRECTORY:
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "storage": GRAPH_DIRECTORY,
            "compression": "gzip",
            "node_count": _int_value(graph.get("node_count")),
            "edge_count": _int_value(graph.get("edge_count")),
            "files_endpoint": graph.get("files_endpoint"),
            "nodes_endpoint": graph.get("nodes_endpoint"),
            "edges_endpoint": graph.get("edges_endpoint"),
        }
    return {"schema_version": 1, "storage": "legacy_json"}


def read_graph_facts(workspace: Path) -> dict[str, Any]:
    """Read complete code facts from compressed storage or a legacy graph file."""

    manifest = _read_manifest(workspace)
    if manifest is not None:
        facts = manifest.get("facts") if isinstance(manifest.get("facts"), dict) else {}
        payload = _read_gzip_json(_safe_graph_path(workspace, str(facts.get("file") or "")))
        return payload if isinstance(payload, dict) else {}
    try:
        data = json.loads((workspace / GRAPH_INDEX_FILE).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    facts = data.get("facts") if isinstance(data, dict) else {}
    return facts if isinstance(facts, dict) else {}


def read_graph_page(
    workspace: Path,
    *,
    kind: str,
    offset: int = 0,
    limit: int = 200,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Read a bounded graph page, optionally scoped to one source file."""

    normalized_kind = str(kind or "nodes").lower()
    if normalized_kind not in {"nodes", "edges", "files"}:
        raise ValueError("graph kind must be nodes, edges, or files")
    normalized_offset = max(0, int(offset))
    normalized_limit = max(1, min(int(limit), MAX_GRAPH_PAGE_SIZE))
    manifest = _read_manifest(workspace)
    if manifest is None:
        return _read_legacy_graph_page(
            workspace,
            kind=normalized_kind,
            offset=normalized_offset,
            limit=normalized_limit,
            file_path=file_path,
        )
    if normalized_kind == "files":
        return _page(
            manifest.get("files") if isinstance(manifest.get("files"), list) else [], normalized_offset, normalized_limit, kind="files"
        )
    if file_path:
        entry = next((item for item in manifest.get("files", []) if isinstance(item, dict) and item.get("path") == file_path), None)
        if entry is None:
            return _page([], normalized_offset, normalized_limit, kind=normalized_kind, file_path=file_path)
        slice_data = _read_gzip_json(_safe_graph_path(workspace, str(entry.get("file") or "")))
        items = slice_data.get(normalized_kind) if isinstance(slice_data, dict) else []
        return _page(
            items if isinstance(items, list) else [], normalized_offset, normalized_limit, kind=normalized_kind, file_path=file_path
        )
    graph = manifest.get("graph") if isinstance(manifest.get("graph"), dict) else {}
    section = graph.get(normalized_kind) if isinstance(graph.get(normalized_kind), dict) else {}
    return _page_from_chunks(workspace, section, normalized_offset, normalized_limit, normalized_kind)


def _write_chunks(directory: Path, name: str, values: list[dict[str, Any]], chunk_size: int) -> dict[str, Any]:
    chunks: list[dict[str, Any]] = []
    for offset in range(0, len(values), chunk_size):
        sequence = offset // chunk_size
        filename = f"{name}-{sequence:05d}.json.gz"
        batch = values[offset : offset + chunk_size]
        _write_gzip_json(directory / filename, batch)
        chunks.append({"file": filename, "offset": offset, "count": len(batch)})
    return {"count": len(values), "chunks": chunks}


def _write_file_slices(
    directory: Path,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    node_files: dict[str, str | None],
) -> list[dict[str, Any]]:
    grouped_nodes: dict[str, list[dict[str, Any]]] = {}
    grouped_edges: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        file_path = node_files.get(str(node.get("id") or ""))
        if file_path:
            grouped_nodes.setdefault(file_path, []).append(node)
    for edge in edges:
        source = node_files.get(str(edge.get("from") or ""))
        target = node_files.get(str(edge.get("to") or ""))
        for file_path in {source, target} - {None}:
            grouped_edges.setdefault(str(file_path), []).append(edge)

    slices_dir = directory / "files"
    slices_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for file_path in sorted(set(grouped_nodes) | set(grouped_edges)):
        filename = f"files/{sha256_text(file_path)[:20]}.json.gz"
        file_nodes = grouped_nodes.get(file_path, [])
        file_edges = grouped_edges.get(file_path, [])
        _write_gzip_json(directory / filename, {"file": file_path, "nodes": file_nodes, "edges": file_edges})
        entries.append({"path": file_path, "file": filename, "node_count": len(file_nodes), "edge_count": len(file_edges)})
    return entries


def _node_file(node: dict[str, Any]) -> str | None:
    anchor = node.get("anchor")
    if isinstance(anchor, dict) and isinstance(anchor.get("file"), str) and anchor["file"]:
        return anchor["file"]
    metadata = node.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("file"), str) and metadata["file"]:
        return metadata["file"]
    if node.get("kind") == "File" and isinstance(node.get("label"), str):
        return node["label"]
    return None


def _read_manifest(workspace: Path) -> dict[str, Any] | None:
    summary = graph_summary(workspace)
    if summary.get("schema_version") != GRAPH_SCHEMA_VERSION:
        return None
    path = workspace / GRAPH_DIRECTORY / GRAPH_MANIFEST_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) and data.get("schema_version") == GRAPH_SCHEMA_VERSION else None


def _page_from_chunks(workspace: Path, section: dict[str, Any], offset: int, limit: int, kind: str) -> dict[str, Any]:
    total = _int_value(section.get("count"))
    if offset >= total:
        return _page([], offset, limit, kind=kind, total=total)
    remaining = limit
    page: list[dict[str, Any]] = []
    for chunk in section.get("chunks", []):
        if not isinstance(chunk, dict):
            continue
        chunk_offset = _int_value(chunk.get("offset"))
        chunk_count = _int_value(chunk.get("count"))
        if chunk_offset + chunk_count <= offset:
            continue
        values = _read_gzip_json(_safe_graph_path(workspace, str(chunk.get("file") or "")))
        if not isinstance(values, list):
            continue
        start = max(0, offset - chunk_offset)
        selected = values[start : start + remaining]
        page.extend(item for item in selected if isinstance(item, dict))
        remaining = limit - len(page)
        if remaining <= 0:
            break
    return _page(page, offset, limit, kind=kind, total=total)


def _read_legacy_graph_page(
    workspace: Path,
    *,
    kind: str,
    offset: int,
    limit: int,
    file_path: str | None,
) -> dict[str, Any]:
    try:
        data = json.loads((workspace / GRAPH_INDEX_FILE).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return _page([], offset, limit, kind=kind, file_path=file_path)
    graph = data.get("graph") if isinstance(data, dict) else {}
    if kind == "files":
        nodes = graph.get("nodes") if isinstance(graph, dict) else []
        files = sorted({_node_file(item) for item in nodes if isinstance(item, dict) and _node_file(item)})
        return _page([{"path": item} for item in files], offset, limit, kind=kind)
    items = graph.get(kind) if isinstance(graph, dict) else []
    values = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    if file_path:
        node_files = {str(item.get("id") or ""): _node_file(item) for item in graph.get("nodes", []) if isinstance(item, dict)}
        if kind == "nodes":
            values = [item for item in values if _node_file(item) == file_path]
        else:
            values = [
                item
                for item in values
                if node_files.get(str(item.get("from") or "")) == file_path or node_files.get(str(item.get("to") or "")) == file_path
            ]
    return _page(values, offset, limit, kind=kind, file_path=file_path)


def _page(
    values: list[Any],
    offset: int,
    limit: int,
    *,
    kind: str,
    total: int | None = None,
    file_path: str | None = None,
) -> dict[str, Any]:
    total = len(values) if total is None else total
    items = values if total != len(values) else values[offset : offset + limit]
    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "kind": kind,
        "file": file_path,
        "offset": offset,
        "limit": limit,
        "total": total,
        "items": items,
        "next_offset": offset + len(items) if offset + len(items) < total else None,
    }


def _safe_graph_path(workspace: Path, relative: str) -> Path:
    root = (workspace / GRAPH_DIRECTORY).resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("invalid graph artifact path") from exc
    return candidate


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def _write_gzip_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=6) as handle:
        json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))


def _read_gzip_json(path: Path) -> Any:
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []


def _replace_directory(staging: Path, target: Path) -> None:
    backup: Path | None = None
    if target.exists():
        backup = target.with_name(f".{target.name}.backup-{uuid.uuid4().hex}")
        os.replace(target, backup)
    try:
        os.replace(staging, target)
    except Exception:
        if backup is not None and backup.exists():
            os.replace(backup, target)
        raise
    if backup is not None:
        shutil.rmtree(backup, ignore_errors=True)


def _int_value(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0
