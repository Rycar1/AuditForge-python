from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from auditforge.engine import run_scan
from auditforge.graph_artifacts import graph_summary, read_graph_facts, read_graph_page, write_graph_artifacts
from auditforge.models import CodeAnchor, CodeEdge, CodeFacts, CodeGraph, CodeNode


def test_graph_artifacts_are_compressed_and_pageable_by_file(tmp_path: Path) -> None:
    anchor = CodeAnchor("src/App.java", 3, 3, "snippet", "App.run")
    graph = CodeGraph(
        nodes=[
            CodeNode("file:app", "File", "src/App.java", language="java"),
            CodeNode("function:run", "Function", "App.run", anchor=anchor),
            CodeNode("sink:sql", "Sink", "raw_sql", anchor=anchor),
        ],
        edges=[
            CodeEdge("file:app", "function:run", "DEFINES", "high", "src/App.java:3"),
            CodeEdge("function:run", "sink:sql", "FLOWS_TO", "high", "src/App.java:3"),
        ],
    )
    facts = CodeFacts()

    index = write_graph_artifacts(tmp_path, facts, graph)

    assert index["graph"]["node_count"] == 3
    assert (tmp_path / "code_graph" / "manifest.json").exists()
    assert graph_summary(tmp_path)["edge_count"] == 2
    assert read_graph_facts(tmp_path)["files"] == []

    node_page = read_graph_page(tmp_path, kind="nodes", offset=1, limit=1)
    file_page = read_graph_page(tmp_path, kind="nodes", file_path="src/App.java", limit=10)
    edge_page = read_graph_page(tmp_path, kind="edges", file_path="src/App.java", limit=10)
    files_page = read_graph_page(tmp_path, kind="files", limit=10)

    assert node_page["items"][0]["id"] == "function:run"
    assert {item["id"] for item in file_page["items"]} == {"file:app", "function:run", "sink:sql"}
    assert len(edge_page["items"]) == 2
    assert files_page["items"][0]["path"] == "src/App.java"


def test_new_scans_keep_large_facts_and_graph_out_of_sqlite(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "polyglot_vulnerable"

    run_scan(repo, tmp_path)

    index = json.loads((tmp_path / "code_graph.json").read_text(encoding="utf-8"))
    con = sqlite3.connect(tmp_path / "auditforge.db")
    try:
        artifact_names = {row[0] for row in con.execute("SELECT name FROM artifacts")}
    finally:
        con.close()

    assert index["schema_version"] == 2
    assert (tmp_path / "code_graph" / "facts.json.gz").exists()
    assert {"facts", "graph"}.isdisjoint(artifact_names)
    assert read_graph_page(tmp_path, kind="nodes", limit=3)["total"] > 0
