from __future__ import annotations

from pathlib import Path

import auditforge.analysis_cache as analysis_cache
import auditforge.python_analysis as python_analysis
import auditforge.scanner as scanner
from auditforge.language_frontend import LanguageAnalysisResult


def _cache_root(tmp_path: Path) -> Path:
    return tmp_path.parent / f"{tmp_path.name}-analysis-cache"


def test_streaming_index_keeps_descriptors_lightweight_and_scan_is_unbounded(tmp_path: Path, monkeypatch) -> None:
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text(f"def {name[0]}():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))
    monkeypatch.setattr(scanner, "MAX_INDEXED_FILES", 2)

    descriptors = scanner.index_source_files(tmp_path, load_content=False, max_files=None)

    assert len(descriptors) == 3
    assert all(not item.content_loaded and item.content == "" and item.lines == [] for item in descriptors)
    assert all(item.content_hash and item.file.lines == 3 for item in descriptors)

    facts = scanner.scan_repo(tmp_path)

    assert {item.path for item in facts.files} == {"a.py", "b.py", "c.py"}
    assert facts.analysis_diagnostics["max_indexed_files"] is None
    assert facts.analysis_diagnostics["truncated"] is False


def test_default_scan_analyzes_source_larger_than_legacy_512_kib_limit(tmp_path: Path, monkeypatch) -> None:
    # This fixture deliberately crosses the former hard cutoff without making
    # the test expensive.  The security-relevant facts at the end must still be
    # extracted, not merely indexed.
    source = "# padding\n" * 53_000 + (
        "from flask import request\ndef search(db):\n    query = request.args.get('q')\n    return db.execute(query)\n"
    )
    assert len(source.encode("utf-8")) > 512 * 1024
    (tmp_path / "large_controller.py").write_text(source, encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))

    facts = scanner.scan_repo(tmp_path)

    indexed = facts.files[0]
    assert indexed.skipped_reason is None
    assert indexed.parsed_by == "ast"
    assert facts.analysis_diagnostics["max_source_file_bytes"] > 512 * 1024
    assert any(item.kind == "http_query" for item in facts.sources)
    assert any(item.kind == "raw_sql" for item in facts.sinks)


def test_source_file_budget_is_configurable_but_bounded(monkeypatch) -> None:
    monkeypatch.setenv(scanner.MAX_SOURCE_FILE_BYTES_ENV, "16MiB")
    assert scanner.source_file_limit_bytes() == 16 * 1024 * 1024

    monkeypatch.setenv(scanner.MAX_SOURCE_FILE_BYTES_ENV, "1")
    assert scanner.source_file_limit_bytes() == scanner.MIN_MAX_SOURCE_FILE_BYTES

    monkeypatch.setenv(scanner.MAX_SOURCE_FILE_BYTES_ENV, "999MiB")
    assert scanner.source_file_limit_bytes() == scanner.HARD_MAX_SOURCE_FILE_BYTES

    monkeypatch.setenv(scanner.MAX_SOURCE_FILE_BYTES_ENV, "not-a-size")
    assert scanner.source_file_limit_bytes() == scanner.DEFAULT_MAX_SOURCE_FILE_BYTES


def test_java_batch_provider_keeps_only_current_batch_results(tmp_path: Path, monkeypatch) -> None:
    for name in ("A.java", "B.java", "C.java"):
        (tmp_path / name).write_text(f"class {name[0]} {{}}\n", encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))
    monkeypatch.setattr(scanner, "JAVA_PRELOAD_BATCH_FILES", 2)

    calls: list[list[str]] = []

    def fake_batch(sources):
        calls.append([source.file.path for source in sources])
        return {
            source.file.path: (
                LanguageAnalysisResult(),
                {"status": "ok", "reason": "fixture", "used": True, "fallback": False},
            )
            for source in sources
        }

    monkeypatch.setattr("auditforge.native_ast_bridge.analyze_java_batch_with_ast", fake_batch)
    descriptors = scanner.index_source_files(tmp_path, load_content=False, max_files=None)
    provider = scanner._JavaBatchProvider(  # noqa: SLF001 - validates bounded provider semantics
        descriptors,
        scanner.AnalysisCache(tmp_path),
        max_file_bytes=scanner.source_file_limit_bytes(),
    )

    loaded = [scanner.load_source_file(item)[0] for item in descriptors]
    assert all(item is not None for item in loaded)
    first, second, third = loaded
    assert first is not None and second is not None and third is not None

    assert provider.take(first) is not None
    assert provider.pending_result_count == 1
    assert provider.take(second) is not None
    assert provider.pending_result_count == 0
    assert provider.take(third) is not None
    assert provider.pending_result_count == 0
    assert calls == [["A.java", "B.java"], ["C.java"]]


def test_streaming_scan_consumes_java_batches_in_source_order(tmp_path: Path, monkeypatch) -> None:
    for name in ("A.java", "B.java", "C.java"):
        (tmp_path / name).write_text(f"class {name[0]} {{}}\n", encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))
    monkeypatch.setattr(scanner, "JAVA_PRELOAD_BATCH_FILES", 2)

    calls: list[list[str]] = []

    def fake_batch(sources):
        calls.append([source.file.path for source in sources])
        return {
            source.file.path: (
                LanguageAnalysisResult(),
                {"status": "ok", "reason": "fixture", "used": True, "fallback": False},
            )
            for source in sources
        }

    monkeypatch.setattr("auditforge.native_ast_bridge.analyze_java_batch_with_ast", fake_batch)
    facts = scanner.scan_repo(tmp_path)

    assert calls == [["A.java", "B.java"], ["C.java"]]
    assert all(item.parsed_by == "ast" for item in facts.files)
    assert facts.analysis_diagnostics["native_ast"]["languages"]["java"]["ast_files"] == 3

    calls.clear()
    cached = scanner.scan_repo(tmp_path)
    assert calls == []
    assert cached.analysis_diagnostics["incremental_cache"]["hits"] == 3
    assert cached.analysis_diagnostics["native_ast"]["languages"]["java"]["ast_files"] == 3


def test_java_batch_fallback_keeps_existing_heuristic_path_without_single_retry(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "Controller.java").write_text("class Controller {}\n", encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))
    monkeypatch.setattr(
        "auditforge.native_ast_bridge.analyze_java_batch_with_ast",
        lambda sources: {
            source.file.path: (
                None,
                {"status": "javac_not_found", "reason": "fixture", "used": False, "fallback": True},
            )
            for source in sources
        },
    )
    single_calls: list[str] = []

    def unexpected_single(source):
        single_calls.append(source.file.path)
        return None, {"status": "unexpected", "reason": "fixture", "used": False, "fallback": True}

    monkeypatch.setattr(
        "auditforge.native_ast_bridge.analyze_native_with_ast",
        unexpected_single,
    )

    facts = scanner.scan_repo(tmp_path)

    assert single_calls == []
    assert facts.files[0].parsed_by == "heuristic"
    diagnostic = facts.analysis_diagnostics["native_ast"]["languages"]["java"]
    assert diagnostic["fallback_files"] == 1
    assert diagnostic["statuses"] == {"javac_not_found": 1}


def test_content_hash_cache_reuses_unchanged_file_facts_and_invalidates_changes(tmp_path: Path, monkeypatch) -> None:
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_text("def first():\n    return 1\n", encoding="utf-8")
    second.write_text("def second():\n    return 2\n", encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))

    calls: list[str] = []
    real_analyze = python_analysis.analyze_python

    def counted_analyze(source):
        calls.append(source.file.path)
        return real_analyze(source)

    monkeypatch.setattr(python_analysis, "analyze_python", counted_analyze)

    first_run = scanner.scan_repo(tmp_path)
    assert calls == ["first.py", "second.py"]
    assert first_run.analysis_diagnostics["incremental_cache"]["writes"] == 2

    calls.clear()
    second_run = scanner.scan_repo(tmp_path)
    assert calls == []
    assert second_run.analysis_diagnostics["incremental_cache"]["hits"] == 2
    assert [item.to_dict() for item in second_run.functions] == [item.to_dict() for item in first_run.functions]

    second.write_text("def changed():\n    return 3\n", encoding="utf-8")
    calls.clear()
    third_run = scanner.scan_repo(tmp_path)

    assert calls == ["second.py"]
    assert third_run.analysis_diagnostics["incremental_cache"]["hits"] == 1
    assert third_run.analysis_diagnostics["incremental_cache"]["writes"] == 1
    assert {item.name for item in third_run.functions} == {"first", "changed"}


def test_transient_typescript_frontend_fallback_is_not_reused_from_cache(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.ts").write_text("const value = request.query.q;\n", encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))

    monkeypatch.setattr(
        "auditforge.typescript_compiler_bridge.analyze_typescript_with_compiler",
        lambda _source: (
            None,
            {"status": "typescript_not_found", "reason": "fixture", "used": False, "fallback": True},
        ),
    )
    fallback = scanner.scan_repo(tmp_path)
    assert fallback.files[0].parsed_by == "heuristic"
    assert fallback.analysis_diagnostics["incremental_cache"]["writes"] == 0

    compiler_calls: list[str] = []

    def compiler_now_available(source):
        compiler_calls.append(source.file.path)
        return LanguageAnalysisResult(), {"status": "ok", "reason": "fixture", "used": True, "fallback": False}

    monkeypatch.setattr("auditforge.typescript_compiler_bridge.analyze_typescript_with_compiler", compiler_now_available)
    upgraded = scanner.scan_repo(tmp_path)

    assert compiler_calls == ["app.ts"]
    assert upgraded.files[0].parsed_by == "ast"
    assert upgraded.analysis_diagnostics["incremental_cache"]["hits"] == 0


def test_malformed_cache_entry_falls_back_to_fresh_analysis(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "app.py"
    path.write_text("def app():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))
    scanner.scan_repo(tmp_path)

    descriptor = scanner.index_source_files(tmp_path, load_content=False, max_files=None)[0]
    cache = scanner.AnalysisCache(tmp_path)
    entry_path = cache._entry_path(  # noqa: SLF001 - validates safe corruption handling at the cache boundary
        path=descriptor.file.path,
        language=descriptor.file.language,
        content_hash=descriptor.content_hash,
    )
    assert entry_path is not None
    entry_path.write_text("not-json", encoding="utf-8")

    calls: list[str] = []
    real_analyze = python_analysis.analyze_python

    def counted_analyze(source):
        calls.append(source.file.path)
        return real_analyze(source)

    monkeypatch.setattr(python_analysis, "analyze_python", counted_analyze)
    facts = scanner.scan_repo(tmp_path)

    assert calls == ["app.py"]
    assert facts.functions[0].name == "app"
    assert facts.analysis_diagnostics["incremental_cache"]["read_errors"] == 1


def test_oversized_cache_entry_is_rejected_before_deserializing(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "app.py"
    path.write_text("def app():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("AUDITFORGE_ANALYSIS_CACHE_DIR", str(_cache_root(tmp_path)))
    scanner.scan_repo(tmp_path)

    descriptor = scanner.index_source_files(tmp_path, load_content=False, max_files=None)[0]
    cache = scanner.AnalysisCache(tmp_path)
    entry_path = cache._entry_path(  # noqa: SLF001 - validates cache input size at the boundary
        path=descriptor.file.path,
        language=descriptor.file.language,
        content_hash=descriptor.content_hash,
    )
    assert entry_path is not None
    entry_path.write_text("x" * 32, encoding="utf-8")
    monkeypatch.setattr(analysis_cache, "MAX_CACHE_ENTRY_BYTES", 16)

    calls: list[str] = []
    real_analyze = python_analysis.analyze_python

    def counted_analyze(source):
        calls.append(source.file.path)
        return real_analyze(source)

    monkeypatch.setattr(python_analysis, "analyze_python", counted_analyze)
    facts = scanner.scan_repo(tmp_path)

    assert calls == ["app.py"]
    assert facts.analysis_diagnostics["incremental_cache"]["read_errors"] == 1
