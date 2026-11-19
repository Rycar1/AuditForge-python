from __future__ import annotations

import hashlib
import os
import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .analysis_cache import AnalysisCache, CachedFileAnalysis
from .models import (
    CallSiteFact,
    ClassFact,
    CodeAnchor,
    CodeFacts,
    ControlFlowFact,
    DataFlowFact,
    FunctionFact,
    ImportFact,
    IndexedFile,
    RouteFact,
    SanitizerFact,
    SinkFact,
    SourceFact,
)
from .rules import SANITIZER_RULES, SINK_RULES, SOURCE_RULES
from .utils import dedupe_by, line_count, normalize_path, sha256_text, stable_id

DEFAULT_MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
# Kept as a public compatibility alias for callers that imported the old
# constant.  Repository scans resolve the environment-controlled limit once at
# startup so an operator can tune it for constrained hosts.
MAX_FILE_BYTES = DEFAULT_MAX_SOURCE_FILE_BYTES
MIN_MAX_SOURCE_FILE_BYTES = 64 * 1024
HARD_MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILE_BYTES_ENV = "AUDITFORGE_MAX_SOURCE_FILE_BYTES"
MAX_INDEXED_FILES = 3000
JAVA_PRELOAD_BATCH_FILES = 48
JAVA_PRELOAD_BATCH_BYTES = 4 * 1024 * 1024

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".shannon",
    ".auditforge",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "third-party",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "target",
    "__pycache__",
    "uploads",
    "uploaded_files",
    "media",
    "tmp",
    "temp",
    "package-staging",
}

SKIP_SOURCE_SUFFIXES = (".min.js",)

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".rs": "rust",
    ".scala": "scala",
}

FUNCTION_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "new",
    "function",
    "class",
    "typeof",
    "sizeof",
    "delete",
    "throw",
}


def source_file_limit_bytes() -> int:
    """Return the bounded per-file source budget for this scan process.

    The old 512 KiB cutoff skipped ordinary generated controllers, API clients,
    and monolithic service classes.  Eight MiB is a practical default for real
    source while the 64 MiB ceiling protects the single-file parsers from an
    accidental or hostile resource spike.  Operators can tune the soft budget
    with ``AUDITFORGE_MAX_SOURCE_FILE_BYTES`` (for example ``16MiB``).
    """

    raw = os.getenv(MAX_SOURCE_FILE_BYTES_ENV, "").strip().lower()
    if not raw:
        return DEFAULT_MAX_SOURCE_FILE_BYTES
    match = re.fullmatch(r"(?P<size>\d+)\s*(?P<unit>b|kb|kib|k|mb|mib|m)?", raw)
    if not match:
        return DEFAULT_MAX_SOURCE_FILE_BYTES
    units = {
        None: 1,
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024 * 1024,
        "mb": 1024 * 1024,
        "mib": 1024 * 1024,
    }
    requested = int(match.group("size")) * units[match.group("unit")]
    return max(MIN_MAX_SOURCE_FILE_BYTES, min(requested, HARD_MAX_SOURCE_FILE_BYTES))


@dataclass(frozen=True)
class SourceFile:
    file: IndexedFile
    absolute_path: Path
    content: str = ""
    lines: list[str] = field(default_factory=list)
    # ``index_source_files`` retains this descriptor but, for repository scans,
    # does not retain its source text.  The scanner materialises it only when a
    # cache miss must be analysed.
    content_hash: str | None = None
    snapshot_size: int | None = None
    snapshot_mtime_ns: int | None = None
    snapshot_stable: bool = True
    content_loaded: bool = True


HASH_COMMENT_LANGUAGES = {"python", "ruby", "php", "shell", "bash"}
C_STYLE_COMMENT_LANGUAGES = {
    "javascript",
    "typescript",
    "java",
    "go",
    "php",
    "csharp",
    "kotlin",
    "rust",
    "scala",
}


def scan_repo(
    repo_path: Path,
    progress_callback: Callable[[int, int], None] | None = None,
) -> CodeFacts:
    diagnostics = _new_scan_diagnostics()
    repo_path = repo_path.resolve(strict=True)
    max_file_bytes = source_file_limit_bytes()
    diagnostics["max_source_file_bytes"] = max_file_bytes
    # Keep only lightweight descriptors during discovery.  This deliberately
    # avoids retaining every source string and split-lines list for large repos.
    # ``index_source_files`` retains its eager default for the public helper API.
    source_files = index_source_files(
        repo_path,
        diagnostics,
        load_content=False,
        max_files=None,
        max_file_bytes=max_file_bytes,
    )
    facts = CodeFacts(analysis_diagnostics=diagnostics)
    indexed_files: list[IndexedFile] = []
    source_total = len(source_files)
    progress_interval = max(1, source_total // 20)
    cache = AnalysisCache(repo_path)
    diagnostics["incremental_cache"] = cache.diagnostics()
    # Java's native parser remains batch-oriented, but the provider keeps only
    # the current bounded batch of facts instead of precomputing the whole
    # repository before normal per-file scanning begins.
    java_batch_provider = _JavaBatchProvider(source_files, cache, max_file_bytes=max_file_bytes)

    for source_index, source_file in enumerate(source_files, start=1):
        completed = source_index - 1
        if progress_callback and (completed == 0 or completed % progress_interval == 0):
            progress_callback(completed, source_total)
        if source_file.file.skipped_reason:
            indexed_files.append(source_file.file)
            continue

        descriptor_hash = source_file.content_hash
        cached = _load_cached_analysis(cache, source_file)
        if cached is not None:
            cached_file = replace(source_file.file, parsed_by=cached.file.parsed_by, analysis_error=None, skipped_reason=None)
            _extend_cached_facts(facts, cached)
            _record_cached_analysis(diagnostics, cached_file, cached.profile)
            indexed_files.append(cached_file)
            continue

        loaded_source, load_error = load_source_file(source_file, max_file_bytes=max_file_bytes)
        if loaded_source is None:
            reason = load_error or "file could not be read"
            fallback_file = replace(source_file.file, parsed_by="fallback", skipped_reason=reason, analysis_error=reason)
            _record_skipped(diagnostics, fallback_file.path, reason)
            diagnostics["errors"].append({"path": fallback_file.path, "stage": "lazy_read", "error": reason})
            diagnostics["error_files"] += 1
            indexed_files.append(fallback_file)
            continue
        source_file = loaded_source

        # A file may change after its descriptor is hashed.  Retry a cache lookup
        # with the loaded snapshot rather than analysing stale bytes or accepting
        # a cache entry for the earlier revision.
        cached = (
            _load_cached_analysis(cache, source_file)
            if source_file.content_hash != descriptor_hash or not source_file.snapshot_stable
            else None
        )
        if cached is not None:
            cached_file = replace(source_file.file, parsed_by=cached.file.parsed_by, analysis_error=None, skipped_reason=None)
            _extend_cached_facts(facts, cached)
            _record_cached_analysis(diagnostics, cached_file, cached.profile)
            indexed_files.append(cached_file)
            continue

        fact_offsets = _fact_offsets(facts)
        facts.imports.extend(extract_imports(source_file))
        current_file = source_file.file
        cache_profile = ""
        analysis_complete = False
        if current_file.language == "python":
            try:
                from .python_analysis import analyze_python

                result = analyze_python(source_file)
                ast_file = replace(current_file, parsed_by="ast")
                source_file = replace(source_file, file=ast_file)
                current_file = ast_file
                _extend_analysis_result(facts, result)
                diagnostics["ast_files"] += 1
                diagnostics["analyzed_files"] += 1
                cache_profile = "python-ast"
                analysis_complete = True
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                fallback_file = replace(current_file, parsed_by="fallback", analysis_error=message)
                source_file = replace(source_file, file=fallback_file)
                current_file = fallback_file
                diagnostics["errors"].append({"path": fallback_file.path, "stage": "python_ast", "error": message})
                diagnostics["error_files"] += 1
                diagnostics["fallback_files"] += 1
        if not analysis_complete and current_file.language == "typescript":
            try:
                from .typescript_compiler_bridge import analyze_typescript_with_compiler

                compiler_result, compiler_diagnostic = analyze_typescript_with_compiler(source_file)
            except Exception as exc:  # noqa: BLE001 - the existing frontend is the safety fallback
                compiler_result = None
                compiler_diagnostic = {
                    "status": "bridge_error",
                    "reason": f"{type(exc).__name__}: {exc}",
                    "used": False,
                    "fallback": True,
                }
            _record_typescript_compiler_diagnostic(diagnostics, source_file.file.path, compiler_diagnostic)
            if compiler_result is not None:
                ast_file = replace(current_file, parsed_by="ast")
                current_file = ast_file
                source_file = replace(source_file, file=ast_file)
                _extend_analysis_result(facts, compiler_result)
                diagnostics["ast_files"] += 1
                diagnostics["analyzed_files"] += 1
                diagnostics["language_frontend_files"] += 1
                diagnostics["language_frontends"]["typescript-compiler-api"] = (
                    int(diagnostics["language_frontends"].get("typescript-compiler-api") or 0) + 1
                )
                cache_profile = "typescript-compiler-api"
                analysis_complete = True
        java_batch = java_batch_provider.take(source_file) if current_file.language == "java" else None
        java_batch_available = bool(java_batch is not None and java_batch[2] == source_file.content_hash)
        if not analysis_complete and current_file.language == "java" and java_batch_available:
            native_result, native_diagnostic, _content_hash = java_batch
            _record_native_ast_diagnostic(diagnostics, current_file.path, current_file.language, native_diagnostic)
            if native_result is not None:
                ast_file = replace(current_file, parsed_by="ast")
                current_file = ast_file
                source_file = replace(source_file, file=ast_file)
                _extend_analysis_result(facts, native_result)
                diagnostics["ast_files"] += 1
                diagnostics["analyzed_files"] += 1
                diagnostics["language_frontend_files"] += 1
                frontend = f"{current_file.language}-native-ast"
                diagnostics["language_frontends"][frontend] = int(diagnostics["language_frontends"].get(frontend) or 0) + 1
                cache_profile = "java-native-ast"
                analysis_complete = True
        if not analysis_complete and (current_file.language == "go" or (current_file.language == "java" and not java_batch_available)):
            try:
                from .native_ast_bridge import analyze_native_with_ast

                native_result, native_diagnostic = analyze_native_with_ast(source_file)
            except Exception as exc:  # noqa: BLE001 - preserve the existing language frontend as a safe fallback
                native_result = None
                native_diagnostic = {
                    "status": "bridge_error",
                    "reason": f"{type(exc).__name__}: {exc}",
                    "used": False,
                    "fallback": True,
                }
            _record_native_ast_diagnostic(diagnostics, current_file.path, current_file.language, native_diagnostic)
            if native_result is not None:
                ast_file = replace(current_file, parsed_by="ast")
                current_file = ast_file
                source_file = replace(source_file, file=ast_file)
                _extend_analysis_result(facts, native_result)
                diagnostics["ast_files"] += 1
                diagnostics["analyzed_files"] += 1
                diagnostics["language_frontend_files"] += 1
                frontend = f"{current_file.language}-native-ast"
                diagnostics["language_frontends"][frontend] = int(diagnostics["language_frontends"].get(frontend) or 0) + 1
                cache_profile = f"{current_file.language}-native-ast"
                analysis_complete = True
        if not analysis_complete:
            source_file = replace(source_file, file=current_file)
            frontend_used = _extend_language_frontend_facts(facts, source_file, diagnostics)
            if not frontend_used:
                _extend_heuristic_facts(facts, source_file)
            diagnostics["heuristic_files"] += 1
            diagnostics["analyzed_files"] += 1
            cache_profile = "language-frontend" if frontend_used else "heuristic"

        indexed_files.append(current_file)
        if _cache_result_is_reusable(current_file):
            cache.store(
                path=current_file.path,
                language=current_file.language,
                content_hash=source_file.content_hash,
                file=current_file,
                facts=_fact_bundle(facts, fact_offsets),
                profile=cache_profile,
            )
        else:
            cache.record_bypass()

    facts.files = indexed_files
    # Framework conventions such as DRF request containers and FastAPI security
    # dependencies are not ordinary language constructs.  Add those facts before
    # the common de-duplication pass so CLI, benchmark and Dashboard scans all see
    # the same modelled evidence.
    from .framework_models import augment_framework_facts
    from .java_framework import augment_java_framework_facts
    from .php_symbols import augment_php_symbol_facts

    augment_framework_facts(repo_path, facts)
    augment_java_framework_facts(repo_path, facts)
    augment_php_symbol_facts(repo_path, facts)
    facts.files = dedupe_by(facts.files, lambda x: x.id)
    facts.functions = dedupe_by(facts.functions, lambda x: x.id)
    facts.classes = dedupe_by(facts.classes, lambda x: x.id)
    facts.routes = dedupe_by(facts.routes, lambda x: x.id)
    facts.data_flows = dedupe_by(facts.data_flows, lambda x: x.id)
    facts.control_flows = dedupe_by(facts.control_flows, lambda x: x.id)
    facts.sources = dedupe_by(facts.sources, lambda x: x.id)
    facts.sinks = dedupe_by(facts.sinks, lambda x: x.id)
    facts.sanitizers = dedupe_by(facts.sanitizers, lambda x: x.id)
    facts.call_sites = dedupe_by(facts.call_sites, lambda x: x.id)
    facts.imports = dedupe_by(facts.imports, lambda x: x.id)
    diagnostics["incremental_cache"] = cache.diagnostics()
    _finalize_scan_diagnostics(diagnostics)
    if progress_callback:
        progress_callback(source_total, source_total)
    return facts


FACT_COLLECTIONS = (
    "functions",
    "classes",
    "routes",
    "sources",
    "sinks",
    "sanitizers",
    "call_sites",
    "data_flows",
    "control_flows",
    "imports",
)


def _fact_offsets(facts: CodeFacts) -> dict[str, int]:
    return {name: len(getattr(facts, name)) for name in FACT_COLLECTIONS}


def _fact_bundle(facts: CodeFacts, offsets: dict[str, int]) -> dict[str, list[Any]]:
    return {name: list(getattr(facts, name)[offsets[name] :]) for name in FACT_COLLECTIONS}


def _extend_cached_facts(facts: CodeFacts, cached: CachedFileAnalysis) -> None:
    for name in FACT_COLLECTIONS:
        getattr(facts, name).extend(cached.facts.get(name, []))


def _load_cached_analysis(cache: AnalysisCache, source_file: SourceFile) -> CachedFileAnalysis | None:
    if not source_file.content_hash or not source_file.snapshot_stable or not _source_snapshot_is_current(source_file):
        return None
    cached = cache.load(
        path=source_file.file.path,
        language=source_file.file.language,
        content_hash=source_file.content_hash,
    )
    if not _source_snapshot_is_current(source_file):
        return None
    return cached if cached is not None and _cache_result_is_reusable(cached.file) else None


def _cache_result_is_reusable(file: IndexedFile) -> bool:
    """Do not let a transient optional-parser fallback reduce future coverage."""

    if file.parsed_by == "fallback" or file.analysis_error:
        return False
    return file.parsed_by == "ast" or file.language not in {"typescript", "java", "go"}


def _record_cached_analysis(diagnostics: dict[str, Any], file: IndexedFile, profile: str) -> None:
    diagnostics["analyzed_files"] += 1
    if file.parsed_by == "ast":
        diagnostics["ast_files"] += 1
    else:
        diagnostics["heuristic_files"] += 1
    if profile == "typescript-compiler-api":
        _record_typescript_compiler_diagnostic(
            diagnostics,
            file.path,
            {"status": "cache_hit", "used": True, "fallback": False},
        )
        _record_cached_frontend(diagnostics, "typescript-compiler-api")
    elif profile in {"java-native-ast", "go-native-ast"}:
        _record_native_ast_diagnostic(
            diagnostics,
            file.path,
            file.language,
            {"status": "cache_hit", "used": True, "fallback": False},
        )
        _record_cached_frontend(diagnostics, profile)
    elif profile == "language-frontend":
        try:
            from .language_registry import frontend_id

            frontend = frontend_id(file.language) or file.language
        except Exception:  # noqa: BLE001 - cached facts remain valid without presentation metadata
            frontend = file.language
        _record_cached_frontend(diagnostics, frontend)


def _record_cached_frontend(diagnostics: dict[str, Any], frontend: str) -> None:
    diagnostics["language_frontend_files"] += 1
    diagnostics["language_frontends"][frontend] = int(diagnostics["language_frontends"].get(frontend) or 0) + 1


class _JavaBatchProvider:
    """Lazily provide bounded Java AST batches to the file scan stream.

    The native Java bridge is much faster in batches.  The old eager preparation
    traded that speed for an additional repository-sized map of result lists.
    This provider starts a batch only when its first uncached Java file reaches
    the main loop and keeps the remaining results for that one batch only.
    """

    def __init__(self, source_files: list[SourceFile], cache: AnalysisCache, *, max_file_bytes: int) -> None:
        self._remaining: deque[SourceFile] = deque(
            item for item in source_files if item.file.language == "java" and not item.file.skipped_reason
        )
        self._cache = cache
        self._max_file_bytes = max_file_bytes
        self._results: dict[str, tuple[Any, dict[str, Any], str | None]] = {}

    @property
    def pending_result_count(self) -> int:
        """Expose the bounded pending result count for diagnostics/tests."""

        return len(self._results)

    def take(self, source_file: SourceFile) -> tuple[Any, dict[str, Any], str | None] | None:
        """Return the native batch result for one loaded Java snapshot.

        A ``None`` return means the normal one-file native fallback should run.
        A tuple with a ``None`` native result is different: the batch frontend
        explicitly failed/unavailable and the established heuristic fallback is
        retained without repeating an equivalent parser invocation.
        """

        path = source_file.file.path
        existing = self._results.pop(path, None)
        if existing is not None:
            return existing if existing[2] == source_file.content_hash else None

        self._discard_through(path)
        batch = self._next_batch(source_file)
        if not batch:
            return None
        self._run_batch(batch)
        result = self._results.pop(path, None)
        return result if result is not None and result[2] == source_file.content_hash else None

    def _discard_through(self, path: str) -> None:
        """Advance past Java descriptors already handled by the main loop."""

        discarded: list[SourceFile] = []
        while self._remaining:
            descriptor = self._remaining.popleft()
            if descriptor.file.path == path:
                return
            discarded.append(descriptor)
        # A descriptor can have been optimistically skipped because a cache file
        # existed, then later prove corrupt.  Keep future work intact when that
        # descriptor is no longer in the queue.
        self._remaining.extendleft(reversed(discarded))

    def _next_batch(self, first: SourceFile) -> list[SourceFile]:
        batch = [first]
        batch_bytes = first.file.bytes
        while self._remaining:
            descriptor = self._remaining[0]
            if self._probable_cache_hit(descriptor):
                # Cache validation still happens in the main loop.  If a stale
                # entry proves invalid later, this file simply starts a new
                # single/bounded batch at that point.
                self._remaining.popleft()
                continue
            if len(batch) >= JAVA_PRELOAD_BATCH_FILES or batch_bytes + descriptor.file.bytes > JAVA_PRELOAD_BATCH_BYTES:
                break
            self._remaining.popleft()
            loaded, _load_error = load_source_file(descriptor, max_file_bytes=self._max_file_bytes)
            if loaded is None:
                # The main loop emits the safe read diagnostic when it reaches
                # this descriptor.  Do not turn a batch optimisation into a
                # second, differently-labelled failure.
                continue
            if batch_bytes + loaded.file.bytes > JAVA_PRELOAD_BATCH_BYTES:
                # Metadata may race with an active checkout. Retry this file as
                # the first item of its own batch when it reaches the stream.
                self._remaining.appendleft(descriptor)
                break
            batch.append(loaded)
            batch_bytes += loaded.file.bytes
        return batch

    def _probable_cache_hit(self, descriptor: SourceFile) -> bool:
        return bool(
            descriptor.snapshot_stable
            and _source_snapshot_is_current(descriptor)
            and self._cache.has_candidate(
                path=descriptor.file.path,
                language=descriptor.file.language,
                content_hash=descriptor.content_hash,
            )
        )

    def _run_batch(self, batch: list[SourceFile]) -> None:
        try:
            from .native_ast_bridge import analyze_java_batch_with_ast

            batch_results = analyze_java_batch_with_ast(batch)
        except Exception:  # noqa: BLE001 - preserve the one-file native fallback
            return
        for item in batch:
            result = batch_results.get(item.file.path)
            if result is None:
                continue
            native_result, native_diagnostic = result
            self._results[item.file.path] = (native_result, native_diagnostic, item.content_hash)


def _extend_heuristic_facts(facts: CodeFacts, source_file: SourceFile) -> None:
    functions = extract_functions(source_file)
    facts.functions.extend(functions)
    facts.classes.extend(extract_classes(source_file))
    facts.routes.extend(extract_routes(source_file))
    facts.sources.extend(extract_sources(source_file, functions))
    facts.sinks.extend(extract_sinks(source_file, functions))
    facts.sanitizers.extend(extract_sanitizers(source_file, functions))
    facts.call_sites.extend(extract_call_sites(source_file, functions))
    facts.data_flows.extend(extract_data_flows(source_file, functions))
    facts.control_flows.extend(extract_control_flows(source_file, functions))


def extract_imports(source_file: SourceFile) -> list[ImportFact]:
    """Collect conservative import aliases for cross-file call resolution."""

    if source_file.file.language == "php":
        return _extract_php_imports(source_file)

    output: list[ImportFact] = []
    for line_no, raw in enumerate(source_file.lines, 1):
        aliases: dict[str, str] = {}
        module = ""
        language = source_file.file.language
        if language in {"javascript", "typescript"}:
            match = re.search(r"\bimport\s+(.+?)\s+from\s+['\"]([^'\"]+)['\"]", raw)
            require = re.search(r"\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]", raw)
            if match:
                module, spec = match.group(2), match.group(1).strip()
                if spec.startswith("{"):
                    for item in spec.strip("{} ").split(","):
                        parts = re.split(r"\s+as\s+", item.strip())
                        if parts and parts[0]:
                            aliases[parts[-1].strip()] = parts[0].strip()
                elif spec.startswith("*") and "as" in spec:
                    aliases[spec.rsplit("as", 1)[-1].strip()] = "*"
                elif spec:
                    aliases[spec.split(",", 1)[0].strip()] = "default"
            elif require:
                aliases[require.group(1)] = "*"
                module = require.group(2)
        elif language == "python":
            match = re.match(r"\s*from\s+([\w.]+)\s+import\s+(.+)$", raw)
            plain = re.match(r"\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?", raw)
            if match:
                module = match.group(1)
                for item in match.group(2).split(","):
                    parts = re.split(r"\s+as\s+", item.strip())
                    aliases[parts[-1].strip()] = parts[0].strip()
            elif plain:
                module = plain.group(1)
                aliases[plain.group(2) or module.rsplit(".", 1)[-1]] = "*"
        elif language == "java":
            match = re.match(r"\s*import\s+(?:static\s+)?([\w.]+)(?:\.\*)?\s*;", raw)
            if match:
                module = match.group(1)
                aliases[module.rsplit(".", 1)[-1]] = "*"
        elif language == "go":
            match = re.match(r'\s*import\s+(?:(\w+)\s+)?"([^"]+)"', raw)
            if match:
                module = match.group(2)
                aliases[match.group(1) or module.rstrip("/").rsplit("/", 1)[-1]] = "*"
        if not module or not aliases:
            continue
        anchor = CodeAnchor(source_file.file.path, line_no, line_no, sha256_text(raw), "import")
        output.append(ImportFact(stable_id("import", source_file.file.path, line_no, module), module, aliases, anchor))
    return output


def _extract_php_imports(source_file: SourceFile) -> list[ImportFact]:
    content = source_file.content
    pattern = re.compile(
        r"(?m)^[ \t]*use[ \t]+(?:(?P<kind>function|const)[ \t]+)?(?P<body>.*?);",
        re.IGNORECASE | re.DOTALL,
    )
    matches = list(pattern.finditer(content))
    allowed = _php_namespace_scope_matches(content, [item.start() for item in matches])
    output: list[ImportFact] = []
    for match in matches:
        if not allowed.get(match.start(), False):
            continue
        default_kind = (match.group("kind") or "class").lower()
        for module, alias, kind in _php_use_items(match.group("body"), default_kind):
            line = content.count("\n", 0, match.start()) + 1
            end_line = content.count("\n", 0, match.end()) + 1
            imported_name = module.rsplit("\\", 1)[-1]
            aliases = {alias or imported_name: imported_name if kind == "function" else "*"}
            anchor = CodeAnchor(source_file.file.path, line, end_line, sha256_text(match.group(0)), "import")
            output.append(
                ImportFact(
                    stable_id("import", source_file.file.path, line, f"{kind}:{module}:{alias}"),
                    module,
                    aliases,
                    anchor,
                    kind=kind,
                )
            )
    return output


def _php_use_items(body: str, default_kind: str) -> list[tuple[str, str | None, str]]:
    compact = body.strip()
    group = re.match(r"(?P<prefix>\\?[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\\\s*\{(?P<items>.*)}\s*$", compact, re.DOTALL)
    raw_items: list[tuple[str, str]] = []
    if group:
        prefix = group.group("prefix").rstrip("\\")
        raw_items = [(f"{prefix}\\{item.strip()}", default_kind) for item in group.group("items").split(",") if item.strip()]
    else:
        raw_items = [(item.strip(), default_kind) for item in compact.split(",") if item.strip()]

    output: list[tuple[str, str | None, str]] = []
    for raw, inherited_kind in raw_items:
        item_kind = inherited_kind
        kind_match = re.match(r"(?P<kind>function|const)\s+(?P<rest>.+)$", raw, re.IGNORECASE | re.DOTALL)
        if kind_match:
            item_kind = kind_match.group("kind").lower()
            raw = kind_match.group("rest")
        alias_match = re.match(r"(?P<module>\\?[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)(?:\s+as\s+(?P<alias>[A-Za-z_]\w*))?\s*$", raw, re.IGNORECASE)
        if not alias_match:
            continue
        output.append((alias_match.group("module").lstrip("\\"), alias_match.group("alias"), item_kind))
    return output


def _php_namespace_scope_matches(content: str, offsets: list[int]) -> dict[int, bool]:
    """Return whether each offset is at file/namespace scope, not in a class."""

    pending = set(offsets)
    output: dict[int, bool] = {}
    stack: list[str] = []
    mask = _php_structure_mask(content)
    header_start = 0
    for index, char in enumerate(mask):
        if index in pending:
            output[index] = all(item == "namespace" for item in stack)
        if char == "{":
            header = mask[header_start:index]
            kind = "namespace" if re.search(r"\bnamespace\s+[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*\s*$", header) else "code"
            stack.append(kind)
            header_start = index + 1
        elif char == "}":
            if stack:
                stack.pop()
            header_start = index + 1
        elif char == ";":
            header_start = index + 1
    for offset in pending:
        output.setdefault(offset, all(item == "namespace" for item in stack))
    return output


def _php_structure_mask(content: str) -> str:
    chars = list(content)
    quote: str | None = None
    escaped = False
    block_comment = False
    line_comment = False
    index = 0
    while index < len(chars):
        char = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            else:
                chars[index] = " "
            index += 1
            continue
        if block_comment:
            if char == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                block_comment = False
                index += 2
            else:
                if char != "\n":
                    chars[index] = " "
                index += 1
            continue
        if quote:
            if char != "\n":
                chars[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char == "/" and following == "*":
            chars[index] = chars[index + 1] = " "
            block_comment = True
            index += 2
            continue
        if char == "/" and following == "/" or char == "#" and following != "[":
            chars[index] = " "
            line_comment = True
            index += 1
            continue
        if char in {"'", '"', "`"}:
            chars[index] = " "
            quote = char
        index += 1
    return "".join(chars)


def _extend_language_frontend_facts(facts: CodeFacts, source_file: SourceFile, diagnostics: dict[str, Any]) -> bool:
    """Use a structured language pack, falling back to generic facts when absent."""

    if source_file.file.language not in {"javascript", "typescript", "java", "go", "php"}:
        return False
    try:
        from .language_registry import analyze_language_frontend, frontend_id

        result = analyze_language_frontend(source_file)
    except Exception as exc:  # noqa: BLE001 - legacy generic extraction remains available
        diagnostics["frontend_errors"].append(
            {"path": source_file.file.path, "language": source_file.file.language, "error": f"{type(exc).__name__}: {exc}"}
        )
        return False
    if result is None or not any(
        (
            result.functions,
            result.classes,
            result.routes,
            result.sources,
            result.sinks,
            result.sanitizers,
            result.call_sites,
            result.data_flows,
            result.control_flows,
        )
    ):
        return False
    _extend_analysis_result(facts, result)
    diagnostics["language_frontend_files"] += 1
    frontend = frontend_id(source_file.file.language) or source_file.file.language
    diagnostics["language_frontends"][frontend] = int(diagnostics["language_frontends"].get(frontend) or 0) + 1
    return True


def _extend_analysis_result(facts: CodeFacts, result: Any) -> None:
    facts.functions.extend(result.functions)
    facts.classes.extend(result.classes)
    facts.routes.extend(result.routes)
    facts.sources.extend(result.sources)
    facts.sinks.extend(result.sinks)
    facts.sanitizers.extend(result.sanitizers)
    facts.call_sites.extend(result.call_sites)
    facts.data_flows.extend(result.data_flows)
    facts.control_flows.extend(result.control_flows)


def _record_typescript_compiler_diagnostic(
    diagnostics: dict[str, Any],
    path: str,
    item: dict[str, Any],
) -> None:
    compiler = diagnostics["typescript_compiler"]
    compiler["attempted_files"] += 1
    status = str(item.get("status") or "unknown")[:80]
    compiler["statuses"][status] = int(compiler["statuses"].get(status) or 0) + 1
    if item.get("used"):
        compiler["ast_files"] += 1
        compiler["available"] = True
    else:
        compiler["fallback_files"] += 1
        if status in {"node_not_found", "typescript_not_found", "disabled", "bridge_missing"} and compiler["available"] is None:
            compiler["available"] = False
    if item.get("version"):
        compiler["version"] = str(item["version"])[:80]
    if len(compiler["files"]) < 250:
        compiler["files"].append(
            {
                "path": path,
                "status": status,
                "used": bool(item.get("used")),
                "fallback": bool(item.get("fallback")),
                "reason": str(item.get("reason") or "")[:600],
            }
        )


def _record_native_ast_diagnostic(
    diagnostics: dict[str, Any],
    path: str,
    language: str,
    item: dict[str, Any],
) -> None:
    native = diagnostics["native_ast"]
    native["attempted_files"] += 1
    per_language = native["languages"].setdefault(
        language,
        {"available": None, "attempted_files": 0, "ast_files": 0, "fallback_files": 0, "statuses": {}},
    )
    per_language["attempted_files"] += 1
    status = str(item.get("status") or "unknown")[:80]
    per_language["statuses"][status] = int(per_language["statuses"].get(status) or 0) + 1
    if item.get("used"):
        per_language["ast_files"] += 1
        per_language["available"] = True
        native["ast_files"] += 1
    else:
        per_language["fallback_files"] += 1
        native["fallback_files"] += 1
        if status in {"javac_not_found", "java_not_found", "go_not_found", "bridge_missing"} and per_language["available"] is None:
            per_language["available"] = False
    if len(native["files"]) < 250:
        native["files"].append(
            {
                "path": path,
                "language": language,
                "status": status,
                "used": bool(item.get("used")),
                "fallback": bool(item.get("fallback")),
                "reason": str(item.get("reason") or "")[:600],
            }
        )


def _new_scan_diagnostics() -> dict[str, Any]:
    return {
        "max_indexed_files": MAX_INDEXED_FILES,
        "max_source_file_bytes": DEFAULT_MAX_SOURCE_FILE_BYTES,
        "discovered_source_files": 0,
        "indexed_files": 0,
        "analyzed_files": 0,
        "ast_files": 0,
        "heuristic_files": 0,
        "fallback_files": 0,
        "skipped_files": 0,
        "error_files": 0,
        "language_frontend_files": 0,
        "language_frontends": {},
        "frontend_errors": [],
        "typescript_compiler": {
            "available": None,
            "attempted_files": 0,
            "ast_files": 0,
            "fallback_files": 0,
            "version": None,
            "statuses": {},
            "files": [],
        },
        "native_ast": {"attempted_files": 0, "ast_files": 0, "fallback_files": 0, "languages": {}, "files": []},
        "truncated": False,
        "truncated_files": 0,
        "skipped": [],
        "errors": [],
        "analysis_coverage": {},
        "analysis_complete": True,
    }


def _finalize_scan_diagnostics(diagnostics: dict[str, Any]) -> None:
    discovered = int(diagnostics.get("discovered_source_files") or 0)
    analyzed = int(diagnostics.get("analyzed_files") or 0)
    diagnostics["analysis_complete"] = not bool(diagnostics.get("truncated")) and int(diagnostics.get("error_files") or 0) == 0
    diagnostics["analysis_coverage"] = {
        "analyzed_files": analyzed,
        "ast_files": int(diagnostics.get("ast_files") or 0),
        "heuristic_files": int(diagnostics.get("heuristic_files") or 0),
        "fallback_files": int(diagnostics.get("fallback_files") or 0),
        "skipped_files": int(diagnostics.get("skipped_files") or 0),
        "error_files": int(diagnostics.get("error_files") or 0),
        "percent_of_discovered": round((analyzed / discovered) * 100, 2) if discovered else 100.0,
    }


def _record_skipped(diagnostics: dict[str, Any], path: str, reason: str) -> None:
    diagnostics["skipped_files"] += 1
    diagnostics["skipped"].append({"path": path, "reason": reason})


def _is_within_repo(path: Path, repo: Path) -> bool:
    try:
        path.relative_to(repo)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class _SourceSnapshot:
    content: bytes | None
    content_hash: str
    size: int
    lines: int
    mtime_ns: int
    stable: bool


def _file_signature(stat: os.stat_result) -> tuple[int, int]:
    return stat.st_size, stat.st_mtime_ns


def _read_source_snapshot(
    path: Path,
    *,
    include_content: bool,
    max_file_bytes: int,
) -> tuple[_SourceSnapshot | None, str | None]:
    """Read a bounded source snapshot and hash it without trusting a pre-read stat.

    Files can change while an upload or a checkout is in progress.  A second
    attempt gives active files a chance to settle; if they still change we return
    the final coherent read but label it non-cacheable rather than silently using
    a hash for different bytes.
    """

    latest: _SourceSnapshot | None = None
    for _attempt in range(2):
        try:
            before = path.stat()
            if before.st_size > max_file_bytes:
                return None, f"larger than {max_file_bytes} bytes"
            digest = hashlib.sha256()
            parts: list[bytes] | None = [] if include_content else None
            byte_count = 0
            newline_count = 0
            with path.open("rb") as handle:
                while chunk := handle.read(64 * 1024):
                    byte_count += len(chunk)
                    if byte_count > max_file_bytes:
                        return None, f"larger than {max_file_bytes} bytes"
                    digest.update(chunk)
                    newline_count += chunk.count(b"\n")
                    if parts is not None:
                        parts.append(chunk)
            after = path.stat()
        except OSError as exc:
            return None, f"file read failed: {exc}"
        snapshot = _SourceSnapshot(
            content=b"".join(parts) if parts is not None else None,
            content_hash=digest.hexdigest(),
            size=byte_count,
            lines=0 if byte_count == 0 else newline_count + 1,
            mtime_ns=after.st_mtime_ns,
            stable=_file_signature(before) == _file_signature(after),
        )
        if snapshot.stable:
            return snapshot, None
        latest = snapshot
    return latest, None


def _source_snapshot_is_current(source_file: SourceFile) -> bool:
    if source_file.snapshot_size is None or source_file.snapshot_mtime_ns is None:
        return False
    try:
        stat = source_file.absolute_path.stat()
    except OSError:
        return False
    return stat.st_size == source_file.snapshot_size and stat.st_mtime_ns == source_file.snapshot_mtime_ns


def load_source_file(
    source_file: SourceFile,
    *,
    max_file_bytes: int | None = None,
) -> tuple[SourceFile | None, str | None]:
    """Materialise one descriptor on demand, never retaining other file text."""

    if source_file.content_loaded:
        content_hash = source_file.content_hash or sha256_text(source_file.content)
        return replace(source_file, content_hash=content_hash), None
    snapshot, error = _read_source_snapshot(
        source_file.absolute_path,
        include_content=True,
        max_file_bytes=max_file_bytes if max_file_bytes is not None else source_file_limit_bytes(),
    )
    if snapshot is None:
        return None, error
    content = (snapshot.content or b"").decode("utf-8", errors="replace")
    indexed = replace(source_file.file, bytes=snapshot.size, lines=line_count(content))
    return (
        replace(
            source_file,
            file=indexed,
            content=content,
            lines=content.splitlines(),
            content_hash=snapshot.content_hash,
            snapshot_size=snapshot.size,
            snapshot_mtime_ns=snapshot.mtime_ns,
            snapshot_stable=snapshot.stable,
            content_loaded=True,
        ),
        None,
    )


def index_source_files(
    repo_path: Path,
    diagnostics: dict[str, Any] | None = None,
    *,
    load_content: bool = True,
    max_files: int | None = MAX_INDEXED_FILES,
    max_file_bytes: int | None = None,
) -> list[SourceFile]:
    """Discover source files deterministically.

    The historic eager behaviour remains the default for extractor callers.  The
    repository scanner passes ``load_content=False`` and an unbounded limit so a
    large project is analysed file-by-file rather than being silently truncated
    or retained wholesale in memory.
    """

    diagnostics = diagnostics if diagnostics is not None else _new_scan_diagnostics()
    diagnostics["max_indexed_files"] = max_files
    max_file_bytes = max_file_bytes if max_file_bytes is not None else source_file_limit_bytes()
    diagnostics["max_source_file_bytes"] = max_file_bytes
    repo_path = repo_path.resolve(strict=True)
    source_files: list[SourceFile] = []

    def record_walk_error(exc: OSError) -> None:
        raw_path = Path(exc.filename) if exc.filename else repo_path
        try:
            path = normalize_path(raw_path.relative_to(repo_path))
        except ValueError:
            path = str(raw_path)
        _record_skipped(diagnostics, path, f"directory walk failed: {exc}")
        diagnostics["errors"].append({"path": path, "stage": "walk", "error": str(exc)})
        diagnostics["error_files"] += 1

    for root, dirs, files in os.walk(repo_path, followlinks=False, onerror=record_walk_error):
        root_path = Path(root)
        retained_dirs: list[str] = []
        for dirname in sorted(dirs):
            child = root_path / dirname
            relative = normalize_path(child.relative_to(repo_path))
            if should_skip_dir(dirname):
                continue
            if child.is_symlink():
                _record_skipped(diagnostics, relative, "symlink directory")
                continue
            try:
                resolved = child.resolve(strict=True)
            except OSError as exc:
                _record_skipped(diagnostics, relative, f"directory resolution failed: {exc}")
                diagnostics["errors"].append({"path": relative, "stage": "directory", "error": str(exc)})
                diagnostics["error_files"] += 1
                continue
            if not _is_within_repo(resolved, repo_path):
                _record_skipped(diagnostics, relative, "resolved directory escapes repository")
                continue
            retained_dirs.append(dirname)
        dirs[:] = retained_dirs

        for name in sorted(files):
            absolute = Path(root) / name
            language = language_for_path(absolute)
            if not language:
                continue
            diagnostics["discovered_source_files"] += 1
            relative = normalize_path(absolute.relative_to(repo_path))
            if absolute.is_symlink():
                _record_skipped(diagnostics, relative, "symlink file")
                continue
            try:
                resolved = absolute.resolve(strict=True)
                if not _is_within_repo(resolved, repo_path):
                    _record_skipped(diagnostics, relative, "resolved file escapes repository")
                    continue
                stat = resolved.stat()
            except OSError as exc:
                _record_skipped(diagnostics, relative, f"file metadata failed: {exc}")
                diagnostics["errors"].append({"path": relative, "stage": "index", "error": str(exc)})
                diagnostics["error_files"] += 1
                continue
            if max_files is not None and len(source_files) >= max_files:
                diagnostics["truncated"] = True
                diagnostics["truncated_files"] += 1
                continue
            indexed = IndexedFile(
                id=stable_id("file", relative, 1, name),
                path=relative,
                language=language,
                bytes=stat.st_size,
                lines=0,
                parsed_by="heuristic",
                skipped_reason=None,
            )
            skipped_reason = skip_source_reason(name)
            if skipped_reason:
                _record_skipped(diagnostics, relative, skipped_reason)
                source_files.append(
                    SourceFile(
                        file=IndexedFile(
                            id=indexed.id,
                            path=relative,
                            language=language,
                            bytes=stat.st_size,
                            lines=0,
                            parsed_by="fallback",
                            skipped_reason=skipped_reason,
                        ),
                        absolute_path=resolved,
                        content="",
                        lines=[],
                        content_loaded=False,
                    )
                )
                continue
            if stat.st_size > max_file_bytes:
                reason = f"larger than {max_file_bytes} bytes"
                _record_skipped(diagnostics, relative, reason)
                source_files.append(
                    SourceFile(
                        file=IndexedFile(
                            id=indexed.id,
                            path=relative,
                            language=language,
                            bytes=stat.st_size,
                            lines=0,
                            parsed_by="fallback",
                            skipped_reason=reason,
                        ),
                        absolute_path=resolved,
                        content="",
                        lines=[],
                        content_loaded=False,
                    )
                )
                continue
            snapshot, read_error = _read_source_snapshot(
                resolved,
                include_content=load_content,
                max_file_bytes=max_file_bytes,
            )
            if snapshot is None:
                reason = read_error or "file read failed"
                _record_skipped(diagnostics, relative, reason)
                if not reason.startswith("larger than"):
                    diagnostics["errors"].append({"path": relative, "stage": "read", "error": reason})
                    diagnostics["error_files"] += 1
                source_files.append(
                    SourceFile(
                        file=replace(indexed, parsed_by="fallback", skipped_reason=reason, analysis_error=reason),
                        absolute_path=resolved,
                        content="",
                        lines=[],
                        content_loaded=False,
                    )
                )
                continue
            content = (snapshot.content or b"").decode("utf-8", errors="replace") if load_content else ""
            lines = content.splitlines() if load_content else []
            source_files.append(
                SourceFile(
                    file=IndexedFile(
                        id=indexed.id,
                        path=relative,
                        language=language,
                        bytes=snapshot.size,
                        lines=line_count(content) if load_content else snapshot.lines,
                        parsed_by="heuristic",
                        skipped_reason=None,
                    ),
                    absolute_path=resolved,
                    content=content,
                    lines=lines,
                    content_hash=snapshot.content_hash,
                    snapshot_size=snapshot.size,
                    snapshot_mtime_ns=snapshot.mtime_ns,
                    snapshot_stable=snapshot.stable,
                    content_loaded=load_content,
                )
            )
            if not snapshot.stable:
                diagnostics.setdefault("snapshot_unstable_files", 0)
                diagnostics["snapshot_unstable_files"] += 1
    diagnostics["indexed_files"] = len(source_files)
    _finalize_scan_diagnostics(diagnostics)
    return source_files


def should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith("workspace-")


def language_for_path(path: Path) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def skip_source_reason(name: str) -> str | None:
    lowered = name.lower()
    if any(lowered.endswith(suffix) for suffix in SKIP_SOURCE_SUFFIXES):
        return "minified generated asset"
    return None


def extract_functions(source_file: SourceFile) -> list[FunctionFact]:
    facts: list[FunctionFact] = []
    patterns = function_patterns(source_file.file.language)
    for idx, line in enumerate(source_file.lines, start=1):
        route_handler = detect_inline_route_handler(line, source_file.file.language)
        if route_handler:
            name, params = route_handler
            anchor = make_anchor(source_file, idx, find_block_end(source_file.lines, idx, source_file.file.language), name)
            facts.append(FunctionFact(id=stable_id("function", source_file.file.path, idx, name), name=name, anchor=anchor, params=params))
            continue
        for pattern in patterns:
            match = pattern.search(line)
            if not match:
                continue
            name = match.group("name")
            params = parse_params(match.groupdict().get("params", ""))
            anchor = make_anchor(source_file, idx, find_block_end(source_file.lines, idx, source_file.file.language), name)
            facts.append(FunctionFact(id=stable_id("function", source_file.file.path, idx, name), name=name, anchor=anchor, params=params))
            break
    return facts


def function_patterns(language: str) -> list[re.Pattern[str]]:
    common = [
        re.compile(r"\bfunction\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)"),
        re.compile(r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?(?P<params>[^)=]*)\)?\s*=>"),
        re.compile(
            r"^\s*(?:public|private|protected|static|async\s+)*[A-Za-z_$][\w$<>,\s\[\]]+\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)"
        ),
    ]
    if language == "python":
        return [re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?:->\s*[^:]+)?\s*:")]
    if language == "go":
        return [re.compile(r"^\s*func\s+(?:\([^)]+\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)"), *common]
    return common


def detect_inline_route_handler(line: str, language: str) -> tuple[str, list[str]] | None:
    if language not in {"javascript", "typescript"}:
        return None
    route = detect_route(line)
    if not route:
        return None
    method, route_path, _framework = route
    arrow = re.search(r",\s*(?:async\s+)?\(?(?P<params>[^)=]*)\)?\s*=>", line)
    if arrow:
        return route_handler_name(method, route_path), parse_params(arrow.group("params"))
    function = re.search(r",\s*(?:async\s+)?function\s*(?:[A-Za-z_$][\w$]*)?\s*\((?P<params>[^)]*)\)", line)
    if function:
        return route_handler_name(method, route_path), parse_params(function.group("params"))
    return None


def route_handler_name(method: str, route_path: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", route_path.strip("/")) or "root"
    return f"route_{method.lower()}_{cleaned.lower()}"


def extract_classes(source_file: SourceFile) -> list[ClassFact]:
    facts: list[ClassFact] = []
    pattern = re.compile(r"\b(class|interface|struct|enum)\s+(?P<name>[A-Za-z_$][\w$]*)\b")
    for idx, line in enumerate(source_file.lines, start=1):
        match = pattern.search(line)
        if not match:
            continue
        name = match.group("name")
        anchor = make_anchor(source_file, idx, find_block_end(source_file.lines, idx, source_file.file.language), name)
        facts.append(ClassFact(id=stable_id("class", source_file.file.path, idx, name), name=name, anchor=anchor))
    return facts


def extract_routes(source_file: SourceFile) -> list[RouteFact]:
    routes: list[RouteFact] = []
    for idx, line in enumerate(source_file.lines, start=1):
        route = detect_route(line)
        if not route:
            continue
        method, route_path, framework = route
        routes.append(
            RouteFact(
                id=stable_id("route", source_file.file.path, idx, f"{method}:{route_path}"),
                method=method,
                path=route_path,
                framework=framework,
                anchor=make_anchor(source_file, idx, idx, f"{method} {route_path}"),
            )
        )
    return routes


def detect_route(line: str) -> tuple[str, str, str] | None:
    express = re.search(
        r"\b(?:app|router|server)\.(?P<method>get|post|put|patch|delete|options|head|all)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]", line, re.I
    )
    if express:
        return express.group("method").upper(), express.group("path"), "express-like"
    flask = re.search(r"@(?:app|router|bp)\.route\(\s*['\"](?P<path>[^'\"]+)['\"](?:.*methods\s*=\s*\[(?P<methods>[^\]]+)])?", line, re.I)
    if flask:
        methods = parse_route_methods(flask.groupdict().get("methods") or "")
        return (",".join(methods) if methods else "GET"), flask.group("path"), "flask-like"
    spring = re.search(
        r"@(?P<method>Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?['\"](?P<path>[^'\"]+)['\"]", line, re.I
    )
    if spring:
        raw_method = spring.group("method")
        return ("ANY" if raw_method.lower() == "request" else raw_method.upper()), spring.group("path"), "spring-like"
    go = re.search(
        r"\b(?:[A-Za-z_][\w.]*\.)?(?P<method>HandleFunc|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
        line,
    )
    if go:
        raw_method = go.group("method")
        return ("ANY" if raw_method == "HandleFunc" else raw_method.upper()), go.group("path"), "go-router-like"
    return None


def parse_route_methods(raw: str) -> list[str]:
    if not raw:
        return []
    methods: list[str] = []
    for match in re.finditer(r"[A-Z]+", raw.upper()):
        method = match.group(0)
        if method and method not in methods:
            methods.append(method)
    return methods


def rule_matching_line(line: str, language: str, rule_kind: str) -> str:
    keep_literal_content = rule_kind == "html_output"
    return strip_literals_and_comments(line, language, keep_literal_content=keep_literal_content)


def strip_literals_and_comments(line: str, language: str, *, keep_literal_content: bool = False) -> str:
    out: list[str] = []
    quote: str | None = None
    escaped = False
    idx = 0
    lower_language = language.lower()
    while idx < len(line):
        char = line[idx]
        next_char = line[idx + 1] if idx + 1 < len(line) else ""
        if quote:
            if keep_literal_content:
                out.append(char)
            elif char == quote:
                out.append(char)
            else:
                out.append(" ")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            idx += 1
            continue

        if char in {"'", '"', "`"}:
            quote = char
            out.append(char)
            idx += 1
            continue
        if lower_language in HASH_COMMENT_LANGUAGES and char == "#":
            break
        if lower_language in C_STYLE_COMMENT_LANGUAGES and char == "/" and next_char in {"/", "*"}:
            break
        out.append(char)
        idx += 1
    return "".join(out)


def extract_sources(source_file: SourceFile, functions: list[FunctionFact] | None = None) -> list[SourceFact]:
    facts: list[SourceFact] = []
    file_functions = functions or []
    for idx, line in enumerate(source_file.lines, start=1):
        for rule in SOURCE_RULES:
            match_line = rule_matching_line(line, source_file.file.language, rule.kind)
            if not rule.pattern.search(match_line):
                continue
            expr = line.strip()[:240]
            assignment = parse_assignment(line.strip())
            enclosing = enclosing_function_for_line(file_functions, idx)
            source_outputs: list[str] = []
            source_inputs = extract_identifiers(expr)
            if assignment:
                assignment_match_text = rule_matching_line(assignment[1], source_file.file.language, rule.kind)
                if rule.pattern.search(assignment_match_text):
                    source_outputs = [assignment[0]]
                    source_inputs = extract_identifiers(assignment[1])
            facts.append(
                SourceFact(
                    id=stable_id("source", source_file.file.path, idx, f"{rule.kind}:{expr}"),
                    kind=rule.kind,
                    expression=expr,
                    anchor=make_anchor(source_file, idx, idx, rule.kind),
                    confidence=rule.confidence,
                    variables=source_outputs,
                    input_variables=source_inputs,
                    enclosing_function_id=enclosing.id if enclosing else None,
                    analysis_method="heuristic",
                )
            )
    return facts


def extract_sinks(source_file: SourceFile, functions: list[FunctionFact] | None = None) -> list[SinkFact]:
    facts: list[SinkFact] = []
    file_functions = functions or []
    for idx, line in enumerate(source_file.lines, start=1):
        for rule in SINK_RULES:
            match_line = rule_matching_line(line, source_file.file.language, rule.kind)
            if not rule.pattern.search(match_line):
                continue
            expr = line.strip()[:240]
            enclosing = enclosing_function_for_line(file_functions, idx)
            taxonomy_id, cwe_ids = sink_taxonomy(rule.kind)
            facts.append(
                SinkFact(
                    id=stable_id("sink", source_file.file.path, idx, f"{rule.kind}:{expr}"),
                    kind=rule.kind,
                    vuln_class=rule.vuln_class,
                    expression=expr,
                    anchor=make_anchor(source_file, idx, idx, rule.kind),
                    confidence=rule.confidence,
                    variables=extract_identifiers(match_line),
                    enclosing_function_id=enclosing.id if enclosing else None,
                    analysis_method="heuristic",
                    taxonomy_id=taxonomy_id,
                    cwe_ids=cwe_ids,
                )
            )
    return facts


def extract_sanitizers(source_file: SourceFile, functions: list[FunctionFact] | None = None) -> list[SanitizerFact]:
    facts: list[SanitizerFact] = []
    file_functions = functions or []
    for idx, line in enumerate(source_file.lines, start=1):
        for rule in SANITIZER_RULES:
            match_line = rule_matching_line(line, source_file.file.language, rule.kind)
            if not rule.pattern.search(match_line):
                continue
            expr = line.strip()[:240]
            assignment = parse_assignment(line.strip())
            enclosing = enclosing_function_for_line(file_functions, idx)
            sanitizer_outputs: list[str] = []
            sanitizer_inputs = extract_identifiers(expr)
            if assignment:
                assignment_match_text = rule_matching_line(assignment[1], source_file.file.language, rule.kind)
                if rule.pattern.search(assignment_match_text):
                    sanitizer_outputs = [assignment[0]]
                    sanitizer_inputs = extract_identifiers(assignment[1])
            facts.append(
                SanitizerFact(
                    id=stable_id("sanitizer", source_file.file.path, idx, f"{rule.kind}:{expr}"),
                    kind=rule.kind,
                    expression=expr,
                    anchor=make_anchor(source_file, idx, idx, rule.kind),
                    confidence=rule.confidence,
                    variables=sanitizer_outputs,
                    input_variables=sanitizer_inputs,
                    enclosing_function_id=enclosing.id if enclosing else None,
                    analysis_method="heuristic",
                    applies_to_sink_kinds=sanitizer_sink_kinds(rule.kind),
                )
            )
    return facts


def sink_taxonomy(kind: str) -> tuple[str | None, list[str]]:
    mapping = {
        "raw_sql": ("sql_injection", ["CWE-89"]),
        "command_execution": ("command_injection", ["CWE-78"]),
        "file_path": ("path_traversal", ["CWE-22"]),
        "deserialization": ("unsafe_deserialization", ["CWE-502"]),
        "html_output": ("cross_site_scripting", ["CWE-79"]),
        "external_request": ("server_side_request_forgery", ["CWE-918"]),
        "auth_primitive": ("authentication_failure", ["CWE-287"]),
        "authorization_decision": ("authorization_failure", ["CWE-862"]),
    }
    return mapping.get(kind, (None, []))


def sanitizer_sink_kinds(kind: str) -> list[str]:
    return {
        "parameterized_query": ["raw_sql"],
        "html_encoding": ["html_output"],
        "url_validation": ["external_request"],
        "type_validation": ["raw_sql", "command_execution", "file_path", "external_request"],
        "authorization_guard": ["authorization_decision"],
    }.get(kind, [])


def extract_call_sites(source_file: SourceFile, functions: list[FunctionFact]) -> list[CallSiteFact]:
    facts: list[CallSiteFact] = []
    file_functions = [fn for fn in functions if fn.anchor.file == source_file.file.path]
    for idx, line in enumerate(source_file.lines, start=1):
        enclosing = next((fn for fn in file_functions if fn.anchor.start_line <= idx <= fn.anchor.end_line), None)
        parsed_calls = parse_call_arguments(line)
        call_arguments = {name: args for name, args in parsed_calls}
        for callee in extract_call_names(line):
            args = call_arguments.get(callee, [])
            facts.append(
                CallSiteFact(
                    id=stable_id("callsite", source_file.file.path, idx, callee),
                    callee=callee,
                    anchor=make_anchor(source_file, idx, idx, callee),
                    enclosing_function_id=enclosing.id if enclosing else None,
                    argument_sources=[extract_identifiers(arg) for arg in args],
                    analysis_method="heuristic",
                )
            )
    return facts


def extract_data_flows(source_file: SourceFile, functions: list[FunctionFact]) -> list[DataFlowFact]:
    facts: list[DataFlowFact] = []
    file_functions = [fn for fn in functions if fn.anchor.file == source_file.file.path]
    for idx, line in enumerate(source_file.lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        enclosing = enclosing_function_for_line(file_functions, idx)
        assignment = parse_assignment(stripped)
        if assignment:
            target, expr = assignment
            facts.append(
                DataFlowFact(
                    id=stable_id("dfg", source_file.file.path, idx, f"assignment:{target}:{expr}"),
                    kind="assignment",
                    target=target,
                    sources=extract_identifiers(expr),
                    expression=expr[:240],
                    anchor=make_anchor(source_file, idx, idx, target),
                    enclosing_function_id=enclosing.id if enclosing else None,
                )
            )
            continue
        return_expr = parse_return(stripped)
        if return_expr is not None:
            facts.append(
                DataFlowFact(
                    id=stable_id("dfg", source_file.file.path, idx, f"return:{return_expr}"),
                    kind="return",
                    target=None,
                    sources=extract_identifiers(return_expr),
                    expression=return_expr[:240],
                    anchor=make_anchor(source_file, idx, idx, "return"),
                    enclosing_function_id=enclosing.id if enclosing else None,
                )
            )
            continue
        for call_name, args in parse_call_arguments(stripped):
            facts.append(
                DataFlowFact(
                    id=stable_id("dfg", source_file.file.path, idx, f"call:{call_name}:{','.join(args)}"),
                    kind="call_argument",
                    target=call_name,
                    sources=[identifier for arg in args for identifier in extract_identifiers(arg)],
                    expression=stripped[:240],
                    anchor=make_anchor(source_file, idx, idx, call_name),
                    enclosing_function_id=enclosing.id if enclosing else None,
                )
            )
    return facts


def extract_control_flows(source_file: SourceFile, functions: list[FunctionFact]) -> list[ControlFlowFact]:
    facts: list[ControlFlowFact] = []
    file_functions = [fn for fn in functions if fn.anchor.file == source_file.file.path]
    for idx, line in enumerate(source_file.lines, start=1):
        stripped = line.strip()
        parsed = parse_control_flow(stripped)
        if not parsed:
            continue
        kind, condition = parsed
        enclosing = enclosing_function_for_line(file_functions, idx)
        facts.append(
            ControlFlowFact(
                id=stable_id("cfg", source_file.file.path, idx, f"{kind}:{condition}"),
                kind=kind,
                condition=condition[:240],
                variables=extract_identifiers(condition),
                anchor=make_anchor(source_file, idx, idx, kind),
                enclosing_function_id=enclosing.id if enclosing else None,
            )
        )
    return facts


def enclosing_function_for_line(functions: list[FunctionFact], line_no: int) -> FunctionFact | None:
    return next((fn for fn in functions if fn.anchor.start_line <= line_no <= fn.anchor.end_line), None)


def parse_assignment(line: str) -> tuple[str, str] | None:
    if re.match(r"^(?:if|elif|else\s+if|for|while|switch|catch|return|throw)\b", line):
        return None
    patterns = [
        r"^(?:const|let|var)\s+(?P<target>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>.+?);?$",
        r"^(?P<target>[A-Za-z_$][\w$]*)\s*:=\s*(?P<expr>.+)$",
        r"^(?P<target>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>[^=].*?);?$",
        r"^(?:[A-Za-z_$][\w$<>,\[\].?]+\s+)+(?P<target>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>.+?);?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if not match:
            continue
        expr = match.group("expr").strip()
        if not expr:
            return None
        return match.group("target"), expr
    return None


def parse_return(line: str) -> str | None:
    match = re.search(r"^return\b\s*(?P<expr>.*?);?$", line)
    if not match:
        return None
    return match.group("expr").strip()


def parse_call_arguments(line: str) -> list[tuple[str, list[str]]]:
    calls: list[tuple[str, list[str]]] = []
    for match in re.finditer(r"\b(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\((?P<args>[^()]*)\)", line):
        name = match.group("name")
        last = name.split(".")[-1]
        if last in FUNCTION_KEYWORDS:
            continue
        args = [arg.strip() for arg in split_args(match.group("args")) if arg.strip()]
        calls.append((name, args))
    return calls


def split_args(raw: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    quote: str | None = None
    depth = 0
    for char in raw:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        args.append("".join(current).strip())
    return args


def parse_control_flow(line: str) -> tuple[str, str] | None:
    patterns = [
        ("if", r"^if\s*(?:\((?P<condition>.*)\)|(?P<py_condition>.*):)$"),
        ("elif", r"^elif\s+(?P<condition>.*):$"),
        ("for", r"^for\s*(?:\((?P<condition>.*)\)|(?P<py_condition>.*):)$"),
        ("while", r"^while\s*(?:\((?P<condition>.*)\)|(?P<py_condition>.*):)$"),
        ("switch", r"^switch\s*\((?P<condition>.*)\)"),
        ("case", r"^case\s+(?P<condition>.*):$"),
        ("catch", r"^catch\s*\((?P<condition>.*)\)"),
    ]
    if line in {"else:", "else {"} or line.startswith("else "):
        return "else", ""
    for kind, pattern in patterns:
        match = re.search(pattern, line)
        if not match:
            continue
        condition = (match.groupdict().get("condition") or match.groupdict().get("py_condition") or "").strip()
        return kind, condition
    return None


def extract_identifiers(expr: str) -> list[str]:
    expr = strip_strings_and_comments(expr)
    identifiers: list[str] = []
    for match in re.finditer(r"\b[A-Za-z_$][\w$]*\b", expr):
        name = match.group(0)
        if name in FUNCTION_KEYWORDS or name in {"true", "false", "null", "None", "return", "await"}:
            continue
        identifiers.append(name)
    return list(dict.fromkeys(identifiers))


def extract_call_names(line: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r"\b(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(", line):
        name = match.group("name")
        last = name.split(".")[-1]
        if last in FUNCTION_KEYWORDS:
            continue
        names.append(name)
    return list(dict.fromkeys(names))


def make_anchor(source_file: SourceFile, start_line: int, end_line: int, symbol: str | None = None) -> CodeAnchor:
    snippet = "\n".join(source_file.lines[start_line - 1 : end_line])
    return CodeAnchor(
        file=source_file.file.path,
        start_line=start_line,
        end_line=end_line,
        snippet_hash=sha256_text(snippet)[:16],
        symbol=symbol,
    )


def parse_params(raw: str) -> list[str]:
    out: list[str] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        item = re.sub(r"=.*$", "", item).strip()
        item = re.sub(r"^(\.\.\.)?", "", item).strip()
        item = re.split(r"[:\s]", item)[0]
        if item:
            out.append(item)
    return out


def find_block_end(lines: list[str], start_line: int, language: str) -> int:
    start_index = start_line - 1
    if language == "python":
        first_line = lines[start_index] if start_index < len(lines) else ""
        base_indent = len(first_line) - len(first_line.lstrip())
        for idx in range(start_index + 1, len(lines)):
            line = lines[idx]
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent:
                return idx
        return len(lines)
    depth = 0
    seen_brace = False
    for idx in range(start_index, len(lines)):
        line = strip_strings_and_comments(lines[idx])
        for char in line:
            if char == "{":
                depth += 1
                seen_brace = True
            elif char == "}":
                depth -= 1
        if seen_brace and depth <= 0:
            return idx + 1
    return min(len(lines), start_line + 80)


def strip_strings_and_comments(line: str) -> str:
    line = re.sub(r"//.*$", "", line)
    line = re.sub(r"#.*$", "", line)
    return re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", '""', line)
