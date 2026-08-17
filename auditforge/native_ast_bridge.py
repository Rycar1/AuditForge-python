"""Optional Java and Go native-parser frontends.

The bridge deliberately delegates parsing to the language's own toolchain:
the JDK compiler tree API for Java and ``go/parser`` for Go.  When a required
toolchain is unavailable, callers receive an explicit diagnostic and keep the
existing heuristic frontend.  Syntax/dataflow facts emitted by the native AST
are marked ``ast``; framework source/sink modelling remains visibly heuristic
until it has corresponding type-aware models.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

from .java_go_analysis import analyze_go, analyze_java
from .language_frontend import LanguageAnalysisResult, LanguageFactBuilder, dedupe_strings
from .utils import sha256_text

BRIDGE_TIMEOUT_SECONDS = 20
MAX_BRIDGE_OUTPUT_BYTES = 12 * 1024 * 1024
MAX_JAVA_BATCH_OUTPUT_BYTES = 24 * 1024 * 1024
JAVA_BATCH_MAX_FILES = 48
JAVA_BATCH_MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_NATIVE_EVENTS = 30000
_JAVA_BRIDGE_COMMANDS: dict[str, list[str]] = {}


def analyze_native_with_ast(source_file: Any) -> tuple[LanguageAnalysisResult | None, dict[str, Any]]:
    """Return hybrid native-AST facts for a Java or Go source file.

    The result has compiler-backed structural facts and the existing explicit
    framework semantics.  It never silently relabels heuristic source/sink
    recognition as AST-derived evidence.
    """

    language = str(source_file.file.language).lower()
    command, unavailable = _bridge_command(language)
    if command is None:
        return None, _diagnostic(unavailable or "toolchain_not_found", "native parser toolchain is unavailable")
    bridge_name = "AuditForgeJavaAstBridge.java" if language == "java" else "auditforge_go_ast_bridge.go"
    bridge_path = Path(__file__).with_name(bridge_name)
    if not bridge_path.is_file():
        return None, _diagnostic("bridge_missing", f"bundled {language} AST bridge is missing")
    command = _java_bridge_command(command, bridge_path) if language == "java" else [*command, str(bridge_path)]
    try:
        completed = subprocess.run(
            command,
            input=str(source_file.content),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=BRIDGE_TIMEOUT_SECONDS,
            check=False,
            cwd=str(bridge_path.parent),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return None, _diagnostic("timeout", f"{language} native AST bridge exceeded {BRIDGE_TIMEOUT_SECONDS}s")
    except OSError as exc:
        return None, _diagnostic("bridge_error", f"{type(exc).__name__}: {exc}")

    stdout = completed.stdout or ""
    if len(stdout.encode("utf-8", errors="replace")) > MAX_BRIDGE_OUTPUT_BYTES:
        return None, _diagnostic("invalid_output", "native AST bridge output exceeded the safety limit")
    if completed.returncode:
        reason = (completed.stderr or stdout or f"toolchain exited with status {completed.returncode}").strip()
        return None, _diagnostic("bridge_error", reason[:1200])
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return None, _diagnostic("invalid_output", f"native AST bridge returned invalid JSON: {exc}")
    if not isinstance(payload, dict):
        return None, _diagnostic("invalid_output", "native AST bridge response must be an object")
    status = _text(payload.get("status"), 80) or "invalid_output"
    if status != "ok":
        return None, _diagnostic(status, _text(payload.get("reason"), 1200) or status)
    return _native_result_from_payload(source_file, payload, language=language)


def analyze_java_batch_with_ast(source_files: list[Any]) -> dict[str, tuple[LanguageAnalysisResult | None, dict[str, Any]]]:
    """Parse Java files in bounded batches while preserving single-file fallback.

    One source-file-mode JVM startup per Java file is disproportionately costly
    on enterprise repositories.  A batch uses the same bridge facts and keeps
    every file eligible for the existing one-file path when a batch is partial
    or malformed, so it never trades coverage for throughput.
    """

    java_files = [item for item in source_files if str(item.file.language).lower() == "java"]
    if not java_files:
        return {}
    command, unavailable = _bridge_command("java")
    if command is None:
        diagnostic = _diagnostic(unavailable or "toolchain_not_found", "Java native parser toolchain is unavailable")
        return {item.file.path: (None, diagnostic) for item in java_files}
    bridge_path = Path(__file__).with_name("AuditForgeJavaAstBridge.java")
    if not bridge_path.is_file():
        diagnostic = _diagnostic("bridge_missing", "bundled Java AST bridge is missing")
        return {item.file.path: (None, diagnostic) for item in java_files}

    results: dict[str, tuple[LanguageAnalysisResult | None, dict[str, Any]]] = {}
    bridge_command = _java_bridge_command(command, bridge_path)
    session = _JavaBridgeSession([*bridge_command, "--server"], bridge_path.parent)
    try:
        for batch in _java_batches(java_files):
            batch_results, failure = session.run_batch(batch)
            if failure:
                # A persistent JVM is a throughput optimisation.  Its failure
                # must not suppress the established one-shot batch path.
                batch_results, fallback_failure = _run_java_batch([*bridge_command, "--batch"], batch, bridge_path.parent)
                failure = fallback_failure or failure
            for source_file in batch:
                payload = batch_results.get(source_file.file.path)
                if payload is not None:
                    results[source_file.file.path] = _native_result_from_payload(source_file, payload, language="java", mode="batch")
                    continue
                # Batch execution is an optimization only. Fall back to the former
                # single-file bridge for every absent result to retain coverage.
                fallback_result, fallback_diagnostic = analyze_native_with_ast(source_file)
                if failure:
                    fallback_diagnostic = {**fallback_diagnostic, "batch_fallback_reason": failure}
                results[source_file.file.path] = fallback_result, fallback_diagnostic
    finally:
        session.close()
    return results


def _native_result_from_payload(
    source_file: Any,
    payload: dict[str, Any],
    *,
    language: str,
    mode: str = "hybrid",
) -> tuple[LanguageAnalysisResult | None, dict[str, Any]]:
    status = _text(payload.get("status"), 80) or "invalid_output"
    if status != "ok":
        return None, _diagnostic(status, _text(payload.get("reason"), 1200) or status)
    try:
        structural = native_payload_to_result(source_file, payload)
    except (TypeError, ValueError, KeyError) as exc:
        return None, _diagnostic("invalid_output", f"native AST fact conversion failed: {exc}")

    heuristic = analyze_java(source_file) if language == "java" else analyze_go(source_file)
    result = _merge_structural_and_framework_facts(structural, heuristic)
    diagnostic = _diagnostic("ok", f"{language} native AST structural facts emitted")
    diagnostic.update({"language": language, "mode": mode, "facts": _fact_count(result)})
    return result, diagnostic


def _java_batches(source_files: list[Any]) -> list[list[Any]]:
    batches: list[list[Any]] = []
    current: list[Any] = []
    current_bytes = 0
    for source_file in source_files:
        source_bytes = len(str(source_file.content).encode("utf-8", errors="replace"))
        if current and (len(current) >= JAVA_BATCH_MAX_FILES or current_bytes + source_bytes > JAVA_BATCH_MAX_INPUT_BYTES):
            batches.append(current)
            current, current_bytes = [], 0
        current.append(source_file)
        current_bytes += source_bytes
    if current:
        batches.append(current)
    return batches


def _run_java_batch(command: list[str], source_files: list[Any], cwd: Path) -> tuple[dict[str, dict[str, Any]], str]:
    inputs, ids_to_path = _java_batch_input(source_files)
    try:
        completed = subprocess.run(
            command,
            input=inputs,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(BRIDGE_TIMEOUT_SECONDS, BRIDGE_TIMEOUT_SECONDS * len(source_files) // 8),
            check=False,
            cwd=str(cwd),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return {}, "Java batch AST bridge timed out"
    except OSError as exc:
        return {}, f"Java batch AST bridge error: {type(exc).__name__}: {exc}"

    return _parse_java_batch_output(completed.stdout or "", completed.returncode, completed.stderr or "", ids_to_path)


def _java_batch_input(source_files: list[Any]) -> tuple[str, dict[str, str]]:
    inputs: list[str] = []
    ids_to_path: dict[str, str] = {}
    for index, source_file in enumerate(source_files):
        identifier = str(index)
        ids_to_path[identifier] = source_file.file.path
        encoded = base64.b64encode(str(source_file.content).encode("utf-8", errors="replace")).decode("ascii")
        inputs.append(f"{identifier}\t{encoded}")
    return "\n".join(inputs) + "\n", ids_to_path


def _parse_java_batch_output(
    stdout: str,
    returncode: int,
    stderr: str,
    ids_to_path: dict[str, str],
) -> tuple[dict[str, dict[str, Any]], str]:
    if len(stdout.encode("utf-8", errors="replace")) > MAX_JAVA_BATCH_OUTPUT_BYTES:
        return {}, "Java batch AST bridge output exceeded the safety limit"
    if returncode:
        reason = (stderr or stdout or f"toolchain exited with status {returncode}").strip()
        return {}, reason[:1200]
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {}, f"Java batch AST bridge returned invalid JSON: {exc}"
    if not isinstance(payload, dict) or _text(payload.get("status"), 80) != "ok":
        return {}, _text(payload.get("reason"), 1200) or "Java batch AST bridge returned an invalid response"

    output: dict[str, dict[str, Any]] = {}
    for item in _objects(payload.get("files")):
        path = ids_to_path.get(_text(item.get("id"), 80))
        nested = item.get("payload")
        if path and isinstance(nested, dict):
            output[path] = nested
    return output, ""


class _JavaBridgeSession:
    """One JVM session for every bounded Java repository scan.

    The Java bridge accepts request/response lines, which lets bounded input
    batches retain their safety limits without paying process startup for each
    batch.  A session error deliberately falls back to the previous one-shot
    bridge at the caller.
    """

    def __init__(self, command: list[str], cwd: Path) -> None:
        self._responses: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._closed = False
        self._failure = ""
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=str(cwd),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            self._process = None
            self._failure = f"Java persistent AST bridge error: {type(exc).__name__}: {exc}"
            return
        self._reader = threading.Thread(target=self._read_responses, name="auditforge-java-ast", daemon=True)
        self._reader.start()

    def run_batch(self, source_files: list[Any]) -> tuple[dict[str, dict[str, Any]], str]:
        if self._process is None:
            return {}, self._failure or "Java persistent AST bridge is unavailable"
        request, ids_to_path = _java_batch_input(source_files)
        timeout = max(BRIDGE_TIMEOUT_SECONDS, BRIDGE_TIMEOUT_SECONDS * len(source_files) // 8)
        encoded = base64.b64encode(request.encode("utf-8")).decode("ascii")
        with self._lock:
            if self._closed or self._process.poll() is not None or self._process.stdin is None:
                return {}, "Java persistent AST bridge exited before processing the batch"
            try:
                self._process.stdin.write(encoded + "\n")
                self._process.stdin.flush()
            except OSError as exc:
                return {}, f"Java persistent AST bridge write error: {type(exc).__name__}: {exc}"
            try:
                stdout = self._responses.get(timeout=timeout)
            except queue.Empty:
                self.close()
                return {}, "Java persistent AST bridge timed out"
        if stdout is None:
            return {}, "Java persistent AST bridge exited without a response"
        return _parse_java_batch_output(stdout, 0, "", ids_to_path)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        process = self._process
        if process is None:
            return
        if process.poll() is None and process.stdin is not None:
            try:
                process.stdin.write("__AUDITFORGE_QUIT__\n")
                process.stdin.flush()
            except OSError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

    def _read_responses(self) -> None:
        if self._process is None or self._process.stdout is None:
            self._responses.put(None)
            return
        try:
            for line in self._process.stdout:
                self._responses.put(line.rstrip("\r\n"))
        finally:
            self._responses.put(None)


def _java_bridge_command(java_command: list[str], bridge_path: Path) -> list[str]:
    """Return a cached class-mode bridge command, with source mode as fallback.

    ``java Bridge.java`` is convenient but recompiles the bridge for each
    bounded source batch.  Large repositories need dozens of batches, so cache
    the compiled class in the operating-system temporary directory by bridge
    content and JDK executable.  The cache holds no repository code, and any
    compilation/cache failure intentionally falls back to the previous source
    launcher behavior.
    """

    source_command = [*java_command, str(bridge_path)]
    if not java_command:
        return source_command
    try:
        java_executable = Path(java_command[0]).resolve()
        compiler = java_executable.with_name("javac.exe" if os.name == "nt" else "javac")
        if not compiler.is_file():
            return source_command
        digest = sha256_text(f"{java_executable}\n{bridge_path.read_text(encoding='utf-8')}")
    except OSError:
        return source_command

    cached = _JAVA_BRIDGE_COMMANDS.get(digest)
    if cached is not None:
        return cached
    cache_root = Path(tempfile.gettempdir()) / "auditforge" / "java-ast-bridge" / digest
    class_file = cache_root / "AuditForgeJavaAstBridge.class"
    compiled_command = [str(java_executable), "-cp", str(cache_root), "AuditForgeJavaAstBridge"]
    if class_file.is_file():
        _JAVA_BRIDGE_COMMANDS[digest] = compiled_command
        return compiled_command

    try:
        cache_root.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=f"{digest[:12]}-", dir=cache_root.parent) as temporary:
            temporary_root = Path(temporary)
            completed = subprocess.run(
                [str(compiler), "-encoding", "UTF-8", "-d", str(temporary_root), str(bridge_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=BRIDGE_TIMEOUT_SECONDS,
                check=False,
                cwd=str(bridge_path.parent),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if completed.returncode or not (temporary_root / "AuditForgeJavaAstBridge.class").is_file():
                return source_command
            if not class_file.is_file():
                try:
                    os.replace(temporary_root, cache_root)
                except FileExistsError:
                    # A concurrent scanner populated this exact content cache.
                    pass
        if class_file.is_file():
            _JAVA_BRIDGE_COMMANDS[digest] = compiled_command
            return compiled_command
    except (OSError, subprocess.TimeoutExpired):
        pass
    return source_command


def native_payload_to_result(source_file: Any, payload: dict[str, Any]) -> LanguageAnalysisResult:
    """Convert bounded native parser events to shared AST-labelled facts."""

    raw = payload.get("facts")
    if not isinstance(raw, dict):
        raise ValueError("facts must be an object")
    event_count = sum(len(value) for value in raw.values() if isinstance(value, list))
    if event_count > MAX_NATIVE_EVENTS:
        raise ValueError(f"fact event limit exceeded ({MAX_NATIVE_EVENTS})")

    language = str(source_file.file.language).lower()
    builder = LanguageFactBuilder(source_file)
    class_map: dict[str, Any] = {}
    function_map: dict[str, Any] = {}
    for item in _objects(raw.get("classes")):
        key, name = _text(item.get("key"), 240), _text(item.get("name"), 240)
        if not key or not name:
            continue
        line = _line(source_file, item.get("line"))
        class_map[key] = builder.add_class(
            name, line, _line(source_file, item.get("endLine"), minimum=line), qualified_name=_text(item.get("qualifiedName"), 500) or name
        )

    functions = _objects(raw.get("functions"))
    for item in functions:
        key, name = _text(item.get("key"), 240), _text(item.get("name"), 240)
        if not key or not name or name == "<init>":
            continue
        line = _line(source_file, item.get("line"))
        qualified = _text(item.get("qualifiedName"), 500) or name
        # Java's heuristic scope ids use the simple method name; Go uses the
        # receiver-qualified method name.  Preserve that compatibility while
        # showing the full display name to users.
        identity = name if language == "java" else qualified
        fact = builder.add_function(
            name,
            line,
            _strings(item.get("params"), 200),
            _line(source_file, item.get("endLine"), minimum=line),
            qualified_name=identity,
            class_id=(class_map.get(_text(item.get("classKey"), 240)).id if _text(item.get("classKey"), 240) in class_map else None),
        )
        if qualified != fact.qualified_name:
            fact = replace(fact, qualified_name=qualified)
            builder.result.functions[-1] = fact
        function_map[key] = fact

    updated_functions = []
    for item in functions:
        fact = function_map.get(_text(item.get("key"), 240))
        if fact is None:
            continue
        parent = function_map.get(_text(item.get("parentKey"), 240))
        updated = replace(fact, parent_function_id=parent.id if parent else None)
        function_map[_text(item.get("key"), 240)] = updated
        updated_functions.append(updated)
    builder.result.functions = updated_functions

    for item in _objects(raw.get("assignments")):
        target = _text(item.get("target"), 600)
        if target:
            builder.add_assignment(
                target,
                _strings(item.get("sources"), 500),
                _text(item.get("expression"), 1600),
                _line(source_file, item.get("line")),
                function=function_map.get(_text(item.get("scopeKey"), 240)),
            )
    for item in _objects(raw.get("returns")):
        builder.add_return(
            _text(item.get("expression"), 1600),
            _strings(item.get("sources"), 500),
            _line(source_file, item.get("line")),
            function=function_map.get(_text(item.get("scopeKey"), 240)),
        )
    for item in _objects(raw.get("calls")):
        callee = _text(item.get("callee"), 800)
        if callee:
            builder.add_call(
                callee,
                _line(source_file, item.get("line")),
                _nested_strings(item.get("argumentSources"), 100, 200),
                function=function_map.get(_text(item.get("scopeKey"), 240)),
            )
    for item in _objects(raw.get("controls")):
        kind = _text(item.get("kind"), 20)
        if kind in {"if", "elif", "else", "for", "while", "switch", "case", "catch"}:
            builder.add_control(
                kind,
                _text(item.get("condition"), 1600),
                _line(source_file, item.get("line")),
                _strings(item.get("variables"), 500),
                function=function_map.get(_text(item.get("scopeKey"), 240)),
            )
    return _mark_ast(builder.result)


def _merge_structural_and_framework_facts(structural: LanguageAnalysisResult, heuristic: LanguageAnalysisResult) -> LanguageAnalysisResult:
    """Keep the parser facts additive to the established language model.

    The native bridge is intentionally an optimisation and a precision upgrade,
    not an authority that can erase a heuristic fact.  Parsers and lightweight
    framework extraction disagree on edge constructs (generated annotations,
    fluent calls, malformed-but-buildable source, and language extensions), so
    replacing a non-empty heuristic collection with AST output could silently
    reduce the candidate surface.  The scanner's stable-id de-duplication
    removes identical facts after all files have been analysed; ordering AST
    facts first preserves their stronger provenance where both frontends agree.
    """
    return LanguageAnalysisResult(
        functions=[*structural.functions, *heuristic.functions],
        classes=[*structural.classes, *heuristic.classes],
        routes=heuristic.routes,
        # Frontends generate call and flow ids from their own event order.  The
        # same source construct can therefore have two ids if one frontend
        # recognises an earlier construct that the other ignores.  Remove only
        # fully equivalent facts here; different callees, variables, paths or
        # expressions remain additive and retain the original detection surface.
        call_sites=_dedupe_equivalent([*structural.call_sites, *heuristic.call_sites], _call_key),
        data_flows=_dedupe_equivalent([*structural.data_flows, *heuristic.data_flows], _data_flow_key),
        control_flows=_dedupe_equivalent([*structural.control_flows, *heuristic.control_flows], _control_flow_key),
        sources=heuristic.sources,
        sinks=heuristic.sinks,
        sanitizers=heuristic.sanitizers,
    )


def _dedupe_equivalent(items: list[Any], key: Any) -> list[Any]:
    seen: set[tuple[Any, ...]] = set()
    result: list[Any] = []
    for item in items:
        marker = key(item)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def _call_key(item: Any) -> tuple[Any, ...]:
    return (
        item.anchor.file,
        item.anchor.start_line,
        item.anchor.end_line,
        item.callee,
        item.enclosing_function_id,
        _nested_value_key(item.argument_sources),
        _mapping_value_key(item.keyword_sources),
    )


def _data_flow_key(item: Any) -> tuple[Any, ...]:
    return (
        item.anchor.file,
        item.anchor.start_line,
        item.anchor.end_line,
        item.kind,
        item.target,
        item.expression,
        item.enclosing_function_id,
        tuple(item.sources),
        _nested_value_key(item.argument_sources),
        _mapping_value_key(item.keyword_sources),
        item.ssa_safe_overwrite,
    )


def _control_flow_key(item: Any) -> tuple[Any, ...]:
    return (
        item.anchor.file,
        item.anchor.start_line,
        item.anchor.end_line,
        item.kind,
        item.condition,
        item.enclosing_function_id,
        tuple(item.variables),
    )


def _nested_value_key(value: list[list[str]]) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(item) for item in value)


def _mapping_value_key(value: dict[str, list[str]]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple(sorted((name, tuple(items)) for name, items in value.items()))


def _bridge_command(language: str) -> tuple[list[str] | None, str | None]:
    if language == "java":
        compiler = shutil.which("javac") or _tool_from_home("JAVA_HOME", "javac") or _discover_windows_javac()
        if not compiler:
            return None, "javac_not_found"
        java = Path(compiler).with_name("java.exe" if os.name == "nt" else "java")
        if not java.is_file():
            return None, "java_not_found"
        return [str(java)], None
    if language == "go":
        go = shutil.which("go") or _tool_from_home("GOROOT", "go")
        return ([go, "run"] if go else None), (None if go else "go_not_found")
    return None, "unsupported_language"


def _tool_from_home(variable: str, name: str) -> str | None:
    home = os.getenv(variable, "").strip()
    if not home:
        return None
    executable = Path(home) / "bin" / f"{name}.exe" if os.name == "nt" else Path(home) / "bin" / name
    return str(executable) if executable.is_file() else None


def _discover_windows_javac() -> str | None:
    if os.name != "nt":
        return None
    roots = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Eclipse Adoptium",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Java",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft",
    ]
    candidates = [candidate for root in roots if root.is_dir() for candidate in root.glob("*/bin/javac.exe") if candidate.is_file()]
    return str(max(candidates, key=lambda item: item.stat().st_mtime)) if candidates else None


def _diagnostic(status: str, reason: str) -> dict[str, Any]:
    return {"status": status, "reason": reason[:1200], "used": status == "ok", "fallback": status != "ok"}


def _mark_ast(result: LanguageAnalysisResult) -> LanguageAnalysisResult:
    for name in ("functions", "classes", "call_sites", "data_flows", "control_flows"):
        setattr(result, name, [replace(item, analysis_method="ast") for item in getattr(result, name)])
    return result


def _fact_count(result: LanguageAnalysisResult) -> int:
    return sum(
        len(getattr(result, name))
        for name in ("functions", "classes", "routes", "call_sites", "data_flows", "control_flows", "sources", "sinks", "sanitizers")
    )


def _objects(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _text(value: Any, limit: int = 1600) -> str:
    return str(value)[:limit] if isinstance(value, (str, int, float)) else ""


def _strings(value: Any, limit: int) -> list[str]:
    return dedupe_strings([_text(item, 500) for item in value[:limit]]) if isinstance(value, list) else []


def _nested_strings(value: Any, outer_limit: int, inner_limit: int) -> list[list[str]]:
    return [_strings(item, inner_limit) for item in value[:outer_limit]] if isinstance(value, list) else []


def _line(source_file: Any, value: Any, *, minimum: int = 1) -> int:
    try:
        line = int(value)
    except (TypeError, ValueError):
        line = minimum
    return min(max(minimum, line), max(1, len(source_file.lines)))
