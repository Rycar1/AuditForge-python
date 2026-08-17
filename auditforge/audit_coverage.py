"""Build an evidence-backed map of analysis coverage and blind spots.

The score in this module describes how much of the repository the analysis
pipeline could inspect.  It is deliberately not presented as vulnerability
recall: a scan cannot infer false negatives without ground truth.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import CodeAnchor, CodeFacts, CodeGraph, TraceCandidate
from .utils import normalize_path

SCHEMA_VERSION = 1
MAX_BLINDSPOT_FILES = 24
MAX_BLINDSPOT_ANCHORS = 32


def build_audit_coverage(
    facts: CodeFacts,
    graph: CodeGraph,
    candidates: list[TraceCandidate],
    llm_diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize observable coverage gaps without claiming measured recall."""

    diagnostics = facts.analysis_diagnostics or {}
    llm = llm_diagnostics or {}
    files = list(facts.files)
    discovered = int(diagnostics.get("discovered_source_files") or len(files))
    analyzed = int(diagnostics.get("analyzed_files") or sum(not item.skipped_reason for item in files))
    ast_files = sum(item.parsed_by == "ast" and not item.skipped_reason for item in files)
    heuristic_files = [item for item in files if item.parsed_by == "heuristic" and not item.skipped_reason]
    fallback_files = [item for item in files if item.parsed_by == "fallback" or item.analysis_error]
    skipped_files = [item for item in files if item.skipped_reason]

    call_ids = {call.id for call in facts.call_sites}
    resolved_call_ids = {edge.from_id for edge in graph.edges if edge.kind == "CALLS" and edge.from_id in call_ids}
    repository_function_names = {function.name for function in facts.functions}
    internal_calls = [
        call for call in facts.call_sites if call.id in resolved_call_ids or call.callee.rsplit(".", 1)[-1] in repository_function_names
    ]
    unresolved_calls = [call for call in internal_calls if call.id not in resolved_call_ids]
    routes_without_handlers = [route for route in facts.routes if not route.handler_function_id]

    candidate_source_keys = {_anchor_key(candidate.source) for candidate in candidates}
    candidate_sink_keys = {_anchor_key(candidate.sink) for candidate in candidates}
    unmatched_sources = [source for source in facts.sources if _anchor_key(source.anchor) not in candidate_source_keys]
    unmatched_sinks = [sink for sink in facts.sinks if _anchor_key(sink.anchor) not in candidate_sink_keys]

    indexing_score = _ratio_score(analyzed, discovered)
    parsing_score = _parsing_score(ast_files, len(heuristic_files), len(fallback_files), analyzed)
    call_score = _ratio_score(len(resolved_call_ids), len(internal_calls))
    dimensions: dict[str, dict[str, Any]] = {
        "indexing": _dimension(indexing_score, analyzed, discovered, "files analyzed"),
        "semantic_parsing": _dimension(
            parsing_score,
            ast_files,
            analyzed,
            "AST/native parser coverage; heuristic and fallback parsing receive partial credit",
        ),
        "call_resolution": _dimension(
            call_score,
            len(resolved_call_ids),
            len(internal_calls),
            "call sites linked to a repository function",
        ),
    }

    llm_enabled = bool(llm.get("enabled"))
    llm_coverage = llm.get("coverage") if isinstance(llm.get("coverage"), dict) else {}
    llm_ratio = _bounded_ratio(llm_coverage.get("ratio"))
    dimensions["llm_review"] = {
        "status": "measured" if llm_enabled else "not_enabled",
        "score": round(llm_ratio * 100, 1) if llm_enabled else None,
        "covered": int((llm_coverage.get("anchors") or {}).get("covered") or 0),
        "total": int((llm_coverage.get("anchors") or {}).get("total") or 0),
        "description": "security anchors included in successful specialist-agent prompts",
    }

    weighted = [(indexing_score, 0.35), (parsing_score, 0.30), (call_score, 0.35)]
    if llm_enabled:
        weighted = [(score, weight * 0.85) for score, weight in weighted]
        weighted.append((llm_ratio * 100, 0.15))
    score = round(sum(value * weight for value, weight in weighted) / sum(weight for _, weight in weighted), 1)

    blindspots: list[dict[str, Any]] = []
    if diagnostics.get("truncated"):
        blindspots.append(
            _blindspot(
                "analysis_truncated",
                "indexing",
                "critical",
                int(diagnostics.get("truncated_files") or 1),
                "Repository indexing stopped at a configured limit.",
                "Raise or remove the indexing limit, then run the scan again.",
                files=_paths_from_diagnostics(diagnostics.get("skipped"), reason_contains="limit"),
            )
        )
    if fallback_files:
        blindspots.append(
            _blindspot(
                "parser_fallback",
                "parsing",
                "high",
                len(fallback_files),
                "One or more files fell back after a parser or file-read failure.",
                "Restore the required language toolchain or fix the parse error, then rescan these files.",
                files=[item.path for item in fallback_files],
                auto_rescan=_rescan_state(llm, "parser_fallback"),
            )
        )
    error_records = diagnostics.get("errors") if isinstance(diagnostics.get("errors"), list) else []
    if error_records and not fallback_files:
        blindspots.append(
            _blindspot(
                "analysis_errors",
                "parsing",
                "high",
                len(error_records),
                "Analysis errors prevented complete fact extraction.",
                "Resolve the recorded parser errors and repeat the affected scopes.",
                files=_paths_from_diagnostics(error_records),
            )
        )
    if skipped_files:
        blindspots.append(
            _blindspot(
                "skipped_source_files",
                "indexing",
                "medium",
                len(skipped_files),
                "Source-like files were indexed but intentionally skipped.",
                "Review skip reasons and explicitly include security-relevant generated or oversized files.",
                files=[item.path for item in skipped_files],
            )
        )
    if heuristic_files:
        blindspots.append(
            _blindspot(
                "heuristic_parsing",
                "parsing",
                "low",
                len(heuristic_files),
                "These files used a structured heuristic frontend instead of a compiler-grade AST.",
                "Install the native frontend where available and prioritize these files for semantic review.",
                files=[item.path for item in heuristic_files],
                auto_rescan=_rescan_state(llm, "heuristic_parsing"),
            )
        )
    if unresolved_calls:
        blindspots.append(
            _blindspot(
                "unresolved_calls",
                "symbol_resolution",
                "high" if len(unresolved_calls) >= max(5, len(internal_calls) // 3) else "medium",
                len(unresolved_calls),
                "Call targets could not be linked conservatively; cross-file taint may stop at these edges.",
                "Prioritize dynamic dispatch, imports, interfaces, dependency injection, and framework bindings in a focused review.",
                anchors=[call.anchor for call in unresolved_calls],
                files=[call.anchor.file for call in unresolved_calls],
                auto_rescan=_rescan_state(llm, "unresolved_calls"),
            )
        )
    if routes_without_handlers:
        blindspots.append(
            _blindspot(
                "unbound_routes",
                "framework_model",
                "medium",
                len(routes_without_handlers),
                "Framework routes were found but could not be bound to handler symbols.",
                "Extend the framework route model or resolve generated/dynamic handler registration.",
                anchors=[route.anchor for route in routes_without_handlers],
                files=[route.anchor.file for route in routes_without_handlers],
                auto_rescan=_rescan_state(llm, "unbound_routes"),
            )
        )
    if unmatched_sinks:
        blindspots.append(
            _blindspot(
                "unmatched_sinks",
                "taint_model",
                "medium",
                len(unmatched_sinks),
                "Dangerous operations were identified but no accepted source-to-sink candidate reached them.",
                "Review reachability, implicit sources, stored data, callbacks, and missing interprocedural edges.",
                anchors=[sink.anchor for sink in unmatched_sinks],
                files=[sink.anchor.file for sink in unmatched_sinks],
                auto_rescan=_rescan_state(llm, "unmatched_sinks"),
            )
        )
    if unmatched_sources:
        blindspots.append(
            _blindspot(
                "unmatched_sources",
                "taint_model",
                "low",
                len(unmatched_sources),
                "External inputs were identified but did not reach an accepted dangerous operation.",
                "Review storage, event, template, and framework-mediated flows that may not appear as direct calls.",
                anchors=[source.anchor for source in unmatched_sources],
                files=[source.anchor.file for source in unmatched_sources],
                auto_rescan=_rescan_state(llm, "unmatched_sources"),
            )
        )

    framework_errors = _framework_errors(diagnostics)
    if framework_errors:
        blindspots.append(
            _blindspot(
                "framework_model_errors",
                "framework_model",
                "medium",
                len(framework_errors),
                "A framework model could not inspect one or more files.",
                "Fix the recorded model error and repeat framework augmentation.",
                files=_paths_from_diagnostics(framework_errors),
            )
        )

    failed_tasks = int(llm.get("failed") or 0)
    if llm_enabled and failed_tasks:
        blindspots.append(
            _blindspot(
                "llm_task_failures",
                "llm_review",
                "high",
                failed_tasks,
                "Specialist-agent tasks failed or timed out after the bounded retry.",
                "Check provider availability and rerun only the failed scopes.",
                files=_failed_task_files(llm),
                auto_rescan=_rescan_state(llm, "llm_task_failures"),
            )
        )
    if llm_enabled and llm_ratio < 0.999:
        anchors = llm_coverage.get("anchors") if isinstance(llm_coverage.get("anchors"), dict) else {}
        missing = max(0, int(anchors.get("total") or 0) - int(anchors.get("covered") or 0))
        blindspots.append(
            _blindspot(
                "llm_uncovered_anchors",
                "llm_review",
                "medium",
                missing,
                "Some routes, sources, or sinks were absent from every successful specialist prompt.",
                "Run the bounded focused rescan or increase the prompt budget for the listed scopes.",
                auto_rescan=_rescan_state(llm, "llm_uncovered_anchors"),
            )
        )

    blindspots.sort(key=lambda item: (_severity_order(item["severity"]), -int(item["count"]), item["id"]))
    severe = any(item["severity"] in {"critical", "high"} for item in blindspots)
    partial = severe or score < 85 or (llm_enabled and not bool(llm.get("complete")))
    return {
        "schema_version": SCHEMA_VERSION,
        "score": score,
        "status": "partial" if partial else "strong",
        "score_kind": "analysis_confidence",
        "recall_measured": False,
        "disclaimer": "This score measures observable analysis coverage, not vulnerability detection rate or false-negative recall.",
        "dimensions": dimensions,
        "summary": {
            "discovered_files": discovered,
            "analyzed_files": analyzed,
            "ast_files": ast_files,
            "heuristic_files": len(heuristic_files),
            "fallback_files": len(fallback_files),
            "skipped_files": len(skipped_files),
            "call_sites": len(facts.call_sites),
            "internal_call_sites": len(internal_calls),
            "resolved_calls": len(resolved_call_ids),
            "unresolved_calls": len(unresolved_calls),
            "routes": len(facts.routes),
            "unbound_routes": len(routes_without_handlers),
            "sources": len(facts.sources),
            "unmatched_sources": len(unmatched_sources),
            "sinks": len(facts.sinks),
            "unmatched_sinks": len(unmatched_sinks),
            "blindspots": len(blindspots),
            "high_priority_blindspots": sum(item["severity"] in {"critical", "high"} for item in blindspots),
        },
        "blindspots": blindspots,
        "auto_rescan": _public_rescan_summary(llm),
    }


def _anchor_key(anchor: CodeAnchor) -> tuple[str, int]:
    return normalize_path(anchor.file), int(anchor.start_line)


def _ratio_score(covered: int, total: int) -> float:
    return round((covered / total) * 100, 1) if total else 100.0


def _parsing_score(ast_files: int, heuristic_files: int, fallback_files: int, analyzed: int) -> float:
    if not analyzed:
        return 100.0
    weighted = ast_files + heuristic_files * 0.72 + fallback_files * 0.35
    remaining = max(0, analyzed - ast_files - heuristic_files - fallback_files)
    weighted += remaining * 0.6
    return round(min(100.0, weighted / analyzed * 100), 1)


def _dimension(score: float, covered: int, total: int, description: str) -> dict[str, Any]:
    return {
        "status": "measured",
        "score": score,
        "covered": covered,
        "total": total,
        "description": description,
    }


def _bounded_ratio(value: object) -> float:
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _blindspot(
    identifier: str,
    category: str,
    severity: str,
    count: int,
    reason: str,
    recommended_action: str,
    *,
    files: Iterable[str] = (),
    anchors: Iterable[CodeAnchor] = (),
    auto_rescan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_files = sorted({normalize_path(path) for path in files if path})[:MAX_BLINDSPOT_FILES]
    anchor_rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for anchor in anchors:
        key = _anchor_key(anchor)
        if key in seen:
            continue
        seen.add(key)
        anchor_rows.append(
            {
                "file": key[0],
                "line": key[1],
                "symbol": anchor.symbol,
            }
        )
        if len(anchor_rows) >= MAX_BLINDSPOT_ANCHORS:
            break
    return {
        "id": identifier,
        "category": category,
        "severity": severity,
        "count": max(0, int(count)),
        "reason": reason,
        "recommended_action": recommended_action,
        "files": normalized_files,
        "anchors": anchor_rows,
        "samples_truncated": len(set(files)) > len(normalized_files) if isinstance(files, (list, tuple, set)) else False,
        "auto_rescan": auto_rescan or {"eligible": False, "scheduled": False, "status": "not_applicable", "task_ids": []},
    }


def _paths_from_diagnostics(records: object, *, reason_contains: str | None = None) -> list[str]:
    if not isinstance(records, list):
        return []
    paths: list[str] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        if reason_contains and reason_contains.lower() not in str(item.get("reason") or item.get("error") or "").lower():
            continue
        path = str(item.get("path") or "")
        if path:
            paths.append(path)
    return paths


def _framework_errors(diagnostics: dict[str, Any]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    framework = diagnostics.get("framework_models")
    if isinstance(framework, dict) and isinstance(framework.get("errors"), list):
        errors.extend(item for item in framework["errors"] if isinstance(item, dict))
    java = diagnostics.get("java_framework")
    if isinstance(java, dict) and isinstance(java.get("errors"), list):
        errors.extend(item for item in java["errors"] if isinstance(item, dict))
    return errors


def _failed_task_files(llm: dict[str, Any]) -> list[str]:
    files: list[str] = []
    details = llm.get("task_details")
    if not isinstance(details, list):
        return files
    for item in details:
        if not isinstance(item, dict) or item.get("status") == "succeeded":
            continue
        scoped = item.get("files")
        if isinstance(scoped, list):
            files.extend(str(path) for path in scoped if path)
    return files


def _rescan_state(llm: dict[str, Any], blindspot_id: str) -> dict[str, Any]:
    rescan = llm.get("blindspot_rescan") if isinstance(llm.get("blindspot_rescan"), dict) else {}
    scopes = rescan.get("scopes") if isinstance(rescan.get("scopes"), list) else []
    matching = [item for item in scopes if isinstance(item, dict) and blindspot_id in (item.get("reasons") or [])]
    task_ids = [str(item.get("id")) for item in matching if item.get("id")]
    if not rescan:
        return {"eligible": True, "scheduled": False, "status": "not_run", "task_ids": []}
    if not matching:
        return {
            "eligible": True,
            "scheduled": False,
            "status": "budget_exhausted" if rescan.get("budget_exhausted") else "not_selected",
            "task_ids": [],
        }
    failed = {str(value) for value in rescan.get("failed_task_ids") or []}
    return {
        "eligible": True,
        "scheduled": True,
        "status": "failed" if any(task_id in failed for task_id in task_ids) else "completed",
        "task_ids": task_ids,
    }


def _public_rescan_summary(llm: dict[str, Any]) -> dict[str, Any]:
    rescan = llm.get("blindspot_rescan") if isinstance(llm.get("blindspot_rescan"), dict) else {}
    return {
        "enabled": bool(rescan.get("enabled")),
        "planned": int(rescan.get("planned") or 0),
        "executed": int(rescan.get("executed") or 0),
        "succeeded": int(rescan.get("succeeded") or 0),
        "failed": int(rescan.get("failed") or 0),
        "recovered_initial_tasks": int(rescan.get("recovered_initial_tasks") or 0),
        "coverage_before": rescan.get("coverage_before") or {},
        "coverage_after": rescan.get("coverage_after") or {},
        "budget_exhausted": bool(rescan.get("budget_exhausted")),
    }


def _severity_order(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(value, 4)
