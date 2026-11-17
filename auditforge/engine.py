from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from .audit_coverage import build_audit_coverage
from .candidates import build_trace_candidates
from .deep_verification import run_deep_verification
from .dependency_scan import analyze_dependencies_with_llm, scan_dependency_manifests
from .direct_findings import generate_direct_candidates
from .graph import build_graph
from .graph_artifacts import write_graph_artifacts
from .llm_candidates import LLMConfig, generate_llm_candidates, preflight_llm_config, triage_candidates_with_llm
from .logging_config import contextual_logger, get_logger
from .models import ScanResult, VerificationResult
from .project_inventory import build_project_inventory, inventory_summary
from .report import write_reports
from .result_sections import build_result_sections, has_runtime_negative_evidence
from .sbom import build_cyclonedx_sbom
from .scanner import scan_repo
from .semantic_findings import generate_semantic_candidates
from .store import write_store
from .utils import write_json
from .validation_runner import ValidationRunnerConfig
from .verification import build_verification_plans, run_safe_verification


def run_scan(
    repo_path: Path,
    workspace: Path,
    target_url: str | None = None,
    verify: str = "none",
    llm_config: LLMConfig | None = None,
    deep_llm_config: LLMConfig | None = None,
    dependency_scan: bool = False,
    dependency_llm_config: LLMConfig | None = None,
    sandbox_concurrency: int | None = None,
    validation_runner_config: ValidationRunnerConfig | None = None,
    project_inventory: dict | None = None,
    progress_callback: Callable[[str, int, str], None] | None = None,
) -> ScanResult:
    repo_path = repo_path.resolve()
    workspace = workspace.resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError(f"待扫描仓库不存在或不是目录：{repo_path}")
    if workspace == repo_path or workspace.is_relative_to(repo_path):
        raise ValueError("输出工作区必须位于待扫描仓库之外，避免覆盖源码或把历史制品计入扫描")
    workspace.mkdir(parents=True, exist_ok=True)
    completion_marker = workspace / "scan_complete.json"
    completion_marker.unlink(missing_ok=True)
    logger = contextual_logger(get_logger(__name__), repo=str(repo_path), workspace=str(workspace))
    logger.info("scan pipeline started", extra={"event": "scan.pipeline.started", "verify": verify})
    llm_config, taint_llm_preflight = preflight_llm_config(llm_config)
    deep_llm_config, deep_llm_preflight = preflight_llm_config(deep_llm_config or llm_config)
    dependency_llm_config, dependency_llm_preflight = preflight_llm_config(dependency_llm_config or llm_config)

    project_inventory = project_inventory or build_project_inventory(repo_path)
    emit_progress(progress_callback, "inventory", 100, f"项目盘点完成：{inventory_summary(project_inventory)}")
    emit_progress(progress_callback, "candidate", 6, "正在索引源码文件并抽取 AST facts")
    facts = scan_repo(
        repo_path,
        progress_callback=lambda completed, total: emit_progress(
            progress_callback,
            "candidate",
            6 + round((completed / max(total, 1)) * 28),
            f"正在抽取语言事实：{completed:,}/{total:,} 个文件",
        ),
    )
    emit_progress(progress_callback, "candidate", 34, f"已索引 {len(facts.files)} 个文件，正在构建统一图模型")
    graph = build_graph(
        facts,
        progress_callback=lambda percent, message: emit_progress(
            progress_callback,
            "candidate",
            34 + round(max(0, min(100, percent)) * 0.20),
            message,
        ),
    )
    emit_progress(progress_callback, "candidate", 54, "统一图模型已生成，正在匹配 source 与 sink")
    candidates = build_trace_candidates(
        facts,
        graph,
        progress_callback=lambda percent, message: emit_progress(
            progress_callback,
            "candidate",
            54 + round(max(0, min(100, percent)) * 0.22),
            message,
        ),
    )
    direct_candidates = generate_direct_candidates(repo_path, facts, candidates)
    direct_candidates.extend(generate_semantic_candidates(repo_path, facts, [*candidates, *direct_candidates]))
    candidates.extend(direct_candidates)
    direct_text = f"，直接审计候选 {len(direct_candidates)} 条" if direct_candidates else ""
    emit_progress(progress_callback, "candidate", 76, f"确定性规则已生成 {len(candidates)} 条候选路径{direct_text}")
    llm_diagnostics = {"enabled": bool(llm_config.enabled), "preflight": taint_llm_preflight}
    if llm_config and llm_config.enabled:
        if llm_config.discovery_enabled:
            emit_progress(progress_callback, "candidate", 84, "正在调用 LLM 补全语义候选路径")
            llm_generated, llm_diagnostics = generate_llm_candidates(repo_path, facts, candidates, llm_config)
            llm_diagnostics["preflight"] = taint_llm_preflight
            candidates.extend(llm_generated)
            emit_progress(progress_callback, "candidate", 90, f"LLM 补全完成，当前候选 {len(candidates)} 条")
        if llm_config.triage_enabled:
            emit_progress(progress_callback, "candidate", 92, "正在调用 LLM 复核候选误报")
            candidates, triage_diagnostics = triage_candidates_with_llm(repo_path, facts, candidates, llm_config)
            llm_diagnostics = dict(llm_diagnostics)
            llm_diagnostics["triage"] = triage_diagnostics
            emit_progress(progress_callback, "candidate", 96, f"LLM 复核完成，保留候选 {len(candidates)} 条")
    emit_progress(progress_callback, "candidate", 100, f"候选路径生成完成，共 {len(candidates)} 条")

    dependency_inventory = []
    dependency_findings = []
    dependency_diagnostics = {"enabled": False}
    if dependency_scan:
        emit_progress(progress_callback, "dependencies", 12, "正在解析 requirements、pom、package、go.mod 等依赖清单")
        dependency_inventory = scan_dependency_manifests(repo_path)
        dependency_count = sum(len(manifest.dependencies) for manifest in dependency_inventory)
        emit_progress(
            progress_callback,
            "dependencies",
            38,
            f"已识别 {len(dependency_inventory)} 个依赖清单、{dependency_count} 个依赖，正在执行 OSV 确定性匹配与 LLM 语义复核",
        )
        dependency_findings, dependency_diagnostics = analyze_dependencies_with_llm(
            repo_path,
            dependency_inventory,
            dependency_llm_config,
        )
        dependency_diagnostics["llm_preflight"] = dependency_llm_preflight
        emit_progress(progress_callback, "dependencies", 100, f"依赖风险分析完成，生成 {len(dependency_findings)} 条组件风险候选")

    verification_modes = parse_verification_modes(verify)
    if not verification_modes:
        emit_progress(progress_callback, "verification_skipped", 100, "未启用二次验证，已跳过验证阶段")
    else:
        emit_progress(progress_callback, "verification", 10, "正在生成候选路径的复现计划")
    allow_state_changes = "stateful" in verification_modes
    plans = build_verification_plans(candidates, allow_state_changes=allow_state_changes)
    verification_results = []
    deep_diagnostics = {"enabled": False}
    safe_results: list[VerificationResult] = []
    deep_results: list[VerificationResult] = []
    if verification_modes & {"safe", "stateful"}:
        emit_progress(progress_callback, "verification", 34, "正在执行 safe 受控验证")
        safe_results = run_safe_verification(candidates, facts, target_url, allow_state_changes=allow_state_changes)
        emit_progress(
            progress_callback, "verification", 62 if "deep" in verification_modes else 92, f"safe 验证完成，获得 {len(safe_results)} 条结果"
        )
    if "deep" in verification_modes:
        emit_progress(progress_callback, "verification", 64 if safe_results else 28, "正在生成声明式验证计划并收集独立 runner 证据")
        deep_results, deep_diagnostics = run_deep_verification(
            repo_path,
            candidates,
            deep_llm_config,
            sandbox_concurrency=sandbox_concurrency,
            target_url=target_url,
            allow_state_changes=allow_state_changes,
            validation_runner_config=validation_runner_config,
            code_facts=facts,
        )
        deep_diagnostics["llm_preflight"] = deep_llm_preflight
        emit_progress(progress_callback, "verification", 92, f"二次深入验证完成，获得 {len(deep_results)} 条结果")
        llm_diagnostics = dict(llm_diagnostics)
        llm_diagnostics["deep_verification"] = deep_diagnostics
    verification_results = combine_verification_results(safe_results, deep_results)
    verification_results = [protect_unsubstantiated_negative(result) for result in verification_results]
    if dependency_scan:
        llm_diagnostics = dict(llm_diagnostics)
        llm_diagnostics["dependency_scan"] = dependency_diagnostics
    if verification_modes:
        emit_progress(progress_callback, "verification", 100, "验证阶段完成，正在写入证据与中文报告")

    analysis_coverage = build_audit_coverage(facts, graph, candidates, llm_diagnostics)

    result = ScanResult(
        repo_path=str(repo_path),
        target_url=target_url,
        facts=facts,
        graph=graph,
        candidates=candidates,
        plans=plans,
        verification_results=verification_results,
        llm_diagnostics=llm_diagnostics,
        dependency_inventory=dependency_inventory,
        dependency_findings=dependency_findings,
        dependency_diagnostics=dependency_diagnostics,
        project_inventory=project_inventory,
        analysis_coverage=analysis_coverage,
    )

    write_artifacts(workspace, result)
    write_store(workspace, result)
    write_reports(workspace, result)
    write_json(
        completion_marker,
        {
            "schema_version": 1,
            "completed_at": datetime.now(UTC).isoformat(),
            "repo_path": result.repo_path,
            "stats": result.stats(),
        },
    )
    logger.info("scan pipeline completed", extra={"event": "scan.pipeline.completed", "stats": result.stats()})
    emit_progress(progress_callback, "completed", 100, "扫描完成，报告已生成")
    return result


def parse_verification_modes(value: str) -> set[str]:
    """Accept legacy modes plus explicit safe/deep compositions."""

    normalized = str(value or "none").lower().replace("_", "+").replace(",", "+")
    aliases = {
        "combined": "safe+deep",
        "safe-deep": "safe+deep",
        "deep-safe": "safe+deep",
        "stateful-deep": "stateful+deep",
        "deep-stateful": "stateful+deep",
    }
    normalized = aliases.get(normalized, normalized)
    modes = {item.strip() for item in normalized.split("+") if item.strip() in {"safe", "stateful", "deep"}}
    if "stateful" in modes:
        modes.discard("safe")
    return modes


def combine_verification_results(
    safe_results: list[VerificationResult],
    deep_results: list[VerificationResult],
) -> list[VerificationResult]:
    """Combine safe target evidence and deep snippet evidence conservatively."""

    grouped: dict[str, list[tuple[str, VerificationResult]]] = {}
    order: list[str] = []
    for source, results in (("safe", safe_results), ("deep", deep_results)):
        for result in results:
            if result.candidate_id not in grouped:
                order.append(result.candidate_id)
            grouped.setdefault(result.candidate_id, []).append((source, result))

    combined: list[VerificationResult] = []
    for candidate_id in order:
        entries = grouped[candidate_id]
        if len(entries) == 1:
            combined.append(entries[0][1])
            continue
        statuses = {item.status for _, item in entries}
        if "confirmed" in statuses:
            status = "confirmed"
        elif statuses & {"sandbox_executed", "sandbox_confirmed"}:
            status = "sandbox_executed"
        elif "needs_manual_review" in statuses:
            status = "needs_manual_review"
        elif "blocked" in statuses:
            status = "blocked"
        elif len(statuses) == 1:
            status = entries[0][1].status
        else:
            status = "needs_manual_review"
        evidence = [f"[{source}] {line}" for source, item in entries for line in item.evidence]
        request_log = [dict(log, verification_source=source) for source, item in entries for log in item.request_log]
        notes = "；".join(f"{source}: {item.notes}" for source, item in entries if item.notes)
        combined.append(
            VerificationResult(
                candidate_id=candidate_id,
                status=status,
                evidence=evidence,
                request_log=request_log,
                notes=notes or "safe 与 deep 组合验证结果。",
            )
        )
    return combined


def protect_unsubstantiated_negative(result: VerificationResult) -> VerificationResult:
    if result.status not in {"false_positive", "not_reproducible"} or has_runtime_negative_evidence(result):
        return result
    return replace(
        result,
        status="needs_manual_review",
        evidence=[*result.evidence, "负面判断缺少有效运行时或确定性证据，未自动归档。"],
        notes=(result.notes + "；" if result.notes else "") + "transport/advisory-only negative verdict retained for review.",
    )


def emit_progress(progress_callback: Callable[[str, int, str], None] | None, stage: str, percent: int, message: str) -> None:
    if not progress_callback:
        return
    progress_callback(stage, max(0, min(100, percent)), message)


def write_artifacts(workspace: Path, result: ScanResult) -> None:
    generated_at = datetime.now(UTC).isoformat()
    metadata = {
        "artifact_schema_version": 2,
        "generated_at": generated_at,
        "repo_path": result.repo_path,
        "target_url": result.target_url,
        "stats": result.stats(),
        "safety_note": (
            "Static candidates are not confirmed vulnerabilities until target-runtime evidence is collected. "
            "New deep checks use validated declarative plans executed by an isolated runner; no LLM-produced code, shell, "
            "Docker command, credential, source tree, or Docker socket crosses that boundary. Legacy sandbox records remain readable."
        ),
        "project_inventory": result.project_inventory,
        "llm": result.llm_diagnostics,
        "dependency_scan": result.dependency_diagnostics,
        "analysis_coverage": {
            "artifact": "analysis_coverage.json",
            "score": result.analysis_coverage.get("score"),
            "status": result.analysis_coverage.get("status"),
            "summary": result.analysis_coverage.get("summary", {}),
        },
    }
    write_json(workspace / "scan_metadata.json", metadata)
    write_json(workspace / "project_inventory.json", result.project_inventory)
    write_json(workspace / "analysis_coverage.json", result.analysis_coverage)
    write_graph_artifacts(workspace, result.facts, result.graph)
    write_json(workspace / "trace_candidates.json", [candidate.to_dict() for candidate in result.candidates])
    write_json(workspace / "verification_plans.json", [plan.to_dict() for plan in result.plans])
    write_json(workspace / "verification_runner_plans.json", extract_validation_runner_plans(result.verification_results))
    write_json(workspace / "verification_results.json", [verification.to_dict() for verification in result.verification_results])
    write_json(workspace / "llm_diagnostics.json", result.llm_diagnostics)
    write_json(workspace / "dependency_inventory.json", [manifest.to_dict() for manifest in result.dependency_inventory])
    write_json(workspace / "dependency_findings.json", [finding.to_dict() for finding in result.dependency_findings])
    write_json(
        workspace / "sbom.cdx.json",
        build_cyclonedx_sbom(
            result.repo_path,
            result.dependency_inventory,
            result.dependency_findings,
            generated_at=generated_at,
        ),
    )
    result_sections = build_result_sections(result)
    write_json(workspace / "result_sections.json", result_sections)
    sections_dir = workspace / "result_sections"
    sections_dir.mkdir(parents=True, exist_ok=True)
    for stale in sections_dir.glob("*.json"):
        if stale.is_file() and not stale.is_symlink():
            stale.unlink()
    for section_id, section in result_sections["sections"].items():
        write_json(sections_dir / f"{section_id}.json", section)


def extract_validation_runner_plans(results: list[VerificationResult]) -> list[dict]:
    """Persist normalized declarative plans separately from legacy human plans."""

    plans: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for verification in results:
        for entry in verification.request_log:
            if not isinstance(entry, dict) or entry.get("type") != "declarative_validation_plan":
                continue
            raw_plan = entry.get("plan")
            if not isinstance(raw_plan, dict):
                raw_plan = {key: value for key, value in entry.items() if key not in {"type", "verification_source"}}
            if not raw_plan:
                continue
            plan = dict(raw_plan)
            plan.setdefault("candidate_id", verification.candidate_id)
            identity = (verification.candidate_id, str(plan.get("id") or plan.get("plan_id") or len(plans)))
            if identity in seen:
                continue
            seen.add(identity)
            plans.append(plan)
    return plans
