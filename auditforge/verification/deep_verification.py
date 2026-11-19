from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from ..analysis.llm_candidates import LLMConfig, load_llm_json_response, parse_json_object, with_output_contract
from ..core.models import CodeFacts, RouteFact, TraceCandidate, VerificationResult, VerificationStatus
from ..core.snippets import candidate_flow_nodes, code_window, format_anchor
from .validation_dsl import (
    DeclarativeValidationPlan,
    EvidenceRecord,
    ValidationEvidenceResult,
    ValidationPlanError,
    ValidationStep,
    normalize_validation_plan,
)
from .validation_runner import ValidationRunnerConfig, dispatch_validation_plan
from .verification import infer_route_for_candidate

MAX_SANDBOX_SCRIPT_CHARS = 6000
MAX_SANDBOX_TESTS_PER_CANDIDATE = 2
MAX_VALIDATION_PLANS_PER_CANDIDATE = 2
# Docker Desktop on Windows can need several seconds simply to attach a cold
# container, even for a tiny no-network script.  The sandbox remains bounded
# by CPU/memory/PID limits; a realistic startup allowance avoids false
# "blocked" verification results.
SANDBOX_TIMEOUT_SECONDS = 25
CONTAINER_IMAGE_PULL_TIMEOUT_SECONDS = 180
DEFAULT_CONTAINER_IMAGE = "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
CONTAINER_RUNTIME_ENV = "AUDITFORGE_CONTAINER_RUNTIME"
CONTAINER_IMAGE_ENV = "AUDITFORGE_SANDBOX_IMAGE"
CONTAINER_RUNTIME_CHECK_TIMEOUT_ENV = "AUDITFORGE_CONTAINER_CHECK_TIMEOUT"

DEFAULT_DEEP_SYSTEM_PROMPT = (
    "你是资深白盒代码审计二次验证器，负责把 source-to-sink 候选转化为受限、声明式的运行验证计划。"
    "你的目标是减少误报：静态证据不足时只能返回 blocked 或 needs_manual_review，不能用自然语言推测代替运行证据。"
    "验证计划只能描述同源 HTTP 请求、响应断言，以及明确标记为占位能力的浏览器/OAST 步骤；不得输出任何可执行代码。"
    "只输出严格 JSON object；禁止 Shell、Python、JavaScript、Docker 命令、文件操作、凭据、真实破坏性 payload 或外部目标。"
    "XSS 需要隔离浏览器证据，SSRF 需要 OAST 回连证据，认证/授权需要身份对照；能力未配置时必须降级。"
)
DEFAULT_DEEP_USER_PROMPT = (
    "对一个 source-to-sink 候选进行二次深入验证。请阅读候选路径、源码片段和上下文，判断能否用无害 AF_MARKER、"
    "同源相对路径、受限 HTTP 方法和结构化响应断言获得真实运行证据。"
    "验证计划必须与候选路由和传播链直接对应；没有目标运行环境、需要凭据、浏览器、OAST、数据库准备或业务状态时，"
    "返回 blocked 或 needs_manual_review，并让 validationPlans 为空或使用明确的占位步骤。"
)
DEEP_VERIFIER_SYSTEM_PROMPT = DEFAULT_DEEP_SYSTEM_PROMPT
DEEP_OUTPUT_CONTRACT = """必须返回一个 JSON object，根对象必须包含：
- verdict: "confirmed" | "false_positive" | "not_reproducible" | "blocked" | "needs_manual_review"
- confidence: "low" | "medium" | "high"
- reason: non-empty Chinese string
- validationPlans: array，可为空；最多 2 个声明式计划
- evidence: string array，可为空
- limitations: string array，可为空
validationPlans[] 格式：
{"version":1,"id":"plan-id","candidate_id":"候选 ID","description":"说明","steps":[{"id":"request-1","action":"http_request","method":"GET","url":"/同源相对路径","query":{},"headers":{},"expected":{"status":200,"body_contains":"AF_MARKER"},"timeout_ms":5000}],"cleanup":{"strategy":"none","always":true}}
可把响应断言拆成后续步骤：{"id":"assert-1","action":"runtime_assert","request_id":"request-1","expected":{"body_contains":"AF_MARKER"}}。
只允许 http_request、runtime_assert、browser_assert、oast_probe；browser_assert 和 oast_probe 当前只是能力占位，不能据此声称已确认。
如果 verdict 是 confirmed、false_positive 或 not_reproducible，应提供直接支持结论的 validationPlans；无法安全执行时必须降级 verdict。
硬性禁止：
- 禁止输出 Markdown、自然语言前后缀、真实破坏性 payload、线上已复现结论或跨域 URL。
- 禁止输出脚本、代码、Shell、Docker 命令、凭据、Cookie、Authorization、文件路径或外部回连地址。
- 禁止把“LLM 觉得可能”作为 confirmed；confirmed 必须绑定真实 runner 证据，最终状态由平台保守决定。"""

SANDBOX_RUNNER = r"""
import json
import sys

script = sys.stdin.read()
prints = []
sink_calls = []

def safe_print(*args, **kwargs):
    prints.append(" ".join(str(item) for item in args)[:500])

def safe_sink(*args, **kwargs):
    sink_calls.append({
        "args": [repr(item)[:300] for item in args],
        "kwargs": {str(key): repr(value)[:300] for key, value in kwargs.items()},
    })
    return True

safe_builtins = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "chr": chr,
    "dict": dict,
    "enumerate": enumerate,
    "Exception": Exception,
    "float": float,
    "int": int,
    "isinstance": isinstance,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "range": range,
    "repr": repr,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "print": safe_print,
    "sink": safe_sink,
}

scope = {"__builtins__": safe_builtins}

try:
    exec(compile(script, "<auditforge-sandbox>", "exec"), scope, scope)
    exports = {}
    for key, value in scope.items():
        if key.startswith("__") or key in {"safe_builtins"}:
            continue
        if key.startswith(("result", "observed", "verdict", "evidence")):
            exports[key] = repr(value)[:500]
    print(json.dumps({"ok": True, "prints": prints[:12], "exports": exports, "sink_calls": sink_calls[:12]}, ensure_ascii=False))
except AssertionError as exc:
    print(json.dumps({"ok": False, "error": "AssertionError: " + str(exc), "prints": prints[:12]}, ensure_ascii=False))
    sys.exit(1)
except Exception as exc:
    print(json.dumps({"ok": False, "error": type(exc).__name__ + ": " + str(exc), "prints": prints[:12]}, ensure_ascii=False))
    sys.exit(1)
"""

DISALLOWED_NODES = (
    ast.AsyncFor,
    ast.AsyncFunctionDef,
    ast.AsyncWith,
    ast.Await,
    ast.ClassDef,
    ast.Delete,
    ast.Global,
    ast.Import,
    ast.ImportFrom,
    ast.Lambda,
    ast.Nonlocal,
    ast.Raise,
    ast.With,
    ast.Yield,
    ast.YieldFrom,
)

DANGEROUS_NAMES = {
    "__builtins__",
    "__import__",
    "breakpoint",
    "compile",
    "dir",
    "eval",
    "exec",
    "getattr",
    "globals",
    "input",
    "locals",
    "object",
    "open",
    "setattr",
    "super",
    "type",
    "vars",
}

SAFE_BUILTIN_NAMES = {
    "abs",
    "all",
    "any",
    "bool",
    "chr",
    "dict",
    "enumerate",
    "Exception",
    "float",
    "int",
    "isinstance",
    "len",
    "list",
    "max",
    "min",
    "print",
    "range",
    "repr",
    "set",
    "sink",
    "sorted",
    "str",
    "sum",
    "tuple",
}

DANGEROUS_ATTRS = {
    "func_globals",
    "func_code",
    "gi_frame",
    "gi_code",
    "f_globals",
    "f_locals",
    "mro",
    "subclasses",
}


class SandboxPolicyError(ValueError):
    pass


class ContainerRuntimeError(RuntimeError):
    pass


READY_CONTAINER_RUNTIMES: set[str] = set()
READY_CONTAINER_IMAGES: set[tuple[str, str]] = set()
CONTAINER_IMAGE_LOCK = threading.Lock()


class ConcurrencyTracker:
    """Thread-safe counter used to report real queue concurrency."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active = 0
        self.maximum = 0

    def enter(self) -> None:
        with self._lock:
            self._active += 1
            self.maximum = max(self.maximum, self._active)

    def exit(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)


def tracked_call(tracker: ConcurrencyTracker, function, *args):  # noqa: ANN001, ANN201 - internal executor adapter
    tracker.enter()
    try:
        return function(*args)
    finally:
        tracker.exit()


def verification_priority(candidate: TraceCandidate, original_index: int = 0) -> tuple[int, int, int, int, str, int, int, int]:
    # Deterministic evidence must not be starved by a full batch of LLM candidates.
    origin_rank = 0 if getattr(candidate, "origin", "deterministic") == "deterministic" else 1
    confidence_rank = {"high": 0, "medium": 1, "low": 2}.get(str(candidate.confidence), 3)
    vuln_rank = {"authz": 0, "ssrf": 1, "injection": 2, "xss": 3, "auth": 4}.get(str(candidate.vuln_class), 5)
    route_rank = 0 if getattr(candidate, "route_id", None) else 1
    return (
        origin_rank,
        confidence_rank,
        vuln_rank,
        route_rank,
        candidate.source.file,
        candidate.source.start_line,
        candidate.sink.start_line,
        original_index,
    )


def select_deep_verification_candidates(candidates: list[TraceCandidate], max_candidates: int) -> list[TraceCandidate]:
    if not candidates:
        return []
    limit = max(1, min(max_candidates, len(candidates)))
    indexed = list(enumerate(candidates))
    deterministic = sorted(
        (item for item in indexed if getattr(item[1], "origin", "deterministic") == "deterministic"),
        key=lambda item: verification_priority(item[1], item[0]),
    )
    llm = sorted(
        (item for item in indexed if getattr(item[1], "origin", "deterministic") == "llm"),
        key=lambda item: verification_priority(item[1], item[0]),
    )
    if deterministic and llm and limit > 1:
        deterministic_quota = (limit + 1) // 2
        selected = deterministic[:deterministic_quota] + llm[: limit - deterministic_quota]
        selected_ids = {index for index, _ in selected}
        remaining = sorted(
            (item for item in indexed if item[0] not in selected_ids),
            key=lambda item: verification_priority(item[1], item[0]),
        )
        selected.extend(remaining[: limit - len(selected)])
        selected.sort(key=lambda item: verification_priority(item[1], item[0]))
    else:
        selected = sorted(indexed, key=lambda item: verification_priority(item[1], item[0]))[:limit]
    return [candidate for _, candidate in selected]


def run_deep_verification(
    repo_path: Path,
    candidates: list[TraceCandidate],
    config: LLMConfig | None,
    *,
    sandbox_concurrency: int | None = None,
    target_url: str | None = None,
    allow_state_changes: bool = False,
    validation_runner_config: ValidationRunnerConfig | None = None,
    code_facts: CodeFacts | None = None,
) -> tuple[list[VerificationResult], dict[str, Any]]:
    runner_config, runner_config_error = resolve_validation_runner_config(validation_runner_config)
    configured_validation_workers = resolve_sandbox_concurrency(config, sandbox_concurrency)
    diagnostics: dict[str, Any] = {
        "enabled": bool(config and config.enabled),
        "provider": config.provider if config else None,
        "model": config.model if config else None,
        "tested": 0,
        "validation_tasks": 0,
        "validation_runtime_confirmed": 0,
        "validation_not_reproduced": 0,
        "validation_inconclusive": 0,
        "validation_blocked": 0,
        "validation_errors": 0,
        "validation_runner": validation_runner_diagnostics(runner_config, runner_config_error),
        "target_configured": bool(target_url),
        "allow_state_changes": bool(allow_state_changes),
        "route_binding": route_binding_diagnostics([], code_facts),
        "legacy_sandbox_tests": 0,
        # These fields remain readable for older UI/report code. New scans do
        # not execute LLM-authored Python and therefore always report zero.
        "sandbox_passed": 0,
        "sandbox_failed": 0,
        "sandbox_blocked": 0,
        "sandbox_tasks": 0,
        "sandbox_proof_valid": 0,
        "sandbox_negative_proof_valid": 0,
        "sandbox_executed": 0,
        "sandbox_isolation": "legacy_disabled",
        "sandbox_image": None,
        "container_runtime": None,
        "container_runtime_ready": None,
        "container_runtime_error": None,
        "selected_candidate_ids": [],
        "concurrency": 0,
        "llm_concurrency": 0,
        "sandbox_concurrency": 0,
        "sandbox_concurrency_configured": configured_validation_workers,
        "validation_concurrency": 0,
        "validation_concurrency_configured": configured_validation_workers,
        "llm_max_concurrency_observed": 0,
        "sandbox_max_concurrency_observed": 0,
        "validation_max_concurrency_observed": 0,
        "max_concurrency_observed": 0,
        "errors": [],
    }
    if not config or not config.enabled:
        return [], diagnostics

    selected_candidates = select_deep_verification_candidates(candidates, config.max_candidates)
    diagnostics["selected_candidate_ids"] = [candidate.id for candidate in selected_candidates]
    route_by_id = {route.id: route for route in code_facts.routes} if code_facts is not None else {}
    diagnostics["route_binding"] = route_binding_diagnostics(selected_candidates, code_facts, route_by_id=route_by_id)
    llm_workers = bounded_worker_count(config, len(selected_candidates))
    diagnostics["concurrency"] = llm_workers  # backward-compatible field
    diagnostics["llm_concurrency"] = llm_workers

    # Stage 1 performs only LLM IO and declarative schema validation. No model
    # output is executed as source code in this process or in a container.
    llm_tracker = ConcurrencyTracker()
    prepared_reviews: list[dict[str, Any] | None] = [None] * len(selected_candidates)
    with ThreadPoolExecutor(max_workers=llm_workers, thread_name_prefix="auditforge-deep-llm") as executor:
        future_map = {
            executor.submit(
                tracked_call,
                llm_tracker,
                prepare_candidate_deep_review,
                repo_path,
                candidate,
                config,
                target_url,
                allow_state_changes,
                find_candidate_route(candidate, code_facts, route_by_id=route_by_id),
            ): (
                index,
                candidate,
            )
            for index, candidate in enumerate(selected_candidates)
        }
        for future in as_completed(future_map):
            index, candidate = future_map[future]
            diagnostics["tested"] += 1
            try:
                prepared_reviews[index] = future.result()
            except Exception as exc:  # noqa: BLE001 - isolate one provider failure from the queue
                diagnostics["errors"].append({"candidate_id": candidate.id, "stage": "llm", "error": str(exc)})
                prepared_reviews[index] = {
                    "candidate": candidate,
                    "validation_plans": [],
                    "legacy_tests": [],
                    "immediate_result": blocked_deep_result(candidate, exc),
                }

    # Stage 2 dispatches validated plans independently. In queue mode the
    # dashboard only writes a JSON job and waits for the isolated runner.
    validation_jobs: list[tuple[int, int, DeclarativeValidationPlan]] = []
    validation_results: dict[int, list[ValidationEvidenceResult | None]] = {}
    for review_index, review in enumerate(prepared_reviews):
        if not review or review.get("immediate_result") is not None:
            continue
        plans = list(review.get("validation_plans") or [])[:MAX_VALIDATION_PLANS_PER_CANDIDATE]
        validation_results[review_index] = [None] * len(plans)
        validation_jobs.extend((review_index, plan_index, plan) for plan_index, plan in enumerate(plans))
        diagnostics["legacy_sandbox_tests"] += len(review.get("legacy_tests") or review.get("tests") or [])

    diagnostics["validation_tasks"] = len(validation_jobs)
    validation_workers = bounded_sandbox_worker_count(configured_validation_workers, len(validation_jobs))
    diagnostics["validation_concurrency"] = validation_workers
    validation_tracker = ConcurrencyTracker()
    if validation_jobs:
        with ThreadPoolExecutor(max_workers=validation_workers, thread_name_prefix="auditforge-validation") as executor:
            future_map = {
                executor.submit(
                    tracked_call,
                    validation_tracker,
                    dispatch_prepared_validation,
                    plan,
                    target_url,
                    allow_state_changes,
                    runner_config,
                    runner_config_error,
                ): (review_index, plan_index, plan)
                for review_index, plan_index, plan in validation_jobs
            }
            for future in as_completed(future_map):
                review_index, plan_index, plan = future_map[future]
                try:
                    validation_result = future.result()
                except Exception as exc:  # noqa: BLE001 - preserve other independent runner results
                    validation_result = validation_exception_result(plan, exc)
                    candidate = prepared_reviews[review_index]["candidate"]  # type: ignore[index]
                    diagnostics["errors"].append(
                        {"candidate_id": candidate.id, "stage": "validation_runner", "plan": plan.id, "error": str(exc)}
                    )
                validation_results[review_index][plan_index] = validation_result

    ordered_results: list[VerificationResult] = []
    for review_index, review in enumerate(prepared_reviews):
        if not review:
            continue
        immediate_result = review.get("immediate_result")
        result = immediate_result or finalize_candidate_deep_review(
            review,
            [item for item in validation_results.get(review_index, []) if item is not None],
            validation_runner_config=runner_config,
        )
        if result.status == "sandbox_executed":
            diagnostics["sandbox_executed"] += 1
        ordered_results.append(result)

    all_validation_results = [item for items in validation_results.values() for item in items if item is not None]
    diagnostics["validation_runtime_confirmed"] = sum(1 for item in all_validation_results if item.status == "runtime_confirmed")
    diagnostics["validation_not_reproduced"] = sum(1 for item in all_validation_results if item.status == "not_reproduced")
    diagnostics["validation_inconclusive"] = sum(1 for item in all_validation_results if item.status == "inconclusive")
    diagnostics["validation_blocked"] = sum(1 for item in all_validation_results if item.status == "blocked")
    diagnostics["validation_errors"] = sum(1 for item in all_validation_results if item.status == "error")
    diagnostics["llm_max_concurrency_observed"] = llm_tracker.maximum
    diagnostics["validation_max_concurrency_observed"] = validation_tracker.maximum
    diagnostics["max_concurrency_observed"] = max(llm_tracker.maximum, validation_tracker.maximum)
    return ordered_results, diagnostics


def blocked_deep_result(candidate: TraceCandidate, exc: Exception) -> VerificationResult:
    return VerificationResult(
        candidate_id=candidate.id,
        status="blocked",
        evidence=[f"二次深入验证失败：{exc}"],
        notes="LLM 或声明式 runner 阶段异常。",
    )


def find_candidate_route(
    candidate: TraceCandidate,
    code_facts: CodeFacts | None,
    *,
    route_by_id: dict[str, RouteFact] | None = None,
) -> RouteFact | None:
    if code_facts is None:
        return None
    route: RouteFact | None = None
    if candidate.route_id:
        if route_by_id is not None:
            route = route_by_id.get(candidate.route_id)
        else:
            route = next((item for item in code_facts.routes if item.id == candidate.route_id), None)
    return route or infer_route_for_candidate(code_facts, candidate)


def route_binding_diagnostics(
    candidates: list[TraceCandidate],
    code_facts: CodeFacts | None,
    *,
    route_by_id: dict[str, RouteFact] | None = None,
) -> dict[str, Any]:
    route_by_id = route_by_id if route_by_id is not None else ({route.id: route for route in code_facts.routes} if code_facts else {})
    bound: list[str] = []
    unbound: list[dict[str, str]] = []
    for candidate in candidates:
        route = find_candidate_route(candidate, code_facts, route_by_id=route_by_id)
        if route is not None:
            bound.append(candidate.id)
            continue
        if code_facts is None:
            reason = "code_facts_not_provided"
        elif not candidate.route_id:
            reason = "candidate_missing_route_id_and_inference_failed"
        else:
            reason = "route_id_not_found_and_inference_failed"
        unbound.append({"candidate_id": candidate.id, "reason": reason})
    return {
        "code_facts_provided": code_facts is not None,
        "bound": len(bound),
        "unbound": len(unbound),
        "bound_candidate_ids": bound,
        "unbound_candidates": unbound,
        "confirmation_requires_bound_route": True,
    }


def resolve_validation_runner_config(
    configured: ValidationRunnerConfig | None,
) -> tuple[ValidationRunnerConfig, str | None]:
    if configured is not None:
        return configured, None
    try:
        return ValidationRunnerConfig.from_environment(), None
    except (OSError, ValueError) as exc:
        return ValidationRunnerConfig(mode="disabled"), str(exc)


def validation_runner_diagnostics(config: ValidationRunnerConfig, config_error: str | None) -> dict[str, Any]:
    if config_error:
        return {
            "mode": "disabled",
            "configured": False,
            "configuration_error": config_error,
        }
    try:
        return config.public_diagnostics()
    except (OSError, ValueError) as exc:
        return {
            "mode": config.mode,
            "configured": config.mode != "disabled",
            "configuration_error": str(exc),
        }


def blocked_validation_result(plan: DeclarativeValidationPlan, message: str) -> ValidationEvidenceResult:
    step = plan.steps[0]
    return ValidationEvidenceResult(
        plan_id=plan.id,
        candidate_id=plan.candidate_id,
        status="blocked",
        evidence=(
            EvidenceRecord(
                step_id=step.id,
                action=step.action,
                status="blocked",
                summary=message[:2_000],
            ),
        ),
        cleanup_status="not_run" if plan.cleanup.strategy != "none" else "not_required",
        notes="声明式计划未执行；未运行任何 LLM 生成的脚本或命令。",
    )


def dispatch_prepared_validation(
    plan: DeclarativeValidationPlan,
    target_url: str | None,
    allow_state_changes: bool,
    runner_config: ValidationRunnerConfig,
    runner_config_error: str | None,
) -> ValidationEvidenceResult:
    if runner_config_error:
        return blocked_validation_result(plan, f"声明式 runner 配置无效：{runner_config_error}")
    if not target_url:
        return blocked_validation_result(plan, "未提供受控 target_url，声明式运行验证未执行。")
    try:
        return dispatch_validation_plan(
            plan,
            target_url=target_url,
            allow_state_changes=allow_state_changes,
            config=runner_config,
        )
    except (OSError, TimeoutError, ValueError, ValidationPlanError) as exc:
        return validation_exception_result(plan, exc)


def validation_exception_result(plan: DeclarativeValidationPlan, exc: Exception) -> ValidationEvidenceResult:
    step = plan.steps[0]
    return ValidationEvidenceResult(
        plan_id=plan.id,
        candidate_id=plan.candidate_id,
        status="error",
        evidence=(
            EvidenceRecord(
                step_id=step.id,
                action=step.action,
                status="error",
                summary=f"声明式 runner 执行异常：{exc}"[:2_000],
            ),
        ),
        cleanup_status="not_run",
        notes="runner 异常已隔离到当前计划；未执行任意脚本。",
    )


def bounded_worker_count(config: LLMConfig, task_count: int) -> int:
    if task_count <= 0:
        return 1
    return max(1, min(task_count, 12, int(getattr(config, "concurrency", 1) or 1)))


def resolve_sandbox_concurrency(config: LLMConfig | None, explicit: int | None = None) -> int:
    """Resolve sandbox capacity without breaking older LLMConfig callers."""

    value = explicit
    if value is None and config is not None:
        value = getattr(config, "sandbox_concurrency", None)
    if value is None and config is not None:
        value = getattr(config, "concurrency", 1)
    try:
        return max(1, min(12, int(value or 1)))
    except (TypeError, ValueError):
        return 1


def bounded_sandbox_worker_count(configured: int, task_count: int) -> int:
    if task_count <= 0:
        return 0
    return max(1, min(task_count, 12, configured))


def verify_candidate_with_llm_sandbox(
    repo_path: Path,
    candidate: TraceCandidate,
    config: LLMConfig,
    *,
    target_url: str | None = None,
    allow_state_changes: bool = False,
    validation_runner_config: ValidationRunnerConfig | None = None,
    code_facts: CodeFacts | None = None,
) -> VerificationResult:
    """Compatibility entry point using the declarative runner.

    The historical function name is retained for callers, but new model
    responses are never executed as Python sandbox scripts.
    """

    runner_config, runner_error = resolve_validation_runner_config(validation_runner_config)
    review = prepare_candidate_deep_review(
        repo_path,
        candidate,
        config,
        target_url,
        allow_state_changes,
        find_candidate_route(candidate, code_facts),
    )
    if review.get("immediate_result") is not None:
        return review["immediate_result"]
    plans = list(review.get("validation_plans") or [])[:MAX_VALIDATION_PLANS_PER_CANDIDATE]
    workers = bounded_sandbox_worker_count(resolve_sandbox_concurrency(config), len(plans))
    if workers <= 1:
        validation_results = [
            dispatch_prepared_validation(plan, target_url, allow_state_changes, runner_config, runner_error) for plan in plans
        ]
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="auditforge-validation") as executor:
            validation_results = list(
                executor.map(
                    lambda plan: dispatch_prepared_validation(
                        plan,
                        target_url,
                        allow_state_changes,
                        runner_config,
                        runner_error,
                    ),
                    plans,
                )
            )
    return finalize_candidate_deep_review(
        review,
        validation_results,
        validation_runner_config=runner_config,
    )


def prepare_candidate_deep_review(
    repo_path: Path,
    candidate: TraceCandidate,
    config: LLMConfig,
    target_url: str | None = None,
    allow_state_changes: bool = False,
    allowed_route: RouteFact | None = None,
) -> dict[str, Any]:
    prompt = build_deep_verification_prompt(
        repo_path,
        candidate,
        config.user_prompt,
        target_url=target_url,
        allow_state_changes=allow_state_changes,
        allowed_route=allowed_route,
    )
    started = time.monotonic()
    system_prompt = with_output_contract(
        (config.system_prompt or DEFAULT_DEEP_SYSTEM_PROMPT).strip() or DEFAULT_DEEP_SYSTEM_PROMPT,
        DEEP_OUTPUT_CONTRACT,
    )
    raw = load_llm_json_response(prompt, config, system_prompt=system_prompt, temperature=0)
    parsed = parse_json_object(raw)
    llm_latency_ms = int((time.monotonic() - started) * 1000)
    schema_errors = validate_deep_response_schema(
        parsed,
        target_url=target_url,
        candidate_id=candidate.id,
        allowed_route=allowed_route,
    )
    if schema_errors:
        return {
            "candidate": candidate,
            "validation_plans": [],
            "legacy_tests": [],
            "immediate_result": VerificationResult(
                candidate_id=candidate.id,
                status="blocked",
                evidence=[
                    "LLM 二次验证输出格式不符合 JSON 契约，已拒绝自动确认。",
                    "格式错误：" + "；".join(schema_errors[:5]),
                ],
                request_log=[
                    {
                        "type": "llm_deep_review",
                        "schema_valid": False,
                        "schema_errors": schema_errors,
                        "latency_ms": llm_latency_ms,
                        "root_keys": sorted(str(key) for key in parsed.keys())[:20],
                    }
                ],
                notes="fail-closed：格式不合规的 LLM 输出不能进入二次确认漏洞区。",
            ),
        }
    verdict = normalize_verdict(parsed.get("verdict"))
    confidence = str(parsed.get("confidence") or "low")
    reason = str(parsed.get("reason") or "LLM 未提供详细原因。")
    plans_raw = extract_validation_plans(parsed)
    plans = normalize_validation_plans(
        plans_raw,
        candidate_id=candidate.id,
        target_url=target_url,
        allowed_route=allowed_route,
    )
    legacy_tests = normalize_sandbox_tests(parsed.get("sandboxTests") or parsed.get("sandbox_tests"))
    return {
        "candidate": candidate,
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "validation_plans": plans[:MAX_VALIDATION_PLANS_PER_CANDIDATE],
        "legacy_tests": legacy_tests[:MAX_SANDBOX_TESTS_PER_CANDIDATE],
        "route_bound": allowed_route is not None,
        "review_evidence": [str(item) for item in parsed.get("evidence") or []],
        "limitations": [str(item) for item in parsed.get("limitations") or []],
        "llm_latency_ms": llm_latency_ms,
        "immediate_result": None,
    }


def finalize_candidate_deep_review(
    review: dict[str, Any],
    validation_results: list[ValidationEvidenceResult],
    *,
    validation_runner_config: ValidationRunnerConfig | None = None,
) -> VerificationResult:
    candidate: TraceCandidate = review["candidate"]
    verdict = normalize_verdict(review.get("verdict"))
    confidence = str(review.get("confidence") or "low")
    reason = str(review.get("reason") or "LLM 未提供详细原因。")
    plans: list[DeclarativeValidationPlan] = list(review.get("validation_plans") or [])
    legacy_tests = list(review.get("legacy_tests") or review.get("tests") or [])
    route_bound = bool(review.get("route_bound"))
    status = decide_declarative_status(
        candidate,
        verdict,
        plans,
        validation_results,
        legacy_tests=legacy_tests,
        route_bound=route_bound,
    )
    evidence = [
        f"LLM 二次判断：{status_to_chinese(verdict)}（置信度：{confidence}）。",
        f"判断依据：{reason}",
    ]
    for item in review.get("review_evidence") or []:
        evidence.append(f"静态复核证据：{item}")
    if plans:
        counts: dict[str, int] = {}
        for item in validation_results:
            counts[item.status] = counts.get(item.status, 0) + 1
        summary = "，".join(f"{name}={count}" for name, count in sorted(counts.items())) or "未返回结果"
        evidence.append(f"声明式运行验证：计划 {len(plans)} 个；{summary}。")
    else:
        evidence.append("LLM 未给出可执行的声明式验证计划，未获得目标运行时证据。")
    for item in validation_results[:2]:
        first = item.evidence[0].summary if item.evidence else item.notes or "无步骤证据"
        evidence.append(f"计划 {item.plan_id}：{item.status}；{first}")
    if any(item.status == "runtime_confirmed" for item in validation_results) and status != "confirmed":
        evidence.append("runner 断言通过，但证据类型未满足该漏洞类别的自动确认门禁，候选保留为人工复核。")
    if plans and not route_bound:
        evidence.append("计划未绑定到候选 route_id 对应的已解析路由，运行结果不能自动确认漏洞。")
    if verdict in {"false_positive", "not_reproducible"} and status == "needs_manual_review":
        evidence.append("负面结论缺少类别匹配的真实运行证据，候选继续保留并转人工复核。")
    if legacy_tests:
        evidence.append(f"检测到 {len(legacy_tests)} 个历史 sandboxTests；为避免执行 LLM 生成代码，本次仅保留记录并阻断执行。")
    for limitation in review.get("limitations") or []:
        evidence.append(f"限制：{limitation}")

    request_log = [
        {
            "type": "llm_deep_review",
            "verdict": verdict,
            "confidence": confidence,
            "latency_ms": int(review.get("llm_latency_ms") or 0),
            "reason": reason[:1000],
        }
    ]
    runner_diagnostics = (
        validation_runner_diagnostics(validation_runner_config, None)
        if validation_runner_config is not None
        else {"mode": "unknown", "configured": False}
    )
    results_by_plan = {item.plan_id: item for item in validation_results}
    for plan in plans:
        request_log.append({"type": "declarative_validation_plan", "plan": plan.to_dict()})
        result = results_by_plan.get(plan.id)
        if result is not None:
            request_log.append(
                {
                    "type": "declarative_validation_result",
                    "runner": runner_diagnostics,
                    "result": result.to_dict(),
                }
            )
    request_log.extend(legacy_sandbox_disabled_result(test) for test in legacy_tests)
    return VerificationResult(
        candidate_id=candidate.id,
        status=status,
        evidence=evidence,
        request_log=request_log,
        notes="二次深入验证只执行已验证的声明式计划；历史 LLM Python 测试不会被执行。",
    )


def legacy_sandbox_disabled_result(test: dict[str, str]) -> dict[str, Any]:
    return {
        "type": "sandbox_python",
        "legacy": True,
        "execution_disabled": True,
        "name": test.get("name") or "历史沙箱测试",
        "expected": test.get("expected") or "",
        "code": test.get("code") or "",
        "ok": False,
        "blocked": True,
        "policy_error": "历史 sandboxTests 仅兼容读取；新扫描禁止执行 LLM 生成的任意 Python。",
    }


def extract_validation_plans(parsed: dict[str, Any]) -> Any:
    for key in ("validationPlans", "validation_plans", "verificationPlans", "verification_plans"):
        if key in parsed:
            return parsed[key]
    return None


def normalize_validation_plans(
    raw: Any,
    *,
    candidate_id: str | None,
    target_url: str | None,
    allowed_route: RouteFact | None = None,
) -> list[DeclarativeValidationPlan]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValidationPlanError("must be an array", path="validationPlans")
    if len(raw) > MAX_VALIDATION_PLANS_PER_CANDIDATE:
        raise ValidationPlanError(
            f"must contain at most {MAX_VALIDATION_PLANS_PER_CANDIDATE} plans",
            path="validationPlans",
        )
    plans: list[DeclarativeValidationPlan] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValidationPlanError("must be an object", path=f"validationPlans[{index}]")
        plan = normalize_validation_plan(item, target_url=target_url)
        if candidate_id is not None and plan.candidate_id != candidate_id:
            raise ValidationPlanError(
                "candidate_id must match the reviewed candidate",
                path=f"validationPlans[{index}].candidate_id",
            )
        if plan.id in seen_ids:
            raise ValidationPlanError("plan id must be unique", path=f"validationPlans[{index}].id")
        if allowed_route is not None:
            validate_plan_route_binding(plan, allowed_route, index=index)
        seen_ids.add(plan.id)
        plans.append(plan)
    return plans


def validate_plan_route_binding(plan: DeclarativeValidationPlan, route: RouteFact, *, index: int = 0) -> None:
    allowed_methods = set(parse_route_methods(route.method))
    if "ANY" in allowed_methods:
        allowed_methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
    if "GET" in allowed_methods:
        allowed_methods.add("HEAD")
    for step_index, step in enumerate(plan.steps):
        if step.action not in {"http_request", "browser_assert"} or not step.url:
            continue
        path = normalized_route_binding_path(step.url, plan_index=index, step_index=step_index)
        if not route_path_matches(route.path, path):
            raise ValidationPlanError(
                f"path {path!r} does not match candidate route {route.path!r}",
                path=f"validationPlans[{index}].steps[{step_index}].url",
            )
        if step.action == "http_request" and step.method and allowed_methods and step.method not in allowed_methods:
            raise ValidationPlanError(
                f"method {step.method} is not allowed by candidate route {route.method!r}",
                path=f"validationPlans[{index}].steps[{step_index}].method",
            )


def parse_route_methods(value: str) -> list[str]:
    methods: list[str] = []
    for item in re.findall(r"[A-Za-z]+", value or ""):
        normalized = item.upper()
        if normalized in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "ANY"} and normalized not in methods:
            methods.append(normalized)
    return methods


def normalized_route_binding_path(url: str, *, plan_index: int, step_index: int) -> str:
    path = urlsplit(url).path
    decoded = path
    for _ in range(3):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    if (
        decoded.startswith("//")
        or "\\" in decoded
        or any(ord(character) < 0x20 for character in decoded)
        or any(segment in {".", ".."} for segment in decoded.split("/"))
    ):
        raise ValidationPlanError(
            "path contains an encoded authority, traversal segment, backslash, or control character",
            path=f"validationPlans[{plan_index}].steps[{step_index}].url",
        )
    return decoded


def route_path_matches(route_path: str, request_path: str) -> bool:
    route = route_path or "/"
    route = re.sub(r"<(?:path|filepath):[A-Za-z_]\w*>", "__AF_PATH_PARAM__", route)
    route = re.sub(r"<(?:[A-Za-z_]\w*:)?[A-Za-z_]\w*>", "__AF_SEGMENT_PARAM__", route)
    route = re.sub(r"\{[^{}]+\}", "__AF_SEGMENT_PARAM__", route)
    route = re.sub(r"(?<=/):[A-Za-z_]\w*", "__AF_SEGMENT_PARAM__", route)
    pattern = re.escape(route)
    pattern = pattern.replace(re.escape("__AF_PATH_PARAM__"), ".+")
    pattern = pattern.replace(re.escape("__AF_SEGMENT_PARAM__"), "[^/]+")
    if route != "/":
        pattern += "/?"
    return re.fullmatch(pattern, request_path) is not None


def decide_declarative_status(
    candidate: TraceCandidate,
    verdict: VerificationStatus,
    plans: list[DeclarativeValidationPlan],
    results: list[ValidationEvidenceResult],
    *,
    legacy_tests: list[dict[str, str]] | None = None,
    route_bound: bool = False,
) -> VerificationStatus:
    """Map runner evidence to the existing public status vocabulary.

    A passed generic response assertion is not universally equivalent to a
    confirmed vulnerability. Each vulnerability class has an explicit proof
    channel so XSS, SSRF and authorization findings cannot be promoted by a
    simple HTTP status/body check.
    """

    legacy_tests = legacy_tests or []
    if not plans:
        if verdict == "blocked" or (legacy_tests and verdict in {"confirmed", "sandbox_confirmed"}):
            return "blocked"
        return "needs_manual_review"
    if not results:
        return "blocked"

    paired = {plan.id: plan for plan in plans}
    if verdict in {"confirmed", "sandbox_confirmed"}:
        if not route_bound:
            if all(result.status in {"blocked", "error"} for result in results):
                return "blocked"
            return "needs_manual_review"
        if any(validation_result_has_strong_confirmation(candidate, paired.get(result.plan_id), result) for result in results):
            return "confirmed"
        if all(result.status in {"blocked", "error"} for result in results):
            return "blocked"
        return "needs_manual_review"

    if verdict in {"false_positive", "not_reproducible"}:
        if not route_bound:
            return "needs_manual_review"
        if any(validation_result_has_safe_control(candidate, paired.get(result.plan_id), result) for result in results):
            return verdict
        if verdict == "not_reproducible" and any(
            validation_result_has_direct_nonreproduction(candidate, paired.get(result.plan_id), result) for result in results
        ):
            return "not_reproducible"
        return "needs_manual_review"

    if verdict == "blocked" or all(result.status in {"blocked", "error"} for result in results):
        return "blocked"
    return "needs_manual_review"


def validation_result_has_strong_confirmation(
    candidate: TraceCandidate,
    plan: DeclarativeValidationPlan | None,
    result: ValidationEvidenceResult,
) -> bool:
    if plan is None or result.status != "runtime_confirmed":
        return False
    passed_evidence = {item.step_id: item for item in result.evidence if item.status == "passed"}
    passed_steps = [step for step in plan.steps if step.id in passed_evidence]
    if candidate.vuln_class == "injection":
        return any(
            step.action in {"http_request", "runtime_assert"}
            and expected_has_positive_marker(step.expected)
            and assertion_request_has_marker(plan, step)
            and evidence_has_assertion_result(
                passed_evidence[step.id],
                {"body_contains", "json_contains", "json_path_equals"},
                True,
            )
            for step in passed_steps
        )
    if candidate.vuln_class == "xss":
        return any(step.action == "browser_assert" for step in passed_steps)
    if candidate.vuln_class == "ssrf":
        return any(step.action == "oast_probe" for step in passed_steps)
    if candidate.vuln_class in {"auth", "authz"}:
        identities = {step.identity for step in passed_steps if step.identity}
        return len(identities) >= 2
    return False


def validation_result_has_safe_control(
    candidate: TraceCandidate,
    plan: DeclarativeValidationPlan | None,
    result: ValidationEvidenceResult,
) -> bool:
    if plan is None or result.status != "runtime_confirmed":
        return False
    passed_evidence = {item.step_id: item for item in result.evidence if item.status == "passed"}
    passed_steps = [step for step in plan.steps if step.id in passed_evidence]
    if candidate.vuln_class == "injection":
        return any(
            step.action in {"http_request", "runtime_assert"}
            and expected_has_negative_marker(step.expected)
            and assertion_request_has_marker(plan, step)
            and evidence_has_assertion_result(passed_evidence[step.id], {"body_not_contains"}, True)
            for step in passed_steps
        )
    if candidate.vuln_class == "xss":
        return any(
            step.action == "browser_assert" and ("selector_not_exists" in step.expected or "text_not_contains" in step.expected)
            for step in passed_steps
        )
    if candidate.vuln_class == "ssrf":
        return any(step.action == "oast_probe" and step.expected.get("interaction_received") is False for step in passed_steps)
    if candidate.vuln_class in {"auth", "authz"}:
        identities = {step.identity for step in passed_steps if step.identity}
        denied = any(expected_has_denial_status(step.expected) for step in passed_steps)
        return len(identities) >= 2 and denied
    return False


def validation_result_has_direct_nonreproduction(
    candidate: TraceCandidate,
    plan: DeclarativeValidationPlan | None,
    result: ValidationEvidenceResult,
) -> bool:
    if plan is None or result.status != "not_reproduced":
        return False
    failed_evidence = {item.step_id: item for item in result.evidence if item.status == "failed" and item.observed}
    failed_steps = [step for step in plan.steps if step.id in failed_evidence]
    if candidate.vuln_class == "injection":
        return any(
            step.action in {"http_request", "runtime_assert"}
            and expected_has_positive_marker(step.expected)
            and assertion_request_has_marker(plan, step)
            and evidence_has_assertion_result(
                failed_evidence[step.id],
                {"body_contains", "json_contains", "json_path_equals"},
                False,
            )
            for step in failed_steps
        )
    if candidate.vuln_class == "xss":
        return any(step.action == "browser_assert" for step in failed_steps)
    if candidate.vuln_class == "ssrf":
        return any(step.action == "oast_probe" for step in failed_steps)
    if candidate.vuln_class in {"auth", "authz"}:
        identities = {step.identity for step in plan.steps if step.identity}
        return len(identities) >= 2 and any(step.id in failed_evidence for step in plan.steps)
    return False


def evidence_has_assertion_result(
    evidence: EvidenceRecord,
    assertion_names: set[str],
    expected_value: bool,
) -> bool:
    observed = evidence.observed
    status = observed.get("status")
    assertions = observed.get("assertions")
    return (
        isinstance(observed.get("method"), str)
        and isinstance(observed.get("url"), str)
        and isinstance(status, int)
        and 200 <= status < 300
        and isinstance(assertions, dict)
        and any(assertions.get(name) is expected_value for name in assertion_names)
    )


def expected_has_positive_marker(expected: dict[str, Any]) -> bool:
    return any(json_value_contains_marker(expected.get(key)) for key in ("body_contains", "json_contains", "json_path_equals"))


def expected_has_negative_marker(expected: dict[str, Any]) -> bool:
    return json_value_contains_marker(expected.get("body_not_contains"))


def assertion_request_has_marker(plan: DeclarativeValidationPlan, assertion_step: ValidationStep) -> bool:
    if assertion_step.action == "http_request":
        request_step = assertion_step
    else:
        request_step = next(
            (step for step in plan.steps if step.id == assertion_step.request_id and step.action == "http_request"),
            None,
        )
    if request_step is None:
        return False
    return any(
        json_value_contains_marker(value) for value in (request_step.url, request_step.query, request_step.body, request_step.headers)
    )


def json_value_contains_marker(value: Any) -> bool:
    if isinstance(value, str):
        return "AF_MARKER" in value
    if isinstance(value, list):
        return any(json_value_contains_marker(item) for item in value)
    if isinstance(value, dict):
        return any(json_value_contains_marker(item) for item in value.values())
    return False


def expected_has_denial_status(expected: dict[str, Any]) -> bool:
    status = expected.get("status", expected.get("status_code"))
    if status in {401, 403, 404}:
        return True
    status_in = expected.get("status_in")
    return isinstance(status_in, list) and bool(status_in) and set(status_in).issubset({401, 403, 404})


def sandbox_exception_result(test: dict[str, str], exc: Exception) -> dict[str, Any]:
    return {
        "type": "sandbox_python",
        "name": test.get("name") or "沙箱测试",
        "expected": test.get("expected") or "",
        "code": test.get("code") or "",
        "ok": False,
        "blocked": True,
        "runtime_error": f"沙箱执行异常：{exc}",
    }


def build_deep_verification_prompt(
    repo_path: Path,
    candidate: TraceCandidate,
    custom_instructions: str | None = None,
    *,
    target_url: str | None = None,
    allow_state_changes: bool = False,
    allowed_route: RouteFact | None = None,
) -> str:
    nodes = []
    for node in candidate_flow_nodes(candidate.to_dict()):
        snippet = code_window(str(repo_path), node["anchor"], context=2)
        nodes.append(
            {
                "role": node.get("role"),
                "title": node.get("title"),
                "anchor": format_anchor(node["anchor"]),
                "edge": node.get("edge"),
                "code": "\n".join(f"{line.number}: {line.text}" for line in snippet.lines) if not snippet.error else snippet.error,
            }
        )
    prompt = {
        "role": "security_audit_deep_verifier",
        "task": (custom_instructions or DEFAULT_DEEP_USER_PROMPT).strip() or DEFAULT_DEEP_USER_PROMPT,
        "rules": [
            "只输出 JSON object，不要 Markdown。",
            "只输出声明式 validationPlans；禁止输出 Python、JavaScript、Shell、Docker 命令或其他可执行代码。",
            "HTTP URL 只能是以一个 / 开头的同源相对路径；禁止协议、主机、凭据、Cookie、Authorization 和跨域地址。",
            "只使用无害 AF_MARKER 或最小标识值，不生成真实攻击 payload，不写入生产数据。",
            "计划必须直接对应 codeFlow 中的路由、参数、source、sink 与防护；不能凭空发明接口或业务状态。",
            "缺少目标、登录态、数据库准备、浏览器、OAST 或业务前置条件时，返回 blocked/needs_manual_review。",
            "模型 verdict 只是建议；最终状态由 runner 的结构化证据和类别门禁决定。",
        ],
        "runtimeCapabilities": {
            "targetConfigured": bool(target_url),
            "allowStateChangesRequested": bool(allow_state_changes),
            "candidateRouteBound": allowed_route is not None,
            "allowedRoute": (
                {
                    "id": allowed_route.id,
                    "method": allowed_route.method,
                    "path": allowed_route.path,
                    "framework": allowed_route.framework,
                }
                if allowed_route is not None
                else None
            ),
            "executableNow": ["http_request", "runtime_assert"],
            "explicitPlaceholders": ["browser_assert", "oast_probe"],
            "runnerRestrictions": [
                "同源 HTTP(S)，禁止重定向",
                "响应大小、步骤数、header、body 和超时均有限制",
                "不执行源码、脚本、Shell 或 Docker 命令",
                "不接受 Cookie、Authorization、代理头或嵌入式凭据",
                "状态变更需要 cleanup；未配置可信 cleanup provider 时 runner 会阻断",
            ],
        },
        "verdictDecisionTree": [
            "先确认 codeFlow 是否给出可定位的入口路由、参数和预期可观察结果。",
            "有目标且只需无副作用同源 GET/HEAD 时，生成最小 HTTP 请求和直接响应断言。",
            "需要 POST/PUT/PATCH/DELETE 时必须声明 cleanup；不确定清理可行性就返回 blocked。",
            "XSS 需要 browser_assert，SSRF 需要 oast_probe，认证/授权需要至少两个 identity 对照；能力未配置时不要 confirmed。",
            "负面结论必须由真实安全控制结果支持；单纯请求失败、超时、404 或环境异常不能证明 false_positive。",
            "没有类别匹配的运行证据时返回 needs_manual_review，而不是 confirmed。",
        ],
        "candidateRiskModel": {
            "injection": "证明外部输入进入 SQL/命令/模板/路径/反序列化/危险上传等 sink，且缺少匹配 sanitizer。",
            "xss": "证明用户输入进入 HTML/JS/URL/CSS/模板 raw/safe 输出上下文，或证明 escape/编码不匹配上下文。",
            "ssrf": "证明用户可控 URL/host/scheme 进入外部请求 sink，且缺少 scheme/host/IP allowlist 或私网拦截。",
            "auth": "证明认证流程可被伪造、重放、弱哈希/硬编码密钥/无凭证完成，或密码重置/token 校验缺失。",
            "authz": "证明低权限用户控制对象 ID/tenant/role/admin 参数后可越权读取/修改，且缺少 ownership/role/tenant check。",
        },
        "validationPlanPolicy": {
            "version": 1,
            "maximumPlans": MAX_VALIDATION_PLANS_PER_CANDIDATE,
            "preferredMethods": ["GET", "HEAD"],
            "allowedMethods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
            "httpAssertions": [
                "status",
                "status_in",
                "body_contains",
                "body_not_contains",
                "header_equals",
                "json_contains",
                "json_path_equals",
            ],
            "cleanupStrategies": ["none", "rollback", "delete_test_data", "reset_environment"],
            "requirements": [
                "每个 HTTP 请求必须有 expected，或由后续 runtime_assert 引用",
                "candidate_id 必须等于当前 candidate.id",
                "步骤 ID 和计划 ID 必须稳定且唯一",
                "GET/HEAD 不允许 body",
                "有状态变更时 cleanup.always 必须为 true",
            ],
        },
        "confirmationDiscipline": {
            "confirmedRequires": [
                "至少一个 validationPlans 直接对应候选入口和风险观察。",
                "runner 返回类别匹配的真实运行证据，而不是通用 2xx 或字符串存在断言。",
                "reason 必须引用 codeFlow 中的 source、sink、防护缺失或防护不匹配证据。",
            ],
            "mustNotConfirmWhen": [
                "没有配置 target_url，或只能依赖自然语言推测。",
                "候选 source/sink 链路在 codeFlow 中不完整。",
                "需要凭据、真实账户、数据库种子、文件、队列、外部服务或破坏性状态变更。",
                "XSS 只有 HTTP body 反射、SSRF 只有 HTTP 响应、auth/authz 没有身份对照。",
                "计划包含脚本、命令、跨域 URL、敏感 header 或真实攻击 payload。",
            ],
        },
        "classSpecificEvidenceGates": {
            "injection": [
                "HTTP/runtime 断言必须观察到 AF_MARKER 对应的危险行为；普通状态码不能确认注入。",
                "若响应无法直接观察 sink 影响，返回 needs_manual_review。",
            ],
            "xss": [
                "必须使用 browser_assert 观察 DOM/脚本执行语义；body_contains 只证明反射，不能确认 XSS。",
                "浏览器 runner 未配置时使用占位步骤并返回 blocked/needs_manual_review。",
            ],
            "ssrf": [
                "必须使用 oast_probe 观察受控回连；目标自身响应不能证明服务端发出了请求。",
                "OAST provider 未配置时使用占位步骤并返回 blocked/needs_manual_review。",
            ],
            "auth": ["必须比较至少两个受控 identity 的认证结果；不得在计划里内嵌凭据。"],
            "authz": ["必须比较 attacker/victim 或不同 tenant/role identity；单身份 200/403 不能确认越权。"],
        },
        "negativeEvidencePolicy": [
            "false_positive 需要运行时安全控制断言通过，例如类别匹配的编码、阻断、身份隔离或 OAST 无交互证据。",
            "not_reproducible 需要计划确实执行且直接风险断言失败；runner blocked/error 不是负面证据。",
            "认证/授权负面结论仍需要身份对照；XSS/SSRF 仍需要浏览器/OAST 证据。",
        ],
        "failureModePolicy": {
            "schemaInvalid": "不要省略必需字段；无法测试时 validationPlans 返回空数组。",
            "testTooDangerous": "如果计划需要脚本、凭据、跨域访问或破坏性操作，verdict 使用 blocked。",
            "contextMissing": "如果缺少源码片段、调用链、真实配置或业务状态，verdict 使用 needs_manual_review。",
            "sanitizerAmbiguous": "如果 sanitizer 是否生效不确定，优先 not_reproducible 或 needs_manual_review，不要 confirmed。",
            "runnerCapabilityMissing": "使用 browser_assert/oast_probe 占位并说明限制，不要退化为通用 HTTP 断言。",
        },
        "verdictRubric": {
            "confirmed": "声明式计划描述了候选风险；是否最终确认仍由真实 runner 证据门禁决定。",
            "false_positive": "源码显示有效 sanitizer、权限检查、参数化、防护逻辑或候选 source/sink 不可达。",
            "not_reproducible": "真实运行计划直接测试了风险，但类别匹配的断言未通过。",
            "blocked": "计划被安全策略/runner 能力阻止，或必须依赖未配置的外部条件。",
            "needs_manual_review": "静态证据有价值但上下文不足，需要人工或真实环境复现。",
        },
        "confidenceRubric": {
            "high": "源码证据与可执行声明式计划都直接对应候选风险。",
            "medium": "源码证据较清晰，但计划依赖尚未配置的身份、浏览器、OAST 或业务前置条件。",
            "low": "依赖推断、命名、框架魔法或未知业务状态。",
        },
        "outputSchema": {
            "verdict": "confirmed|false_positive|not_reproducible|blocked|needs_manual_review",
            "confidence": "low|medium|high",
            "reason": "中文说明为什么这个候选成立或不成立",
            "validationPlans": [
                {
                    "version": 1,
                    "id": "plan-稳定标识",
                    "candidate_id": candidate.id,
                    "description": "计划目的",
                    "steps": [
                        {
                            "id": "request-1",
                            "action": "http_request",
                            "method": "GET",
                            "url": "/同源相对路径",
                            "query": {"input": "AF_MARKER"},
                            "headers": {},
                            "expected": {"status": 200, "body_contains": "AF_MARKER"},
                            "timeout_ms": 5000,
                        }
                    ],
                    "cleanup": {"strategy": "none", "always": True},
                }
            ],
            "evidence": ["关键证据"],
            "limitations": ["不能覆盖的条件"],
        },
        "candidate": candidate.to_dict(),
        "codeFlow": nodes,
    }
    return json.dumps(prompt, ensure_ascii=False)


def validate_deep_response_schema(
    parsed: dict[str, Any],
    *,
    target_url: str | None = None,
    candidate_id: str | None = None,
    allowed_route: RouteFact | None = None,
) -> list[str]:
    errors: list[str] = []
    verdict = str(parsed.get("verdict") or "").lower()
    if verdict not in {"confirmed", "false_positive", "not_reproducible", "blocked", "needs_manual_review"}:
        errors.append("verdict 缺失或枚举值非法")
    confidence = str(parsed.get("confidence") or "").lower()
    if confidence not in {"low", "medium", "high"}:
        errors.append("confidence 缺失或枚举值非法")
    if not isinstance(parsed.get("reason"), str) or not str(parsed.get("reason")).strip():
        errors.append("reason 必须是非空字符串")
    plan_keys = [key for key in ("validationPlans", "validation_plans", "verificationPlans", "verification_plans") if key in parsed]
    legacy_keys = [key for key in ("sandboxTests", "sandbox_tests") if key in parsed]
    if len(plan_keys) > 1:
        errors.append("validationPlans/verificationPlans 别名不能同时出现")
    if len(legacy_keys) > 1:
        errors.append("sandboxTests 别名不能同时出现")
    if not plan_keys and not legacy_keys:
        errors.append("validationPlans 必须存在；历史响应可使用 sandboxTests")

    plans = extract_validation_plans(parsed)
    if plan_keys:
        if not isinstance(plans, list):
            errors.append("validationPlans 必须是数组")
        else:
            try:
                normalize_validation_plans(
                    plans,
                    candidate_id=candidate_id,
                    target_url=target_url,
                    allowed_route=allowed_route,
                )
            except ValidationPlanError as exc:
                errors.append(f"validationPlans 非法：{exc}")

    tests = parsed.get(legacy_keys[0]) if legacy_keys else None
    if legacy_keys:
        if not isinstance(tests, list):
            errors.append("sandboxTests 必须是数组")
            tests = []
        for index, item in enumerate(tests[:MAX_SANDBOX_TESTS_PER_CANDIDATE], start=1):
            if not isinstance(item, dict):
                errors.append(f"sandboxTests[{index}] 必须是对象")
                continue
            if str(item.get("language") or "").lower() != "python":
                errors.append(f"sandboxTests[{index}].language 必须是 python")
            if not isinstance(item.get("code"), str) or not str(item.get("code")).strip():
                errors.append(f"sandboxTests[{index}].code 必须是非空字符串")
            if not isinstance(item.get("name"), str) or not str(item.get("name")).strip():
                errors.append(f"sandboxTests[{index}].name 必须是非空字符串")
    has_plans = isinstance(plans, list) and bool(plans)
    has_legacy_tests = isinstance(tests, list) and bool(tests)
    if verdict == "confirmed" and not has_plans and not has_legacy_tests:
        errors.append("confirmed verdict 必须提供至少一个 validationPlans")
    for key in ("evidence", "limitations"):
        value = parsed.get(key, [])
        if value is not None and not isinstance(value, list):
            errors.append(f"{key} 必须是数组")
    return errors


def normalize_sandbox_tests(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    tests: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        language = str(item.get("language") or "python").lower()
        code = str(item.get("code") or "")
        if language != "python" or not code.strip():
            continue
        tests.append(
            {
                "name": str(item.get("name") or f"沙箱测试 {len(tests) + 1}")[:120],
                "language": "python",
                "code": code[:MAX_SANDBOX_SCRIPT_CHARS],
                "expected": str(item.get("expected") or "")[:500],
            }
        )
    return tests


def run_sandbox_test(test: dict[str, str]) -> dict[str, Any]:
    name = test.get("name") or "沙箱测试"
    code = test.get("code") or ""
    runtime = find_container_runtime_path()
    image = container_sandbox_image()
    result: dict[str, Any] = {
        "type": "sandbox_python",
        "isolation": "container",
        "container_runtime": runtime,
        "container_image": image,
        "network": "none",
        "read_only_rootfs": True,
        "cap_drop": "ALL",
        "no_new_privileges": True,
        "pids_limit": 64,
        "memory_limit": "128m",
        "cpu_limit": "0.5",
        "name": name,
        "expected": test.get("expected") or "",
        "ok": False,
        "code": code,
    }
    try:
        validate_sandbox_script(code)
    except SandboxPolicyError as exc:
        result["blocked"] = True
        result["policy_error"] = str(exc)
        return result
    if not runtime:
        result["blocked"] = True
        result["runtime_error"] = "未找到容器运行时。请安装 Docker 或 Podman，或通过 AUDITFORGE_CONTAINER_RUNTIME 指定运行时路径。"
        return result
    runtime_ready, runtime_error = check_container_runtime(runtime)
    if not runtime_ready:
        result["blocked"] = True
        result["runtime_error"] = runtime_error or "容器运行时未启动或不可用。"
        return result
    try:
        completed = run_containerized_python(runtime, image, code)
    except subprocess.TimeoutExpired:
        result["blocked"] = True
        result["error"] = f"沙箱超时（>{SANDBOX_TIMEOUT_SECONDS}s）"
        return result
    except ContainerRuntimeError as exc:
        result["blocked"] = True
        result["runtime_error"] = str(exc)
        return result
    result["exit_code"] = completed.returncode
    result["stderr"] = completed.stderr[:1200]
    if completed.returncode in {125, 126, 127}:
        result["blocked"] = True
        result["runtime_error"] = (completed.stderr or completed.stdout or f"容器运行失败，退出码 {completed.returncode}")[:1200]
        return result
    try:
        payload = json.loads(completed.stdout.strip() or "{}")
    except json.JSONDecodeError:
        payload = {"ok": False, "error": completed.stdout[:1200] or "沙箱未返回 JSON"}
    result["ok"] = bool(payload.get("ok")) and completed.returncode == 0
    result["prints"] = payload.get("prints") or []
    result["exports"] = payload.get("exports") or {}
    result["sink_calls"] = payload.get("sink_calls") or []
    proof_valid, proof_reason = evaluate_sandbox_proof(code, payload)
    negative_proof_valid, negative_proof_reason = evaluate_sandbox_negative_proof(code, payload)
    result["proof_valid"] = proof_valid
    result["proof_reason"] = proof_reason
    result["negative_proof_valid"] = negative_proof_valid
    result["negative_proof_reason"] = negative_proof_reason
    if payload.get("error"):
        result["error"] = str(payload["error"])[:1200]
    return result


def evaluate_sandbox_proof(code: str, payload: dict[str, Any]) -> tuple[bool, str]:
    """Apply a deterministic minimum bar to an executed LLM-authored test.

    This does not prove a production vulnerability. It only distinguishes a
    meaningful, observable assertion from scripts such as ``assert True``.
    """

    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError:
        return False, "脚本无法解析"
    assertions = [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]
    if not assertions:
        return False, "缺少 assert"
    meaningful_assertions = [node for node in assertions if not (isinstance(node.test, ast.Constant) and bool(node.test.value))]
    if not meaningful_assertions:
        return False, "仅包含恒真断言"
    has_marker = "AF_MARKER" in code
    has_authz_model = all(token in code.lower() for token in ("attacker", "victim"))
    if not has_marker and not has_authz_model:
        return False, "缺少 AF_MARKER 或 attacker/victim 授权对照"
    observations = json.dumps(
        {
            "prints": payload.get("prints") or [],
            "exports": payload.get("exports") or {},
            "sink_calls": payload.get("sink_calls") or [],
        },
        ensure_ascii=False,
        default=str,
    )
    if has_marker and "AF_MARKER" not in observations:
        return False, "AF_MARKER 未出现在 sink_calls 或导出结果中"
    if has_authz_model and not (payload.get("exports") or payload.get("prints") or payload.get("sink_calls")):
        return False, "授权对照没有导出可观察结果"
    return True, "执行结果包含非恒真断言和可观察证据"


def evaluate_sandbox_negative_proof(code: str, payload: dict[str, Any]) -> tuple[bool, str]:
    """Require executed, observable protection evidence before accepting a negative verdict."""

    if not payload.get("ok"):
        return False, "测试未成功执行"
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError:
        return False, "脚本无法解析"
    assertions = [node.test for node in ast.walk(tree) if isinstance(node, ast.Assert)]
    meaningful = [node for node in assertions if not (isinstance(node, ast.Constant) and bool(node.value))]
    if not meaningful:
        return False, "缺少非恒真断言"
    if not any(is_negative_security_assertion(node) for node in meaningful):
        return False, "缺少直接证明阻断、编码或不相等结果的负向断言"

    lowered = code.lower()
    has_marker = "AF_MARKER" in code
    has_authz_model = all(token in lowered for token in ("attacker", "victim"))
    if not has_marker and not has_authz_model:
        return False, "缺少 AF_MARKER 或 attacker/victim 授权对照"
    observations = {
        "prints": payload.get("prints") or [],
        "exports": payload.get("exports") or {},
        "sink_calls": payload.get("sink_calls") or [],
    }
    if not any(observations.values()):
        return False, "保护结果没有导出可观察证据"
    sink_observations = json.dumps(observations["sink_calls"], ensure_ascii=False, default=str)
    if has_marker and "AF_MARKER" in sink_observations:
        return False, "AF_MARKER 仍到达受监控 sink，不能作为负面证据"
    return True, "容器执行了负向安全断言并导出可观察保护结果"


def is_negative_security_assertion(node: ast.expr) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return True
    if isinstance(node, ast.Compare):
        negative_ops = (ast.NotEq, ast.NotIn, ast.IsNot)
        if any(isinstance(operator, negative_ops) for operator in node.ops):
            return True
        compared = [node.left, *node.comparators]
        if any(isinstance(value, ast.Constant) and value.value in {False, None} for value in compared):
            return True
        if any(is_empty_literal(value) for value in compared):
            return True
        rendered = ast.unparse(node).lower()
        safe_outcome_tokens = (
            "escaped",
            "encoded",
            "sanitized",
            "parameterized",
            "placeholder",
            "denied",
            "blocked",
            "forbidden",
            "unauthorized",
            "allowlist",
            "is_allowed",
            "is_authorized",
            "?",
        )
        if any(isinstance(operator, ast.Eq) for operator in node.ops) and any(token in rendered for token in safe_outcome_tokens):
            return True
    return False


def is_empty_literal(node: ast.expr) -> bool:
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    return False


def container_sandbox_image() -> str:
    image = os.getenv(CONTAINER_IMAGE_ENV, DEFAULT_CONTAINER_IMAGE).strip() or DEFAULT_CONTAINER_IMAGE
    if image.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._/:@-]+", image):
        raise ContainerRuntimeError("沙箱镜像名称包含非法字符")
    if not re.search(r"@sha256:[0-9a-fA-F]{64}$", image):
        raise ContainerRuntimeError("沙箱镜像必须使用 @sha256 摘要固定，禁止可变 tag")
    return image


def find_container_runtime_path() -> str | None:
    configured = os.getenv(CONTAINER_RUNTIME_ENV, "").strip()
    if configured:
        return shutil.which(configured) or configured
    return shutil.which("docker") or shutil.which("podman")


def check_container_runtime(runtime: str | None) -> tuple[bool, str | None]:
    if not runtime:
        return False, "未找到容器运行时。请安装 Docker 或 Podman，或通过 AUDITFORGE_CONTAINER_RUNTIME 指定运行时路径。"
    if runtime in READY_CONTAINER_RUNTIMES:
        return True, None
    try:
        completed = subprocess.run(
            [runtime, "info", "--format", "{{json .ServerVersion}}"],
            text=True,
            capture_output=True,
            timeout=container_runtime_check_timeout(),
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, f"容器运行时不可用：{exc}"
    if completed.returncode == 0 and completed.stdout.strip():
        READY_CONTAINER_RUNTIMES.add(runtime)
        return True, None
    detail = (completed.stderr or completed.stdout or "容器 daemon 未响应。").strip()
    return False, f"容器运行时未启动或不可用：{detail[:600]}"


def container_runtime_check_timeout() -> float:
    raw_value = os.getenv(CONTAINER_RUNTIME_CHECK_TIMEOUT_ENV, "30").strip()
    try:
        value = float(raw_value)
    except ValueError:
        value = 30.0
    return min(max(value, 5.0), 120.0)


def run_containerized_python(runtime: str, image: str, code: str) -> subprocess.CompletedProcess[str]:
    ensure_container_image(runtime, image)
    container_name = f"auditforge-sandbox-{uuid.uuid4().hex[:12]}"
    command = [
        runtime,
        "run",
        "--rm",
        "-i",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--memory-swap",
        "128m",
        "--cpus",
        "0.5",
        "--user",
        "65534:65534",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--workdir",
        "/tmp",
        image,
        "python",
        "-I",
        "-S",
        "-c",
        SANDBOX_RUNNER,
    ]
    try:
        return subprocess.run(
            command,
            input=code,
            text=True,
            capture_output=True,
            timeout=SANDBOX_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        cleanup_container(runtime, container_name)
        raise
    except FileNotFoundError as exc:
        raise ContainerRuntimeError(f"容器运行时不可用：{runtime}") from exc


def ensure_container_image(runtime: str, image: str) -> None:
    cache_key = (runtime, image)
    if cache_key in READY_CONTAINER_IMAGES:
        return
    # Parallel sandbox workers share one pull/inspect operation. Without this
    # lock a cold start can launch several pulls for the same digest.
    with CONTAINER_IMAGE_LOCK:
        if cache_key in READY_CONTAINER_IMAGES:
            return
        inspect = subprocess.run(
            [runtime, "image", "inspect", image],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if inspect.returncode == 0:
            READY_CONTAINER_IMAGES.add(cache_key)
            return
        pull = subprocess.run(
            [runtime, "pull", image],
            text=True,
            capture_output=True,
            timeout=CONTAINER_IMAGE_PULL_TIMEOUT_SECONDS,
            check=False,
        )
        if pull.returncode != 0:
            stderr = (pull.stderr or inspect.stderr or "").strip()
            raise ContainerRuntimeError(f"容器镜像不可用：{image}。{stderr[:600]}")
        READY_CONTAINER_IMAGES.add(cache_key)


def cleanup_container(runtime: str, name: str) -> None:
    try:
        subprocess.run([runtime, "rm", "-f", name], text=True, capture_output=True, timeout=8, check=False)
    except Exception:
        return


def validate_sandbox_script(code: str) -> None:
    if len(code) > MAX_SANDBOX_SCRIPT_CHARS:
        raise SandboxPolicyError("脚本过长")
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        raise SandboxPolicyError(f"语法错误：{exc}") from exc
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    for node in ast.walk(tree):
        if isinstance(node, DISALLOWED_NODES):
            raise SandboxPolicyError(f"不允许的语法：{node.__class__.__name__}")
        if isinstance(node, ast.Name) and node.id in DANGEROUS_NAMES:
            raise SandboxPolicyError(f"不允许使用名称：{node.id}")
        if isinstance(node, ast.Attribute):
            attr = node.attr.lower()
            if node.attr.startswith("_") or attr in DANGEROUS_ATTRS:
                raise SandboxPolicyError(f"不允许访问属性：{node.attr}")
        if isinstance(node, ast.Call):
            validate_sandbox_call(node, function_names)


def validate_sandbox_call(node: ast.Call, function_names: set[str]) -> None:
    if isinstance(node.func, ast.Name):
        name = node.func.id
        if name not in SAFE_BUILTIN_NAMES and name not in function_names:
            raise SandboxPolicyError(f"不允许调用函数：{name}")
    elif isinstance(node.func, ast.Attribute):
        attr = node.func.attr.lower()
        if node.func.attr.startswith("_") or attr in DANGEROUS_ATTRS:
            raise SandboxPolicyError(f"不允许调用方法：{node.func.attr}")
    elif isinstance(node.func, ast.Subscript):
        if not is_safe_callable_subscript(node.func, function_names):
            raise SandboxPolicyError("不允许动态调用")
    else:
        raise SandboxPolicyError("不允许动态调用")


def is_safe_callable_subscript(node: ast.Subscript, function_names: set[str]) -> bool:
    value = node.value
    if isinstance(value, ast.Name):
        return value.id not in DANGEROUS_NAMES
    if isinstance(value, ast.Subscript):
        return is_safe_callable_subscript(value, function_names)
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return value.func.id in function_names
    return False


def normalize_verdict(value: Any) -> VerificationStatus:
    verdict = str(value or "needs_manual_review").lower()
    aliases = {
        "vulnerable": "confirmed",
        "true_positive": "confirmed",
        "sandbox_confirmed": "sandbox_confirmed",
        "manual": "needs_manual_review",
        "unknown": "needs_manual_review",
    }
    verdict = aliases.get(verdict, verdict)
    allowed = {"confirmed", "sandbox_confirmed", "blocked", "false_positive", "not_reproducible", "needs_manual_review"}
    return verdict if verdict in allowed else "needs_manual_review"  # type: ignore[return-value]


def decide_deep_status(
    verdict: VerificationStatus,
    has_passed_test: bool,
    has_tests: bool,
    has_blocked_test: bool = False,
    *,
    negative_proof_valid: bool = False,
    transport_failed: bool = False,
) -> VerificationStatus:
    if verdict in {"confirmed", "sandbox_confirmed"}:
        if has_passed_test:
            return "sandbox_executed"  # type: ignore[return-value]
        if has_blocked_test:
            return "blocked"
        return "blocked"
    if verdict in {"false_positive", "not_reproducible"}:
        # A model verdict is advisory. Only a successfully executed negative
        # proof may archive a candidate; provider/container transport failures
        # and missing tests remain visible for human review.
        if transport_failed or not has_tests or not negative_proof_valid:
            return "needs_manual_review"
        return verdict
    return verdict


def status_to_chinese(status: str) -> str:
    return {
        "confirmed": "代码片段可验证",
        "sandbox_confirmed": "容器沙箱验证通过",
        "sandbox_executed": "容器沙箱测试已执行（未自动确认漏洞）",
        "blocked": "验证受阻",
        "false_positive": "倾向误报",
        "not_reproducible": "未复现",
        "needs_manual_review": "需人工验证",
    }.get(status, status)
