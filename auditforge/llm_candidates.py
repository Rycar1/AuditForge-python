from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, TypeVar

from .call_resolution import CallResolver, resolution_models_from_diagnostics
from .models import CodeAnchor, CodeFacts, Confidence, TraceCandidate, TraceStep
from .snippets import code_window
from .utils import normalize_path, sha256_text

ALLOWED_VULN_CLASSES: set[str] = {"injection", "xss", "ssrf", "auth", "authz"}
ALLOWED_CONFIDENCE: set[str] = {"low", "medium", "high"}
MAX_LLM_CANDIDATES = 36
MAX_LLM_CANDIDATES_PER_TASK = 500
MAX_LLM_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_AUDIT_TASKS_PER_AGENT = 8
MAX_FUNCTIONS_PER_SCOPE = 8
MAX_RELATED_FUNCTIONS_PER_SCOPE = 48
MAX_CALL_GRAPH_DEPTH = 3
MAX_CALL_SUBGRAPH_EDGES = 96
MAX_BLINDSPOT_RESCAN_TASKS = 6
MAX_BLINDSPOT_FOCUS_ANCHORS = 24
MAX_CONTEXT_FILE_BYTES = 2 * 1024 * 1024
MAX_STRUCTURE_LINE_CHARS = 500
MAX_FUNCTION_CONTEXT_CHARS = 2400
DEFAULT_MODEL = "gpt-5.5"
DEFAULT_BASE_URL = "https://api.openai.com/v1"
CANDIDATE_OUTPUT_CONTRACT = """必须返回一个 JSON object，根对象必须包含 candidates 字段。
candidates 必须是数组；没有候选时返回 {"candidates": []}。
每个 candidates[] 元素必须包含：
- vulnClass: "injection" | "xss" | "ssrf" | "auth" | "authz"
- source: {"file": string, "startLine": positive integer, "endLine"?: positive integer, "symbol"?: string}
- sink: {"file": string, "startLine": positive integer, "endLine"?: positive integer, "symbol"?: string}
- steps: array，可为空；元素格式为 {"kind": "assignment"|"call"|"return"|"branch"|"framework_binding"|"llm_inferred", "from"?: CodeAnchor, "to"?: CodeAnchor, "explanation": non-empty Chinese string, "confidence": "low"|"medium"|"high"}
- sanitizers: array，可为空；元素必须是 CodeAnchor
- blockers: string array，可为空；填写会阻碍确认的条件，例如认证态、角色、业务状态、上下文 sanitizer 不确定
- confidence: "low" | "medium" | "high"
- staticEvidence: non-empty Chinese string，必须引用具体文件、行号、source、sink、传播或缺失检查
- verificationHint: non-empty Chinese string，必须是非破坏性验证建议，不要给出攻击性 payload
- notes: string array，可为空；说明 LLM 语义推断依据和仍不确定的地方
硬性禁止：
- 禁止输出 Markdown、自然语言前后缀、confirmed 结论、真实攻击 payload、破坏性请求、仓库外文件路径或不存在的行号。
- 禁止臆造源码、路由、函数或依赖；所有 file/startLine/endLine 必须来自输入 codeContext 或 facts。
- 禁止把已有参数化 SQL、上下文 HTML 编码、URL allowlist、对象归属检查、角色检查误报为高置信漏洞。"""
DEFAULT_CANDIDATE_SYSTEM_PROMPT = (
    "你是资深多语言白盒代码审计路径生成器，任务是在确定性 facts 的基础上补充可能漏掉的 source-to-sink 候选。"
    "你不是漏洞定案器；输出只进入验证队列，不能声明已确认、已利用或线上可复现。"
    "你必须像 SAST triager 一样保守：先证明入口可控、sink 有安全影响、传播链可解释、防护与上下文不匹配，再给候选。"
    "你要优先发现规则扫描容易漏掉的语义漏洞，但不能为了覆盖率牺牲证据质量；无法定位源码锚点时宁可不输出。"
    "你必须区分数据污染、控制条件、认证、对象级授权和上下文编码，不能把登录态、CSRF 或类型转换误当成完整安全边界。"
    "所有 file/startLine/endLine 必须来自输入 facts、anchorContext 或 codeContext；不能臆造源码、路由、函数、依赖或行号。"
    "遇到动态分发、框架魔法、业务状态、认证授权不明时，记录 blocker 并降低置信度。"
    "只输出严格 JSON object，中文解释，完全遵守输出契约。"
)
DEFAULT_CANDIDATE_USER_PROMPT = (
    "请按“入口盘点 -> 危险 sink -> 调用/数据流传播 -> 防护语义匹配 -> 误报排除 -> 验证提示”的流程审查输入。"
    "重点补充规则容易漏掉的跨函数传播、框架绑定、模板上下文、业务授权条件、反序列化、SSRF、文件上传、弱认证、水平/垂直越权等语义型问题。"
    "每条候选必须包含真实源码锚点、变量/参数如何流动、缺失或不匹配的 sanitizer/guard、保守置信度和非破坏性验证思路。"
    "输出前先自检：source 是否攻击者可控、sink 是否有明确安全影响、steps 是否能复核、sanitizer 是否按上下文判断、是否与已有候选重复。"
    "证据不足、传播链断裂、行号不确定、已被有效防护覆盖或只能依赖命名猜测时，不输出或降为 low。"
)


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool = False
    provider: str = "openai-compatible"
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    api_key: str | None = None
    api_key_env: str = "AUDITFORGE_LLM_API_KEY"
    response_file: str | None = None
    timeout_seconds: int = 60
    max_prompt_chars: int = 36000
    max_candidates: int = MAX_LLM_CANDIDATES
    concurrency: int = 3
    system_prompt: str | None = None
    user_prompt: str | None = None


def preflight_llm_config(config: LLMConfig | None) -> tuple[LLMConfig, dict[str, Any]]:
    """Disable unavailable remote LLM work before task/chunk fan-out begins.

    Callers that use fixture providers retain their deterministic behavior.  An
    OpenAI-compatible profile with no credential used to create one failed
    request per audit task or dependency chunk; returning a disabled copy here
    keeps deterministic analysis and OSV matching available without noisy,
    repeated failures.
    """

    effective = config or LLMConfig(enabled=False)
    diagnostics: dict[str, Any] = {
        "requested": bool(effective.enabled),
        "enabled": bool(effective.enabled),
        "provider": effective.provider,
        "reason": None,
    }
    if not effective.enabled:
        diagnostics["reason"] = "disabled"
        return effective, diagnostics
    if effective.provider == "fixture":
        if effective.response_file and Path(effective.response_file).is_file():
            diagnostics["reason"] = "fixture"
            return effective, diagnostics
        diagnostics.update({"enabled": False, "reason": "fixture_response_file_missing"})
        return replace(effective, enabled=False), diagnostics
    if effective.provider != "openai-compatible":
        diagnostics.update({"enabled": False, "reason": "unsupported_provider"})
        return replace(effective, enabled=False), diagnostics
    api_key = effective.api_key or os.getenv(effective.api_key_env) or os.getenv("OPENAI_API_KEY")
    if not api_key:
        diagnostics.update({"enabled": False, "reason": "missing_api_key"})
        return replace(effective, enabled=False), diagnostics
    diagnostics["reason"] = "configured"
    return replace(effective, api_key=api_key), diagnostics


@dataclass(frozen=True)
class LLMAuditAgent:
    id: str
    name: str
    vuln_classes: tuple[str, ...]
    mission: str


@dataclass(frozen=True)
class LLMAuditTask:
    id: str
    agent: LLMAuditAgent
    files: tuple[str, ...]
    function_ids: tuple[str, ...]
    scope_kind: str
    seed_function_ids: tuple[str, ...] = ()
    focus_anchor_lines: tuple[tuple[str, int], ...] = ()
    blindspot_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class CandidateEvidenceAssessment:
    accepted: bool
    score: int
    route_id: str | None
    reasons: tuple[str, ...]
    signals: dict[str, Any]


LLM_AUDIT_AGENTS: tuple[LLMAuditAgent, ...] = (
    LLMAuditAgent(
        id="dataflow_injection",
        name="数据流与注入审计 Agent",
        vuln_classes=("injection",),
        mission=(
            "专注追踪外部输入经过赋值、调用参数、返回值、对象字段和容器后到达 SQL、命令、路径、模板执行或反序列化等危险点；"
            "优先补充跨函数、跨层和框架绑定造成的注入候选，并核对参数化、allowlist 与类型约束是否真的覆盖当前 sink。"
        ),
    ),
    LLMAuditAgent(
        id="auth_authz",
        name="认证与授权审计 Agent",
        vuln_classes=("auth", "authz"),
        mission=(
            "专注认证、会话、密码重置、角色、对象归属和租户隔离；逐入口区分已登录、功能级授权与对象级授权，"
            "寻找水平越权、垂直越权、弱 token 及 guard 仅覆盖部分路径的问题。"
        ),
    ),
    LLMAuditAgent(
        id="web_ssrf_xss",
        name="Web 边界、SSRF 与 XSS 审计 Agent",
        vuln_classes=("xss", "ssrf"),
        mission=(
            "专注 HTML/JS/CSS/URL 上下文输出、模板自动转义绕过、DOM sink、重定向和服务端外部请求；"
            "核对上下文编码、scheme/host allowlist、DNS/IP 私网限制与重定向策略，补充 SSRF/XSS 语义候选。"
        ),
    ),
)
PromptItem = TypeVar("PromptItem")


def generate_llm_candidates(
    repo_path: Path,
    facts: CodeFacts,
    existing_candidates: list[TraceCandidate],
    config: LLMConfig,
) -> tuple[list[TraceCandidate], dict[str, Any]]:
    diagnostics: dict[str, Any] = {
        "enabled": config.enabled,
        "provider": config.provider,
        "model": config.model,
        "schema": "auditforge.llm_candidates.v1",
        "accepted": 0,
        "rejected": [],
        "error": None,
        "agent_count": 0,
        "tasks": 0,
        "succeeded": 0,
        "failed": 0,
        "concurrency": 0,
        "overall_timeout_seconds": 0,
        "overall_timeout": False,
        "timed_out": [],
        "coverage": empty_llm_coverage(),
        "complete": False,
        "task_details": [],
        "blindspot_rescan": {
            "enabled": True,
            "planned": 0,
            "executed": 0,
            "succeeded": 0,
            "failed": 0,
            "recovered_initial_tasks": 0,
            "failed_task_ids": [],
            "coverage_before": empty_llm_coverage(),
            "coverage_after": empty_llm_coverage(),
            "budget_exhausted": False,
            "scopes": [],
        },
        "evidence_critic": {
            "evaluated": 0,
            "passed": 0,
            "rejected": 0,
            "assessments": [],
        },
    }
    if not config.enabled:
        return [], diagnostics

    tasks = plan_llm_audit_tasks(facts)
    diagnostics["agent_count"] = len({task.agent.id for task in tasks})
    diagnostics["tasks"] = len(tasks)
    if not tasks:
        diagnostics["coverage"] = measure_llm_prompt_coverage(facts, [])
        diagnostics["blindspot_rescan"]["coverage_before"] = diagnostics["coverage"]
        diagnostics["blindspot_rescan"]["coverage_after"] = diagnostics["coverage"]
        diagnostics["complete"] = True
        return [], diagnostics

    prepared: list[tuple[int, LLMAuditTask, str]] = []
    task_details: dict[int, dict[str, Any]] = {}
    for index, task in enumerate(tasks):
        detail = {
            "id": task.id,
            "agent": task.agent.id,
            "scope": task.scope_kind,
            "files": list(task.files),
            "status": "pending",
            "accepted": 0,
            "attempts": 0,
        }
        task_details[index] = detail
        try:
            prompt = build_llm_prompt(
                repo_path,
                facts,
                existing_candidates,
                config.max_prompt_chars,
                config.user_prompt,
                audit_task=task,
            )
            detail["context_manifest"] = prompt_context_manifest(prompt, facts, task, config.max_prompt_chars)
        except Exception as exc:  # noqa: BLE001 - one malformed scope must not stop other agents
            detail["status"] = "failed"
            detail["error"] = str(exc)
            continue
        prepared.append((index, task, prompt))

    workers = max(1, min(12, int(config.concurrency or 1), len(prepared) or 1))
    diagnostics["concurrency"] = workers if prepared else 0
    responses, initial_batch = execute_llm_task_batch(prepared, config, task_details)
    diagnostics["overall_timeout_seconds"] = initial_batch["timeout_seconds"]
    diagnostics["overall_timeout"] = initial_batch["timed_out"]
    diagnostics["timed_out"] = list(initial_batch["timed_out_task_ids"])

    rescan_diagnostics = diagnostics["blindspot_rescan"]
    failed_prepared = [item for item in prepared if task_details[item[0]]["status"] == "failed"]
    if failed_prepared and not diagnostics["overall_timeout"]:
        retry_scopes = [
            {
                "id": f"retry:{task.id}",
                "agent": task.agent.id,
                "files": list(task.files),
                "focus_anchors": [],
                "reasons": ["llm_task_failures"],
                "kind": "transient_retry",
            }
            for _, task, _ in failed_prepared
        ]
        rescan_diagnostics["scopes"].extend(retry_scopes)
        rescan_diagnostics["planned"] += len(failed_prepared)
        retry_responses, retry_batch = execute_llm_task_batch(failed_prepared, config, task_details)
        responses.update(retry_responses)
        rescan_diagnostics["executed"] += len(failed_prepared)
        rescan_diagnostics["succeeded"] += len(retry_responses)
        rescan_diagnostics["failed"] += len(failed_prepared) - len(retry_responses)
        rescan_diagnostics["recovered_initial_tasks"] = len(retry_responses)
        rescan_diagnostics["failed_task_ids"].extend(f"retry:{task_id}" for task_id in retry_batch["failed_task_ids"])

    successful_prompts = [responses[index][1] for index in sorted(responses)]
    rescan_diagnostics["coverage_before"] = measure_llm_prompt_coverage(facts, successful_prompts)
    initial_succeeded = sum(detail["status"] == "succeeded" for detail in task_details.values())
    initial_failed = len(tasks) - initial_succeeded

    focused_tasks: list[LLMAuditTask] = []
    all_tasks = list(tasks)
    all_task_details = dict(task_details)
    if not diagnostics["overall_timeout"] and initial_failed == 0:
        focused_tasks, rescan_budget_exhausted = plan_blindspot_rescan_tasks(
            facts,
            existing_candidates,
            successful_prompts,
            max_tasks=MAX_BLINDSPOT_RESCAN_TASKS,
        )
        rescan_diagnostics["budget_exhausted"] = rescan_budget_exhausted
        focused_prepared: list[tuple[int, LLMAuditTask, str]] = []
        for offset, task in enumerate(focused_tasks, start=len(tasks)):
            detail = {
                "id": task.id,
                "agent": task.agent.id,
                "scope": task.scope_kind,
                "files": list(task.files),
                "status": "pending",
                "accepted": 0,
                "attempts": 0,
                "focus_anchors": [{"file": file, "line": line} for file, line in task.focus_anchor_lines],
                "reasons": list(task.blindspot_reasons),
            }
            all_task_details[offset] = detail
            try:
                prompt = build_llm_prompt(
                    repo_path,
                    facts,
                    existing_candidates,
                    config.max_prompt_chars,
                    config.user_prompt,
                    audit_task=task,
                )
                detail["context_manifest"] = prompt_context_manifest(prompt, facts, task, config.max_prompt_chars)
            except Exception as exc:  # noqa: BLE001 - one focused scope must not stop the scan
                detail["status"] = "failed"
                detail["error"] = str(exc)
                continue
            focused_prepared.append((offset, task, prompt))
        all_tasks.extend(focused_tasks)
        rescan_diagnostics["planned"] += len(focused_tasks)
        focused_responses, focused_batch = execute_llm_task_batch(focused_prepared, config, all_task_details)
        responses.update(focused_responses)
        rescan_diagnostics["executed"] += len(focused_prepared)
        rescan_diagnostics["succeeded"] += len(focused_responses)
        focused_failures = len(focused_tasks) - len(focused_responses)
        rescan_diagnostics["failed"] += focused_failures
        focused_failed_ids = {
            task.id for index, task in enumerate(focused_tasks, start=len(tasks)) if all_task_details[index]["status"] != "succeeded"
        }
        focused_failed_ids.update(focused_batch["failed_task_ids"])
        rescan_diagnostics["failed_task_ids"].extend(sorted(focused_failed_ids))
        rescan_diagnostics["scopes"].extend(
            {
                "id": task.id,
                "agent": task.agent.id,
                "files": list(task.files),
                "focus_anchors": [{"file": file, "line": line} for file, line in task.focus_anchor_lines],
                "reasons": list(task.blindspot_reasons),
                "kind": "focused_blindspot",
                "status": all_task_details[index]["status"],
            }
            for index, task in enumerate(focused_tasks, start=len(tasks))
        )

    generated_by_task: dict[int, list[TraceCandidate]] = {}
    quality_by_candidate: dict[tuple[int, str], CandidateEvidenceAssessment] = {}
    assessment_cache: dict[str, CandidateEvidenceAssessment] = {}
    for index in sorted(responses):
        task, prompt, parsed = responses[index]
        scoped = filter_agent_response(parsed, task, diagnostics)
        local_diagnostics: dict[str, Any] = {"rejected": []}
        generated = normalize_llm_candidates(
            repo_path,
            scoped,
            existing_candidates,
            MAX_LLM_CANDIDATES_PER_TASK,
            local_diagnostics,
            allowed_anchor_lines_from_prompt(prompt),
        )
        for rejected in local_diagnostics["rejected"]:
            rejected.setdefault("task_id", task.id)
            rejected.setdefault("agent", task.agent.id)
            diagnostics["rejected"].append(rejected)
        all_task_details[index]["produced"] = len(generated)
        passed: list[TraceCandidate] = []
        for candidate in generated:
            assessment_key = json.dumps(candidate.to_dict(), sort_keys=True, ensure_ascii=False)
            assessment = assessment_cache.get(assessment_key)
            if assessment is None:
                assessment = evaluate_candidate_evidence(candidate, facts)
                assessment_cache[assessment_key] = assessment
                record_evidence_assessment(diagnostics, task, candidate, assessment)
            if not assessment.accepted:
                diagnostics["rejected"].append(
                    {
                        "reason": "evidence_gate: incomplete source-to-sink trace",
                        "candidate_fingerprint": candidate.fingerprint,
                        "task_id": task.id,
                        "agent": task.agent.id,
                        "critic_reasons": list(assessment.reasons),
                    }
                )
                continue
            candidate = replace(candidate, route_id=candidate.route_id or assessment.route_id)
            passed.append(candidate)
            quality_by_candidate[(index, candidate.fingerprint)] = assessment
        all_task_details[index]["critic_passed"] = len(passed)
        all_task_details[index]["critic_rejected"] = len(generated) - len(passed)
        generated_by_task[index] = passed

    accepted, provenance = merge_agent_candidates(
        all_tasks,
        generated_by_task,
        existing_candidates,
        max(1, int(config.max_candidates)),
        diagnostics,
        all_task_details,
        quality_by_candidate,
    )

    accepted = [
        replace(candidate, id=f"LLM-{candidate.vuln_class.upper()}-TRACE-{index:03d}") for index, candidate in enumerate(accepted, 1)
    ]
    diagnostics["accepted"] = len(accepted)
    diagnostics["candidate_provenance"] = provenance
    diagnostics["succeeded"] = initial_succeeded
    diagnostics["failed"] = initial_failed
    successful_prompts = [responses[index][1] for index in sorted(responses)]
    diagnostics["coverage"] = measure_llm_prompt_coverage(facts, successful_prompts)
    rescan_diagnostics["coverage_after"] = diagnostics["coverage"]
    diagnostics["complete"] = (
        diagnostics["failed"] == 0 and diagnostics["coverage"]["ratio"] >= 0.999 and int(rescan_diagnostics["failed"] or 0) == 0
    )
    diagnostics["task_details"] = [task_details[index] for index in sorted(task_details)]
    if diagnostics["failed"]:
        failed_messages = [
            f"{detail['id']}: {detail.get('error', 'unknown error')}"
            for detail in diagnostics["task_details"]
            if detail["status"] != "succeeded"
        ]
        diagnostics["error"] = f"{diagnostics['failed']}/{len(tasks)} LLM audit tasks failed: " + "; ".join(failed_messages[:3])
    elif rescan_diagnostics["failed"]:
        diagnostics["error"] = f"{rescan_diagnostics['failed']} focused blind-spot audit tasks failed"
    diagnostics["rejected"].sort(key=rejection_sort_key)
    return accepted, diagnostics


def run_llm_audit_task(prompt: str, config: LLMConfig) -> dict[str, Any]:
    return parse_json_object(load_llm_response(prompt, config))


def execute_llm_task_batch(
    prepared: list[tuple[int, LLMAuditTask, str]],
    config: LLMConfig,
    task_details: dict[int, dict[str, Any]],
) -> tuple[dict[int, tuple[LLMAuditTask, str, dict[str, Any]]], dict[str, Any]]:
    """Execute one bounded task wave while isolating failures per scope."""

    if not prepared:
        return {}, {
            "timeout_seconds": 0,
            "timed_out": False,
            "timed_out_task_ids": [],
            "failed_task_ids": [],
        }
    workers = max(1, min(12, int(config.concurrency or 1), len(prepared)))
    stage_timeout = llm_stage_timeout_seconds(config, len(prepared), workers)
    deadline = time.monotonic() + stage_timeout
    responses: dict[int, tuple[LLMAuditTask, str, dict[str, Any]]] = {}
    timed_out_task_ids: list[str] = []
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="auditforge-llm-agent")
    futures = {}
    for index, task, prompt in prepared:
        detail = task_details[index]
        detail["attempts"] = int(detail.get("attempts") or 0) + 1
        detail["status"] = "running"
        detail.pop("error", None)
        futures[executor.submit(run_llm_audit_task, prompt, config)] = (index, task, prompt)
    pending = set(futures)
    timed_out = False
    try:
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                for future in pending:
                    index, task, _ = futures[future]
                    future.cancel()
                    detail = task_details[index]
                    detail["status"] = "timed_out"
                    detail["error"] = f"LLM audit stage exceeded its {stage_timeout}s deadline"
                    timed_out_task_ids.append(task.id)
                break
            completed, pending = wait(pending, timeout=min(remaining, 1.0), return_when=FIRST_COMPLETED)
            for future in completed:
                index, task, prompt = futures[future]
                detail = task_details[index]
                try:
                    parsed = future.result()
                except Exception as exc:  # noqa: BLE001 - isolate provider/schema failures per task
                    detail["status"] = "failed"
                    detail["error"] = str(exc)
                    continue
                detail["status"] = "succeeded"
                responses[index] = (task, prompt, parsed)
    finally:
        # A stalled urllib call remains isolated in the Dashboard worker process
        # and can be terminated through the task cancellation endpoint.
        executor.shutdown(wait=False, cancel_futures=True)
    failed_task_ids = [
        task.id for index, task, _ in prepared if index not in responses and task_details[index].get("status") != "succeeded"
    ]
    return responses, {
        "timeout_seconds": stage_timeout,
        "timed_out": timed_out,
        "timed_out_task_ids": timed_out_task_ids,
        "failed_task_ids": failed_task_ids,
    }


def llm_stage_timeout_seconds(config: LLMConfig, task_count: int, workers: int) -> int:
    """Bound total fan-out wait without reducing static-analysis coverage.

    Every individual request keeps the configured request timeout.  The total
    allowance covers multiple waves of agents, but is capped so an unavailable
    provider cannot leave a scan apparently stuck forever.
    """

    request_timeout = max(10, min(600, int(config.timeout_seconds or 60)))
    waves = max(1, (max(0, task_count) + max(1, workers) - 1) // max(1, workers))
    return min(900, request_timeout * max(2, min(6, waves)))


def evaluate_candidate_evidence(candidate: TraceCandidate, facts: CodeFacts) -> CandidateEvidenceAssessment:
    """Apply a deterministic local evidence gate and quality rubric to an LLM candidate."""

    starts_at_source, ends_at_sink, connected = trace_chain_status(candidate)
    source_matches = [item for item in facts.sources if anchors_overlap(candidate.source, item.anchor)]
    sink_matches = [item for item in facts.sinks if anchors_overlap(candidate.sink, item.anchor)]
    class_sink_matches = [item for item in sink_matches if item.vuln_class == candidate.vuln_class]
    route_id = candidate.route_id or route_for_candidate(candidate, facts)
    inferred_steps = sum(step.kind == "llm_inferred" for step in candidate.steps)
    concrete_steps = len(candidate.steps) - inferred_steps
    evidence_text = " ".join(
        [
            candidate.static_evidence,
            *candidate.blockers,
            *candidate.reviewer_notes,
            *(step.explanation for step in candidate.steps),
        ]
    ).lower()
    explains_missing_guard = bool(
        re.search(r"缺少|未校验|未检查|不足|不匹配|绕过|部分路径|missing|without|bypass|insufficient|not checked", evidence_text)
    )
    effective_sanitizers = effective_sanitizers_for_candidate(candidate, facts, sink_matches)
    acknowledged_sanitizer = any(
        anchors_overlap(candidate_anchor, sanitizer.anchor)
        for candidate_anchor in candidate.sanitizers
        for sanitizer in effective_sanitizers
    )
    guard_clues = security_guard_clues(candidate, facts)
    evidence_has_source_file = normalize_path(candidate.source.file).lower() in normalize_path(evidence_text).lower()
    evidence_has_sink_file = normalize_path(candidate.sink.file).lower() in normalize_path(evidence_text).lower()
    evidence_has_line = bool(re.search(r"(?:^|[^a-z0-9_])\d{1,7}(?:[^a-z0-9_]|$)", evidence_text))

    score = 8
    score += 10 if starts_at_source else 0
    score += 10 if ends_at_sink else 0
    score += 18 if connected else 0
    score += min(12, concrete_steps * 4)
    score += 2 if inferred_steps and not concrete_steps else 0
    score += 10 if source_matches else 0
    score += 8 if sink_matches else 0
    score += 5 if class_sink_matches else 0
    score += 7 if route_id else 0
    score += 3 if candidate.sanitizers else 0
    score += 3 if candidate.blockers else 0
    score += 3 if evidence_has_source_file else 0
    score += 3 if evidence_has_sink_file else 0
    score += 3 if evidence_has_line else 0
    score += {"low": 0, "medium": 3, "high": 5}.get(candidate.confidence, 0)

    reasons: list[str] = []
    if not starts_at_source:
        reasons.append("no trace step starts at the declared source")
    if not ends_at_sink:
        reasons.append("no trace step ends at the declared sink")
    if starts_at_source and ends_at_sink and not connected:
        reasons.append("trace steps do not form a connected source-to-sink path")
    if not source_matches:
        reasons.append("source is LLM-discovered and has no matching deterministic source fact")
    if not sink_matches:
        reasons.append("sink is LLM-discovered and has no matching deterministic sink fact")
    elif not class_sink_matches:
        reasons.append("sink anchor is known but its deterministic vulnerability class differs")
        score -= 4
    if inferred_steps and not concrete_steps:
        reasons.append("trace relies only on an llm_inferred step")
        score -= 6
    if effective_sanitizers and not (acknowledged_sanitizer or explains_missing_guard):
        reasons.append("an applicable sanitizer exists before the sink but is not addressed")
        score -= 18
    elif effective_sanitizers:
        reasons.append("applicable sanitizer is explicitly addressed and requires verification")
    if guard_clues and not explains_missing_guard:
        reasons.append("security guard clues exist on the path but are not addressed")
        score -= 14
    elif guard_clues:
        reasons.append("security guard clues are explicitly discussed")
        score += 2
    if not (evidence_has_source_file and evidence_has_sink_file):
        reasons.append("static evidence does not name both source and sink files")

    accepted = bool(candidate.steps) and starts_at_source and ends_at_sink and connected
    score = max(0, min(100, score))
    signals: dict[str, Any] = {
        "starts_at_source": starts_at_source,
        "ends_at_sink": ends_at_sink,
        "connected_trace": connected,
        "concrete_steps": concrete_steps,
        "inferred_steps": inferred_steps,
        "source_fact": bool(source_matches),
        "sink_fact": bool(sink_matches),
        "class_sink_fact": bool(class_sink_matches),
        "route": bool(route_id),
        "guard_clues": len(guard_clues),
        "effective_sanitizers": len(effective_sanitizers),
        "sanitizer_addressed": acknowledged_sanitizer or explains_missing_guard,
    }
    return CandidateEvidenceAssessment(
        accepted=accepted,
        score=score,
        route_id=route_id,
        reasons=tuple(reasons),
        signals=signals,
    )


def trace_chain_status(candidate: TraceCandidate) -> tuple[bool, bool, bool]:
    edges = [(step.from_anchor, step.to_anchor) for step in candidate.steps if step.from_anchor is not None and step.to_anchor is not None]
    starts_at_source = any(anchors_overlap(candidate.source, source) for source, _ in edges)
    ends_at_sink = any(anchors_overlap(candidate.sink, sink) for _, sink in edges)
    if not starts_at_source or not ends_at_sink:
        return starts_at_source, ends_at_sink, False

    frontier = [candidate.source]
    visited: set[tuple[str, int, int, str]] = {evidence_anchor_key(candidate.source)}
    while frontier:
        current = frontier.pop(0)
        if anchors_overlap(current, candidate.sink):
            return True, True, True
        for from_anchor, to_anchor in edges:
            if not anchors_overlap(current, from_anchor):
                continue
            key = evidence_anchor_key(to_anchor)
            if key in visited:
                continue
            visited.add(key)
            frontier.append(to_anchor)
    return True, True, False


def anchors_overlap(left: CodeAnchor, right: CodeAnchor) -> bool:
    if normalize_path(left.file).lower() != normalize_path(right.file).lower():
        return False
    if left.start_line <= right.end_line and right.start_line <= left.end_line:
        return True
    left_symbol = str(left.symbol or "").strip().lower()
    right_symbol = str(right.symbol or "").strip().lower()
    return bool(left_symbol and right_symbol and left_symbol == right_symbol)


def evidence_anchor_key(anchor: CodeAnchor) -> tuple[str, int, int, str]:
    return (
        normalize_path(anchor.file).lower(),
        anchor.start_line,
        anchor.end_line,
        str(anchor.symbol or "").strip().lower(),
    )


def route_for_candidate(candidate: TraceCandidate, facts: CodeFacts) -> str | None:
    source_functions = function_ids_for_anchor(candidate.source, facts)
    sink_functions = function_ids_for_anchor(candidate.sink, facts)
    for function_ids in (source_functions & sink_functions, source_functions, sink_functions):
        for route in facts.routes:
            if route.handler_function_id and route.handler_function_id in function_ids:
                return route.id
    return None


def function_ids_for_anchor(anchor: CodeAnchor, facts: CodeFacts) -> set[str]:
    function_ids = {
        function.id
        for function in facts.functions
        if normalize_path(function.anchor.file).lower() == normalize_path(anchor.file).lower()
        and function.anchor.start_line <= anchor.start_line <= function.anchor.end_line
    }
    for collection in (facts.sources, facts.sinks, facts.sanitizers):
        for item in collection:
            if item.enclosing_function_id and anchors_overlap(anchor, item.anchor):
                function_ids.add(item.enclosing_function_id)
    return function_ids


def effective_sanitizers_for_candidate(
    candidate: TraceCandidate,
    facts: CodeFacts,
    sink_matches: list[Any],
) -> list[Any]:
    sink_function_ids = function_ids_for_anchor(candidate.sink, facts)
    sink_kinds = {sink.kind for sink in sink_matches}
    effective: list[Any] = []
    for sanitizer in facts.sanitizers:
        if normalize_path(sanitizer.anchor.file).lower() != normalize_path(candidate.sink.file).lower():
            continue
        if sanitizer.anchor.start_line > candidate.sink.start_line:
            continue
        if sink_function_ids and sanitizer.enclosing_function_id not in sink_function_ids:
            continue
        if sink_kinds and sanitizer.applies_to_sink_kinds and not sink_kinds.intersection(sanitizer.applies_to_sink_kinds):
            continue
        if not sanitizer.applies_to_sink_kinds:
            continue
        effective.append(sanitizer)
    return effective


def security_guard_clues(candidate: TraceCandidate, facts: CodeFacts) -> list[Any]:
    if candidate.vuln_class not in {"auth", "authz"}:
        return []
    sink_function_ids = function_ids_for_anchor(candidate.sink, facts)
    guard_pattern = re.compile(
        r"owner|ownership|role|permission|authorize|authorise|tenant|admin|current_user|user_id|account_id|"
        r"属主|归属|角色|权限|授权|租户|管理员|当前用户",
        re.I,
    )
    return [
        flow
        for flow in facts.control_flows
        if flow.anchor.start_line <= candidate.sink.start_line
        and normalize_path(flow.anchor.file).lower() == normalize_path(candidate.sink.file).lower()
        and (not sink_function_ids or flow.enclosing_function_id in sink_function_ids)
        and guard_pattern.search(flow.condition)
    ]


def record_evidence_assessment(
    diagnostics: dict[str, Any],
    task: LLMAuditTask,
    candidate: TraceCandidate,
    assessment: CandidateEvidenceAssessment,
) -> None:
    critic = diagnostics["evidence_critic"]
    critic["evaluated"] += 1
    critic["passed" if assessment.accepted else "rejected"] += 1
    if len(critic["assessments"]) < 250:
        critic["assessments"].append(
            {
                "fingerprint": candidate.fingerprint,
                "task_id": task.id,
                "agent": task.agent.id,
                "accepted": assessment.accepted,
                "score": assessment.score,
                "route_id": assessment.route_id,
                "reasons": list(assessment.reasons),
                "signals": assessment.signals,
            }
        )


def merge_agent_candidates(
    tasks: list[LLMAuditTask],
    generated_by_task: dict[int, list[TraceCandidate]],
    existing_candidates: list[TraceCandidate],
    limit: int,
    diagnostics: dict[str, Any],
    task_details: dict[int, dict[str, Any]],
    quality_by_candidate: dict[tuple[int, str], CandidateEvidenceAssessment],
) -> tuple[list[TraceCandidate], list[dict[str, Any]]]:
    """Select evidence-ranked candidates while reserving space for specialist diversity."""

    queues: dict[str, list[tuple[int, int, TraceCandidate]]] = {agent.id: [] for agent in LLM_AUDIT_AGENTS}
    for index, task in enumerate(tasks):
        queues[task.agent.id].extend(
            (index, candidate_index, candidate) for candidate_index, candidate in enumerate(generated_by_task.get(index, []))
        )
    for agent in LLM_AUDIT_AGENTS:
        queues[agent.id].sort(
            key=lambda item: (
                -quality_by_candidate[(item[0], item[2].fingerprint)].score,
                item[0],
                item[1],
                item[2].fingerprint,
            )
        )

    seen_keys = {candidate_identity_key(candidate) for candidate in existing_candidates}
    seen_fingerprints = {candidate.fingerprint for candidate in existing_candidates}
    accepted: list[TraceCandidate] = []
    provenance: list[dict[str, Any]] = []
    remaining: list[tuple[int, int, TraceCandidate]] = []

    def try_accept(task_index: int, candidate: TraceCandidate) -> bool:
        task = tasks[task_index]
        key = candidate_identity_key(candidate)
        assessment = quality_by_candidate[(task_index, candidate.fingerprint)]
        if key in seen_keys or candidate.fingerprint in seen_fingerprints:
            diagnostics["rejected"].append(
                {
                    "reason": "duplicate",
                    "candidate_fingerprint": candidate.fingerprint,
                    "task_id": task.id,
                    "agent": task.agent.id,
                }
            )
            return False
        seen_keys.add(key)
        seen_fingerprints.add(candidate.fingerprint)
        accepted.append(candidate)
        task_details[task_index]["accepted"] = int(task_details[task_index].get("accepted") or 0) + 1
        provenance.append(
            {
                "fingerprint": candidate.fingerprint,
                "task_id": task.id,
                "agent": task.agent.id,
                "quality_score": assessment.score,
            }
        )
        return True

    # When the budget permits, reserve one slot for the strongest unique result
    # from each specialist. Remaining slots are globally quality-ranked.
    active_agents = [agent for agent in LLM_AUDIT_AGENTS if queues[agent.id]]
    if limit >= len(active_agents):
        for agent in LLM_AUDIT_AGENTS:
            queue = queues[agent.id]
            while queue and len(accepted) < limit:
                task_index, _, candidate = queue.pop(0)
                if try_accept(task_index, candidate):
                    break

    for queue in queues.values():
        remaining.extend(queue)
    remaining.sort(
        key=lambda item: (
            -quality_by_candidate[(item[0], item[2].fingerprint)].score,
            next(index for index, agent in enumerate(LLM_AUDIT_AGENTS) if agent.id == tasks[item[0]].agent.id),
            item[0],
            item[1],
            item[2].fingerprint,
        )
    )
    for task_index, _, candidate in remaining:
        if len(accepted) >= limit:
            break
        try_accept(task_index, candidate)

    diagnostics["truncated"] = False
    if len(accepted) >= limit:
        for _task_index, _, candidate in remaining:
            if candidate.fingerprint not in seen_fingerprints and candidate_identity_key(candidate) not in seen_keys:
                diagnostics["truncated"] = True
                break
    diagnostics["quality_order"] = [
        {"fingerprint": item["fingerprint"], "score": item["quality_score"], "agent": item["agent"]} for item in provenance
    ]
    return accepted, provenance


def candidate_identity_key(candidate: TraceCandidate) -> tuple[str, str, int, str, int]:
    return (
        candidate.vuln_class,
        normalize_path(candidate.source.file).lower(),
        candidate.source.start_line,
        normalize_path(candidate.sink.file).lower(),
        candidate.sink.start_line,
    )


def select_prompt_items(items: list[PromptItem], limit: int) -> list[PromptItem]:
    """Select an order-preserving sample without always starving later modules."""

    if limit <= 0:
        return []
    if len(items) <= limit:
        return list(items)
    if limit == 1:
        return [items[0]]
    indices = [round(index * (len(items) - 1) / (limit - 1)) for index in range(limit)]
    return [items[index] for index in indices]


def select_prompt_items_with_focus(
    items: list[PromptItem],
    limit: int,
    focus_anchor_lines: set[tuple[str, int]],
) -> list[PromptItem]:
    """Keep focused blind-spot anchors before applying the normal fair sample."""

    if not focus_anchor_lines:
        return select_prompt_items(items, limit)
    focused = [
        item
        for item in items
        if hasattr(item, "anchor") and (normalize_path(item.anchor.file), int(item.anchor.start_line)) in focus_anchor_lines
    ]
    focused_ids = {id(item) for item in focused}
    remaining = [item for item in items if id(item) not in focused_ids]
    if len(focused) >= limit:
        return focused[:limit]
    return [*focused, *select_prompt_items(remaining, limit - len(focused))]


def plan_blindspot_rescan_tasks(
    facts: CodeFacts,
    existing_candidates: list[TraceCandidate],
    successful_prompts: list[str],
    *,
    max_tasks: int = MAX_BLINDSPOT_RESCAN_TASKS,
) -> tuple[list[LLMAuditTask], bool]:
    """Plan one bounded wave for observable semantic and prompt blind spots."""

    if max_tasks <= 0:
        return [], False
    agents_by_id = {agent.id: agent for agent in LLM_AUDIT_AGENTS}
    candidate_sink_keys = {(normalize_path(candidate.sink.file), candidate.sink.start_line) for candidate in existing_candidates}
    candidate_source_keys = {(normalize_path(candidate.source.file), candidate.source.start_line) for candidate in existing_candidates}
    covered_lines: set[tuple[str, int]] = set()
    for prompt in successful_prompts:
        try:
            covered_lines.update(allowed_anchor_lines_from_prompt(prompt))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue

    groups: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        *,
        priority: int,
        agent_id: str,
        file: str,
        line: int,
        reason: str,
        function_id: str | None = None,
    ) -> None:
        normalized_file = normalize_path(file)
        if not normalized_file or line <= 0 or agent_id not in agents_by_id:
            return
        group = groups.setdefault(
            (agent_id, normalized_file),
            {
                "priority": priority,
                "agent": agents_by_id[agent_id],
                "file": normalized_file,
                "anchors": set(),
                "function_ids": set(),
                "reasons": set(),
            },
        )
        group["priority"] = min(int(group["priority"]), priority)
        if len(group["anchors"]) < MAX_BLINDSPOT_FOCUS_ANCHORS:
            group["anchors"].add((normalized_file, line))
        if function_id:
            group["function_ids"].add(function_id)
        group["reasons"].add(reason)

    for sink in facts.sinks:
        key = (normalize_path(sink.anchor.file), sink.anchor.start_line)
        if key not in candidate_sink_keys:
            add(
                priority=0,
                agent_id=_agent_id_for_vuln_class(sink.vuln_class),
                file=sink.anchor.file,
                line=sink.anchor.start_line,
                reason="unmatched_sinks",
                function_id=sink.enclosing_function_id,
            )
        if key not in covered_lines:
            add(
                priority=0,
                agent_id=_agent_id_for_vuln_class(sink.vuln_class),
                file=sink.anchor.file,
                line=sink.anchor.start_line,
                reason="llm_uncovered_anchors",
                function_id=sink.enclosing_function_id,
            )

    resolver = CallResolver(facts.functions, facts.imports, resolution_models_from_diagnostics(facts.analysis_diagnostics))
    repository_function_names = {function.name for function in facts.functions}
    for call in facts.call_sites:
        if resolver.resolve(call) is not None or call.callee.rsplit(".", 1)[-1] not in repository_function_names:
            continue
        add(
            priority=1,
            agent_id=_agent_id_for_call(call.callee),
            file=call.anchor.file,
            line=call.anchor.start_line,
            reason="unresolved_calls",
            function_id=call.enclosing_function_id,
        )

    for indexed in facts.files:
        if indexed.parsed_by != "fallback" and not indexed.analysis_error:
            continue
        functions = [function for function in facts.functions if normalize_path(function.anchor.file) == normalize_path(indexed.path)]
        add(
            priority=1,
            agent_id="dataflow_injection",
            file=indexed.path,
            line=functions[0].anchor.start_line if functions else 1,
            reason="parser_fallback",
            function_id=functions[0].id if functions else None,
        )

    for route in facts.routes:
        key = (normalize_path(route.anchor.file), route.anchor.start_line)
        if not route.handler_function_id:
            add(
                priority=2,
                agent_id="auth_authz",
                file=route.anchor.file,
                line=route.anchor.start_line,
                reason="unbound_routes",
            )
        if key not in covered_lines:
            add(
                priority=2,
                agent_id="auth_authz",
                file=route.anchor.file,
                line=route.anchor.start_line,
                reason="llm_uncovered_anchors",
                function_id=route.handler_function_id,
            )

    for source in facts.sources:
        key = (normalize_path(source.anchor.file), source.anchor.start_line)
        if key not in candidate_source_keys:
            add(
                priority=3,
                agent_id=_agent_id_for_source(source.kind, source.expression),
                file=source.anchor.file,
                line=source.anchor.start_line,
                reason="unmatched_sources",
                function_id=source.enclosing_function_id,
            )
        if key not in covered_lines:
            add(
                priority=2,
                agent_id=_agent_id_for_source(source.kind, source.expression),
                file=source.anchor.file,
                line=source.anchor.start_line,
                reason="llm_uncovered_anchors",
                function_id=source.enclosing_function_id,
            )

    for prompt in successful_prompts:
        try:
            payload = json.loads(prompt)
        except (TypeError, json.JSONDecodeError):
            continue
        subgraph = payload.get("connectedCallSubgraph")
        scope = payload.get("scope")
        agent = payload.get("agent")
        if not isinstance(subgraph, dict) or not subgraph.get("truncated") or not isinstance(scope, dict):
            continue
        agent_id = str(agent.get("id") or "dataflow_injection") if isinstance(agent, dict) else "dataflow_injection"
        nodes = subgraph.get("nodes") if isinstance(subgraph.get("nodes"), list) else []
        for node in nodes:
            if not isinstance(node, dict) or "seed" not in (node.get("roles") or []):
                continue
            add(
                priority=1,
                agent_id=agent_id,
                file=str(node.get("file") or ""),
                line=int(node.get("startLine") or 0),
                reason="prompt_context_truncated",
                function_id=str(node.get("id") or "") or None,
            )

    ordered_groups = sorted(
        groups.values(),
        key=lambda item: (int(item["priority"]), item["file"], item["agent"].id),
    )
    selected = ordered_groups[:max_tasks]
    file_order = {normalize_path(item.path): index for index, item in enumerate(facts.files)}
    function_order = {function.id: index for index, function in enumerate(facts.functions)}
    tasks: list[LLMAuditTask] = []
    for index, group in enumerate(selected, 1):
        seed_ids = set(group["function_ids"])
        if not seed_ids:
            focus_lines = {line for file, line in group["anchors"] if file == group["file"]}
            seed_ids.update(
                function.id
                for function in facts.functions
                if normalize_path(function.anchor.file) == group["file"]
                and any(function.anchor.start_line <= line <= function.anchor.end_line for line in focus_lines)
            )
        expanded_ids = expand_related_function_ids(facts, seed_ids)
        expanded_files = {group["file"]}
        expanded_files.update(normalize_path(function.anchor.file) for function in facts.functions if function.id in expanded_ids)
        task = LLMAuditTask(
            id=f"blindspot:{group['agent'].id}:{index:03d}",
            agent=group["agent"],
            files=tuple(sorted(expanded_files, key=lambda path: file_order.get(path, 10**9))),
            function_ids=tuple(sorted(expanded_ids, key=lambda function_id: function_order.get(function_id, 10**9))),
            scope_kind="blindspot_rescan",
            seed_function_ids=tuple(sorted(seed_ids, key=lambda function_id: function_order.get(function_id, 10**9))),
            focus_anchor_lines=tuple(sorted(group["anchors"])),
            blindspot_reasons=tuple(sorted(group["reasons"])),
        )
        tasks.append(task)
    return tasks, len(ordered_groups) > len(selected)


def _agent_id_for_vuln_class(vuln_class: str) -> str:
    for agent in LLM_AUDIT_AGENTS:
        if vuln_class in agent.vuln_classes:
            return agent.id
    return "dataflow_injection"


def _agent_id_for_call(callee: str) -> str:
    lowered = callee.lower()
    if re.search(r"auth|login|token|session|role|permission|owner|tenant|user", lowered):
        return "auth_authz"
    if re.search(r"fetch|request|http|url|render|html|redirect|web", lowered):
        return "web_ssrf_xss"
    return "dataflow_injection"


def _agent_id_for_source(kind: str, expression: str) -> str:
    lowered = f"{kind} {expression}".lower()
    if re.search(r"auth|token|session|role|permission|owner|tenant|user_id", lowered):
        return "auth_authz"
    if re.search(r"url|host|html|template|redirect|webhook", lowered):
        return "web_ssrf_xss"
    return "dataflow_injection"


def plan_llm_audit_tasks(facts: CodeFacts) -> list[LLMAuditTask]:
    """Build deterministic, bounded module/entrypoint/sink slices for specialist agents."""

    ordered_files = ordered_fact_files(facts)
    if not ordered_files:
        return []

    focus_function_ids = {
        function_id
        for function_id in (
            *(route.handler_function_id for route in facts.routes),
            *(source.enclosing_function_id for source in facts.sources),
            *(sink.enclosing_function_id for sink in facts.sinks),
        )
        if function_id
    }
    functions_by_file: dict[str, list[str]] = {file: [] for file in ordered_files}
    for function in facts.functions:
        if function.id in focus_function_ids:
            functions_by_file.setdefault(normalize_path(function.anchor.file), []).append(function.id)

    scope_units: list[tuple[tuple[str, ...], tuple[str, ...], str]] = []
    for file in ordered_files:
        function_ids = functions_by_file.get(file, [])
        if not function_ids:
            scope_units.append(((file,), (), "module_slice"))
            continue
        for offset in range(0, len(function_ids), MAX_FUNCTIONS_PER_SCOPE):
            chunk = tuple(function_ids[offset : offset + MAX_FUNCTIONS_PER_SCOPE])
            kind = "entrypoint_sink_slice" if scope_has_entry_or_sink(facts, set(chunk)) else "module_slice"
            scope_units.append(((file,), chunk, kind))

    packed_scopes = pack_llm_scope_units(facts, scope_units, MAX_AUDIT_TASKS_PER_AGENT)
    tasks: list[LLMAuditTask] = []
    for agent in LLM_AUDIT_AGENTS:
        for scope_index, (files, function_ids, scope_kind) in enumerate(packed_scopes, 1):
            expanded_ids = expand_related_function_ids(facts, set(function_ids))
            expanded_files = set(files)
            expanded_files.update(normalize_path(function.anchor.file) for function in facts.functions if function.id in expanded_ids)
            tasks.append(
                LLMAuditTask(
                    id=f"{agent.id}:{scope_index:03d}",
                    agent=agent,
                    files=tuple(path for path in ordered_files if path in expanded_files),
                    function_ids=tuple(function.id for function in facts.functions if function.id in expanded_ids),
                    scope_kind=scope_kind,
                    seed_function_ids=tuple(function.id for function in facts.functions if function.id in set(function_ids)),
                )
            )
    return tasks


def ordered_fact_files(facts: CodeFacts) -> list[str]:
    ordered: list[str] = []

    def add(value: str) -> None:
        normalized = normalize_path(value)
        if normalized and normalized not in ordered:
            ordered.append(normalized)

    for indexed in facts.files:
        if not indexed.skipped_reason and indexed.lines > 0:
            add(indexed.path)
    for collection in (
        facts.functions,
        facts.classes,
        facts.routes,
        facts.call_sites,
        facts.data_flows,
        facts.control_flows,
        facts.sources,
        facts.sinks,
        facts.sanitizers,
    ):
        for item in collection:
            add(item.anchor.file)
    return ordered


def scope_has_entry_or_sink(facts: CodeFacts, function_ids: set[str]) -> bool:
    return any(route.handler_function_id in function_ids for route in facts.routes) or any(
        sink.enclosing_function_id in function_ids for sink in facts.sinks
    )


def pack_llm_scope_units(
    facts: CodeFacts,
    units: list[tuple[tuple[str, ...], tuple[str, ...], str]],
    limit: int,
) -> list[tuple[tuple[str, ...], tuple[str, ...], str]]:
    if len(units) <= limit:
        return units

    byte_sizes = {normalize_path(item.path): max(1, item.bytes) for item in facts.files}
    bins: list[list[tuple[tuple[str, ...], tuple[str, ...], str]]] = [[] for _ in range(limit)]
    weights = [0] * limit
    weighted_units = [
        (sum(byte_sizes.get(file, 1) for file in files) + len(function_ids) * 500, index, (files, function_ids, kind))
        for index, (files, function_ids, kind) in enumerate(units)
    ]
    for weight, _, unit in sorted(weighted_units, key=lambda item: (-item[0], item[1])):
        target = min(range(limit), key=lambda index: (weights[index], index))
        bins[target].append(unit)
        weights[target] += weight

    packed: list[tuple[tuple[str, ...], tuple[str, ...], str]] = []
    file_order = {path: index for index, path in enumerate(ordered_fact_files(facts))}
    function_order = {function.id: index for index, function in enumerate(facts.functions)}
    for bucket in bins:
        files = sorted({file for unit in bucket for file in unit[0]}, key=lambda path: file_order.get(path, 10**9))
        function_ids = sorted(
            {function_id for unit in bucket for function_id in unit[1]},
            key=lambda function_id: function_order.get(function_id, 10**9),
        )
        kinds = {unit[2] for unit in bucket}
        scope_kind = next(iter(kinds)) if len(kinds) == 1 else "module_entrypoint_sink_slice"
        packed.append((tuple(files), tuple(function_ids), scope_kind))
    return packed


def expand_related_function_ids(facts: CodeFacts, seed_ids: set[str]) -> set[str]:
    if not seed_ids:
        return set()
    order = {function.id: index for index, function in enumerate(facts.functions)}
    adjacency: dict[str, set[str]] = {function.id: set() for function in facts.functions}
    for caller_id, callee_id, _ in resolved_call_edges(facts):
        adjacency.setdefault(caller_id, set()).add(callee_id)
        adjacency.setdefault(callee_id, set()).add(caller_id)

    expanded = set(seed_ids)
    queue = [(function_id, 0) for function_id in sorted(seed_ids, key=lambda item: order.get(item, 10**9))]
    related_count = 0
    while queue:
        function_id, depth = queue.pop(0)
        if depth >= MAX_CALL_GRAPH_DEPTH:
            continue
        for related_id in sorted(adjacency.get(function_id, ()), key=lambda item: order.get(item, 10**9)):
            if related_id in expanded:
                continue
            if related_count >= MAX_RELATED_FUNCTIONS_PER_SCOPE:
                return expanded
            expanded.add(related_id)
            related_count += 1
            queue.append((related_id, depth + 1))
    return expanded


def resolved_call_edges(facts: CodeFacts) -> list[tuple[str, str, Any]]:
    resolver = CallResolver(facts.functions, facts.imports, resolution_models_from_diagnostics(facts.analysis_diagnostics))
    edges: list[tuple[str, str, Any]] = []
    for call in facts.call_sites:
        if not call.enclosing_function_id:
            continue
        resolved = resolver.resolve_with_reason(call)
        if resolved is not None:
            edges.append((call.enclosing_function_id, resolved[0].id, call))
    return edges


def resolve_call_target_for_context(call: Any, functions: list[Any], functions_by_file: dict[str, list[Any]]) -> Any | None:
    simple = call.callee.rsplit(".", 1)[-1]
    call_file = normalize_path(call.anchor.file)
    if "." not in call.callee:
        local = [function for function in functions_by_file.get(call_file, []) if function.name == simple]
        return local[0] if len(local) == 1 else None
    caller = next(
        (function for function in functions_by_file.get(call_file, []) if function.id == call.enclosing_function_id),
        None,
    )
    if call.callee.startswith(("self.", "cls.")) and caller and caller.class_id:
        methods = [
            function
            for function in functions_by_file.get(call_file, [])
            if function.class_id == caller.class_id and function.name == simple
        ]
        return methods[0] if len(methods) == 1 else None
    exact = [
        function
        for function in functions
        if call.callee
        == ".".join(part for part in (module_name_for_context(function.anchor.file), function.qualified_name or function.name) if part)
    ]
    if len(exact) == 1:
        return exact[0]
    prefix = call.callee[: -(len(simple) + 1)]
    suffix = [
        function for function in functions if function.name == simple and module_name_for_context(function.anchor.file).endswith(prefix)
    ]
    return suffix[0] if len(suffix) == 1 else None


def module_name_for_context(file_path: str) -> str:
    parts = normalize_path(file_path).split("/")
    if not parts or not parts[-1].endswith(".py"):
        return ""
    parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(part for part in parts if part)


def slice_code_facts(facts: CodeFacts, task: LLMAuditTask) -> CodeFacts:
    files = {normalize_path(path) for path in task.files}
    function_ids = set(task.function_ids)

    def include(anchor: CodeAnchor, enclosing_function_id: str | None) -> bool:
        if enclosing_function_id:
            return enclosing_function_id in function_ids
        return normalize_path(anchor.file) in files

    return CodeFacts(
        files=[item for item in facts.files if normalize_path(item.path) in files],
        functions=[item for item in facts.functions if item.id in function_ids],
        classes=[item for item in facts.classes if normalize_path(item.anchor.file) in files],
        routes=[
            item
            for item in facts.routes
            if item.handler_function_id in function_ids or (item.handler_function_id is None and normalize_path(item.anchor.file) in files)
        ],
        call_sites=[item for item in facts.call_sites if include(item.anchor, item.enclosing_function_id)],
        data_flows=[item for item in facts.data_flows if include(item.anchor, item.enclosing_function_id)],
        control_flows=[item for item in facts.control_flows if include(item.anchor, item.enclosing_function_id)],
        sources=[item for item in facts.sources if include(item.anchor, item.enclosing_function_id)],
        sinks=[item for item in facts.sinks if include(item.anchor, item.enclosing_function_id)],
        sanitizers=[item for item in facts.sanitizers if include(item.anchor, item.enclosing_function_id)],
        imports=[item for item in facts.imports if normalize_path(item.anchor.file) in files],
        analysis_diagnostics=facts.analysis_diagnostics,
    )


def build_connected_call_subgraph(facts: CodeFacts, task: LLMAuditTask) -> dict[str, Any]:
    function_ids = set(task.function_ids)
    seed_ids = set(task.seed_function_ids)
    route_ids = {route.handler_function_id for route in facts.routes if route.handler_function_id}
    source_ids = {source.enclosing_function_id for source in facts.sources if source.enclosing_function_id}
    sink_ids = {sink.enclosing_function_id for sink in facts.sinks if sink.enclosing_function_id}
    nodes = [
        {
            "id": function.id,
            "name": function.qualified_name or function.name,
            "file": function.anchor.file,
            "startLine": function.anchor.start_line,
            "endLine": function.anchor.end_line,
            "roles": [
                role
                for role, members in (
                    ("seed", seed_ids),
                    ("entrypoint", route_ids),
                    ("source", source_ids),
                    ("sink", sink_ids),
                )
                if function.id in members
            ],
        }
        for function in facts.functions
        if function.id in function_ids
    ]
    edges = []
    for caller_id, callee_id, call in resolved_call_edges(facts):
        if caller_id not in function_ids or callee_id not in function_ids:
            continue
        edges.append(
            {
                "callerFunctionId": caller_id,
                "calleeFunctionId": callee_id,
                "callee": call.callee,
                "file": call.anchor.file,
                "startLine": call.anchor.start_line,
                "endLine": call.anchor.end_line,
            }
        )
        if len(edges) >= MAX_CALL_SUBGRAPH_EDGES:
            break
    return {
        "depth": MAX_CALL_GRAPH_DEPTH,
        "nodes": nodes,
        "edges": edges,
        "truncated": len(edges) >= MAX_CALL_SUBGRAPH_EDGES,
    }


def filter_agent_response(parsed: dict[str, Any], task: LLMAuditTask, diagnostics: dict[str, Any]) -> dict[str, Any]:
    raw_candidates = parsed.get("candidates")
    if not isinstance(raw_candidates, list):
        return parsed
    accepted: list[Any] = []
    allowed = set(task.agent.vuln_classes)
    for raw in raw_candidates:
        vuln_class = str(raw.get("vulnClass") or raw.get("vuln_class") or "") if isinstance(raw, dict) else ""
        if vuln_class in allowed:
            accepted.append(raw)
            continue
        diagnostics["rejected"].append(
            {
                "reason": "agent_scope_mismatch",
                "task_id": task.id,
                "agent": task.agent.id,
                "vuln_class": vuln_class,
            }
        )
    scoped = dict(parsed)
    scoped["candidates"] = accepted
    return scoped


def empty_llm_coverage() -> dict[str, Any]:
    return {
        "ratio": 0.0,
        "anchors": {"total": 0, "covered": 0, "ratio": 0.0},
        "files": {"total": 0, "covered": 0, "ratio": 0.0},
        "routes": {"total": 0, "covered": 0, "ratio": 0.0},
        "sources": {"total": 0, "covered": 0, "ratio": 0.0},
        "sinks": {"total": 0, "covered": 0, "ratio": 0.0},
        "functions": {"total": 0, "covered": 0, "ratio": 0.0},
        "by_agent": {},
    }


def measure_llm_prompt_coverage(facts: CodeFacts, prompts: list[str]) -> dict[str, Any]:
    coverage = empty_llm_coverage()
    file_targets = set(ordered_fact_files(facts))
    route_targets = {(normalize_path(item.anchor.file), item.anchor.start_line) for item in facts.routes}
    source_targets = {(normalize_path(item.anchor.file), item.anchor.start_line) for item in facts.sources}
    sink_targets = {(normalize_path(item.anchor.file), item.anchor.start_line) for item in facts.sinks}
    function_targets = {(normalize_path(item.anchor.file), item.anchor.start_line) for item in facts.functions}
    security_targets = route_targets | source_targets | sink_targets

    covered_lines: set[tuple[str, int]] = set()
    covered_files: set[str] = set()
    agent_lines: dict[str, set[tuple[str, int]]] = {}
    for prompt in prompts:
        try:
            payload = json.loads(prompt)
        except (TypeError, json.JSONDecodeError):
            continue
        lines = allowed_anchor_lines_from_prompt(prompt)
        covered_lines.update(lines)
        covered_files.update(file for file, _ in lines)
        agent_id = str((payload.get("agent") or {}).get("id") or "global")
        agent_lines.setdefault(agent_id, set()).update(lines)

    def metric(targets: set[Any], covered: set[Any]) -> dict[str, Any]:
        total = len(targets)
        count = len(targets & covered)
        return {"total": total, "covered": count, "ratio": round(count / total, 4) if total else 1.0}

    coverage["anchors"] = metric(security_targets, covered_lines)
    coverage["files"] = metric(file_targets, covered_files)
    coverage["routes"] = metric(route_targets, covered_lines)
    coverage["sources"] = metric(source_targets, covered_lines)
    coverage["sinks"] = metric(sink_targets, covered_lines)
    coverage["functions"] = metric(function_targets, covered_lines)
    coverage["ratio"] = coverage["anchors"]["ratio"]
    coverage["by_agent"] = {agent.id: metric(security_targets, agent_lines.get(agent.id, set())) for agent in LLM_AUDIT_AGENTS}
    return coverage


def rejection_sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
    reason = str(item.get("reason") or "")
    if reason == "duplicate":
        priority = 0
    elif reason.startswith("schema_error"):
        priority = 1
    elif reason == "agent_scope_mismatch":
        priority = 3
    else:
        priority = 2
    return priority, str(item.get("task_id") or ""), reason


def build_llm_prompt(
    repo_path: Path,
    facts: CodeFacts,
    existing_candidates: list[TraceCandidate],
    max_chars: int,
    custom_instructions: str | None = None,
    *,
    audit_task: LLMAuditTask | None = None,
) -> str:
    prompt_facts = slice_code_facts(facts, audit_task) if audit_task else facts
    source_limit = 32 if audit_task else 80
    sink_limit = 32 if audit_task else 80
    sanitizer_limit = 16 if audit_task else 80
    route_limit = 16 if audit_task else 80
    function_limit = 20 if audit_task else 120
    call_limit = 16 if audit_task else 180
    data_flow_limit = 20 if audit_task else 180
    control_flow_limit = 12 if audit_task else 120
    focus_anchor_lines = set(audit_task.focus_anchor_lines) if audit_task else set()
    selected_sources = select_prompt_items_with_focus(prompt_facts.sources, source_limit, focus_anchor_lines)
    role_sinks = (
        [sink for sink in prompt_facts.sinks if sink.vuln_class in audit_task.agent.vuln_classes] if audit_task else prompt_facts.sinks
    )
    selected_sinks = select_prompt_items_with_focus(role_sinks, sink_limit, focus_anchor_lines)
    selected_sanitizers = select_prompt_items_with_focus(prompt_facts.sanitizers, sanitizer_limit, focus_anchor_lines)
    source_summary = [
        {
            "kind": source.kind,
            "file": source.anchor.file,
            "line": source.anchor.start_line,
            "expression": source.expression,
        }
        for source in selected_sources
    ]
    sink_summary = [
        {
            "kind": sink.kind,
            "vulnClass": sink.vuln_class,
            "file": sink.anchor.file,
            "line": sink.anchor.start_line,
            "expression": sink.expression,
        }
        for sink in selected_sinks
    ]
    sanitizer_summary = [
        {
            "kind": sanitizer.kind,
            "file": sanitizer.anchor.file,
            "line": sanitizer.anchor.start_line,
            "expression": sanitizer.expression,
        }
        for sanitizer in selected_sanitizers
    ]
    existing_keys = [
        {
            "vulnClass": candidate.vuln_class,
            "source": f"{candidate.source.file}:{candidate.source.start_line}",
            "sink": f"{candidate.sink.file}:{candidate.sink.start_line}",
        }
        for candidate in select_prompt_items(existing_candidates, 50 if audit_task else len(existing_candidates))
    ]
    facts_payload = {
        "routes": [route.to_dict() for route in select_prompt_items_with_focus(prompt_facts.routes, route_limit, focus_anchor_lines)],
        "functions": [
            function.to_dict() for function in select_prompt_items_with_focus(prompt_facts.functions, function_limit, focus_anchor_lines)
        ],
        "callSites": [call.to_dict() for call in select_prompt_items_with_focus(prompt_facts.call_sites, call_limit, focus_anchor_lines)],
        "sources": source_summary,
        "sinks": sink_summary,
        "sanitizers": sanitizer_summary,
        "dataFlows": [
            flow.to_dict() for flow in select_prompt_items_with_focus(prompt_facts.data_flows, data_flow_limit, focus_anchor_lines)
        ],
        "controlFlows": [
            flow.to_dict() for flow in select_prompt_items_with_focus(prompt_facts.control_flows, control_flow_limit, focus_anchor_lines)
        ],
        "existingCandidates": existing_keys,
    }
    code_budget = max(6000, max_chars // 3) if audit_task else max(8000, max_chars // 2)
    anchor_budget = max(3000, max_chars // 6) if audit_task else max(4000, max_chars // 3)
    structure_budget = max(3000, max_chars // 6) if audit_task else max(3000, max_chars // 8)
    code_payload = build_code_context(
        repo_path,
        prompt_facts,
        max_chars=code_budget,
        files=audit_task.files if audit_task else None,
        priority_function_ids=audit_task.seed_function_ids if audit_task else None,
    )
    structure_payload = build_structure_context(
        repo_path,
        audit_task.files if audit_task else tuple(item.path for item in prompt_facts.files),
        max_chars=structure_budget,
    )
    call_subgraph = build_connected_call_subgraph(facts, audit_task) if audit_task else {"depth": 0, "nodes": [], "edges": []}
    anchor_facts = CodeFacts(sources=selected_sources, sinks=selected_sinks, sanitizers=selected_sanitizers) if audit_task else prompt_facts
    anchor_payload = build_anchor_context(repo_path, anchor_facts, max_chars=anchor_budget)
    task_instructions = (custom_instructions or DEFAULT_CANDIDATE_USER_PROMPT).strip() or DEFAULT_CANDIDATE_USER_PROMPT
    if audit_task:
        task_instructions = f"{task_instructions}\n\n当前专业角色：{audit_task.agent.name}。{audit_task.agent.mission}"
    prompt = {
        "role": "security_audit_candidate_generator" if audit_task is None else "security_audit_specialist_agent",
        "task": task_instructions,
        "rules": [
            "只输出 JSON object，不要 Markdown。",
            "只能生成候选路径，不要声称 confirmed。",
            "不要重复 existingCandidates 中已有 source/sink/vulnClass。",
            "候选必须包含可达入口、用户可控 source、危险 sink、传播解释、缺失或不匹配的 sanitizer 判断。",
            "source 必须是用户、低权限用户、外部系统或可被攻击者影响的数据；常量、硬编码测试数据、管理员后台固定配置不能作为普通 source。",
            "sink 必须能产生安全影响：SQL/命令/模板/HTML/路径/反序列化/外部请求/认证授权决策/敏感对象读取。",
            "sanitizer 需要按上下文判断：参数化查询只防 SQLi，不防授权绕过；HTML escape 只防 HTML 上下文 XSS，不防 URL/JS/CSS 上下文；类型转换只降低部分注入风险。",
            "如果看到 allowlist、ownership check、role check、tenant check、CSRF/token/old password 校验，应作为 sanitizer 或 blocker 处理，不要高置信报告。",
            "如果只能根据命名或注释推断，confidence 必须为 low；如果有同函数清晰数据流可 medium/high；跨函数或框架魔法需解释调用链。",
            "同一漏洞不要拆成多个重复候选；选择最靠近入口的 source 和最能表达影响的 sink。",
            "staticEvidence 必须包含具体代码行号和为什么 sanitizer 不足；verificationHint 必须给出安全、只读或可回滚验证办法。",
            "如果证据不足、源码缺失、行号不确定或已被有效 sanitizer 覆盖，不输出。",
            "遵守安全边界：不要输出破坏性 payload。",
        ],
        "decisionProcedure": [
            "1. 先从 routes、sources、codeContext 中确认外部输入入口，标记入口类型和可控主体。",
            "2. 再从 sinks、callSites、codeContext 中确认危险操作或安全决策点，标记影响面。",
            "3. 用 dataFlows、callSites、函数签名、返回值和对象字段把 source 拼到 sink；缺失环节必须写入 blockers 或降置信。",
            "4. 逐段检查 sanitizer/guard 是否在 sink 前生效，并判断其是否匹配当前漏洞类型和上下文。",
            "5. 用 existingCandidates 去重；只输出新增路径、更准确路径或规则扫描明显漏掉的语义路径。",
            "6. 最后按 confidenceRubric 重新打分，宁可少报，也不要把未锚定推测包装成高置信。",
        ],
        "pathAnchoringPolicy": {
            "sourceAnchor": "优先选择最靠近外部入口的真实源码行，例如 route 参数读取、request body 解析、消息回调入参或低权限用户可写字段读取。",
            "sinkAnchor": "选择真正产生安全影响的调用行或决策行，不要选择普通变量赋值、日志输出或中间 helper 名称。",
            "stepAnchors": "steps 中的 from/to 应尽量指向代码中实际发生赋值、调用、return、分支或框架绑定的行。",
            "snippetRequirement": "如果某个 anchor 无法在 facts、anchorContext 或 codeContext 中找到，不能使用该 anchor。",
            "lineDiscipline": "startLine/endLine 必须是输入中出现过的行号；无法确认 endLine 时可等于 startLine。",
        },
        "ambiguityPolicy": [
            "动态分发、ORM 魔法、依赖注入、反射、装饰器或注解只提供间接证据时，使用 llm_inferred step 并把 confidence 降到 low 或 medium。",
            "业务状态、登录态、角色、租户、对象归属、审批状态不明时，写入 blockers，不要直接给 high。",
            "只看到变量名像 userId、tenantId、admin、token，但没有传播和决策证据时，不输出。",
            "如果 sanitizer 是否覆盖当前上下文不确定，保留候选但在 sanitizers/blockers/staticEvidence 中说明不确定点。",
            "如果候选只适合人工复核，verificationHint 应说明需要什么只读请求、沙箱或权限对比，而不是给攻击步骤。",
        ],
        "analysisChecklist": [
            "先枚举入口：HTTP route、GraphQL/WebSocket handler、CLI 参数、文件上传、用户可控 DB 字段。",
            "再找危险点：SQL/命令/模板/HTML/路径/反序列化/HTTP client/认证授权决策。",
            "按调用图和数据流连接 source 到 sink；跨函数必须写清 controller/service/repository 或 handler/helper 链路。",
            "检查每一步是否有 sanitizer、guard、ownership、role、tenant、allowlist、类型约束或参数化 API。",
            "判断 sanitizer 是否和 sink 上下文匹配，不匹配则说明原因。",
            "用 existingCandidates 去重，只补充确定性规则漏掉或更准确的路径。",
        ],
        "evidenceQualityBar": {
            "mustHave": [
                "source 必须是攻击者、低权限用户或外部系统可影响的数据入口。",
                "sink 必须产生明确安全影响，且能说明具体危险表达式或决策点。",
                "steps 至少解释关键变量、参数、返回值、对象字段或框架绑定如何连接 source 与 sink。",
                "staticEvidence 必须点名文件、行号、关键变量和为什么防护不足或上下文不匹配。",
                "verificationHint 只能给安全、只读、可回滚或本地沙箱验证思路。",
            ],
            "rejectIf": [
                "source/sink 只有同文件邻近关系但没有传播关系。",
                "行号不在输入 facts、anchorContext 或 codeContext 中。",
                "候选依赖真实攻击 payload、破坏性请求或外部目标访问才能说明。",
                "已有参数化查询、上下文编码、强 allowlist、ownership/role/tenant check 且与 sink 匹配。",
                "只能根据函数名、注释、README、测试 fixture 或示例代码猜测。",
            ],
        },
        "flowStepRequirements": [
            "assignment: 说明变量、对象字段、字典键或解构赋值如何携带用户输入。",
            "call: 说明调用者实参到被调函数形参的对应关系，跨层链路要写 controller/service/repository 或 handler/helper。",
            "return: 说明返回值如何继续被使用，不要把未使用返回值当成传播。",
            "branch: 说明条件分支是 guard、blocker 还是绕过条件；不能把登录检查当作对象级授权检查。",
            "framework_binding: 说明 route 参数、依赖注入、decorator/annotation、中间件或模板变量绑定的依据。",
            "llm_inferred: 只能用于动态分发、反射、ORM 魔法、框架约定等模糊处，且 confidence 通常为 low。",
        ],
        "sourceSinkTaxonomy": {
            "sources": [
                "HTTP query/body/header/cookie/path 参数、form/json payload、上传文件名和内容",
                "GraphQL args、WebSocket 消息、RPC/queue 消息、CLI 参数",
                "session/user-controlled token、低权限用户可控数据库字段、外部 webhook",
                "URL、host、path、template name、serialized blob、role/user_id/object_id/tenant_id 参数",
            ],
            "sinks": [
                "raw SQL/ORM raw/字符串拼接查询、命令执行、模板字符串执行、反序列化",
                "HTML/JS/CSS/URL 输出、模板 safe/raw/innerHTML/document.write",
                "文件路径读写/上传保存/路径拼接、外部 HTTP 请求、重定向 URL",
                "认证决策、密码重置、session/token/remember-me、权限/对象归属/租户隔离判断",
            ],
            "nonSources": [
                "硬编码常量、固定枚举、服务端私有配置、不可由低权限用户影响的管理员维护数据",
                "测试 fixture、注释、README、未被执行的示例代码",
            ],
        },
        "sanitizerContextMatrix": {
            "sql": "参数化查询、ORM bind parameters、强 allowlist 可作为 SQLi sanitizer；字符串转义和 int 转换只能覆盖部分情况。",
            "xss_html": "HTML escape 只覆盖 HTML 文本上下文；JS/CSS/URL 属性需要对应上下文编码。",
            "ssrf": "必须有 scheme/host allowlist、DNS/IP 私网拦截、重定向限制；单纯 startswith('http') 不是充分防护。",
            "path": "basename/realpath 后仍需目录边界检查；扩展名检查不能阻止路径穿越。",
            "authz": "需要 ownership/role/tenant check 位于 sink 前且绑定当前用户；仅登录检查不等于授权检查。",
            "auth": "token 必须不可预测、绑定用户/用途/过期时间，并在使用时校验；弱哈希/硬编码密钥降低可信度。",
        },
        "frameworkHints": [
            "Flask/FastAPI/Django/Spring/Express/Gin/Echo/Laravel/Rails 等 route handler 参数通常来自用户输入。",
            "模板文件和 render/return HTML 需要结合上下文判断是否自动转义；safe/raw 会改变结论。",
            "Repository/DAO/service/helper 层中的 sink 可能通过 controller 参数跨函数到达。",
            "中间件、decorator、annotation、dependency injection 可能提供认证/权限 guard，应作为 blocker 或 sanitizer 记录。",
            "反射、动态 import、magic method、ORM filter string、raw SQL annotation 需要低置信解释。",
        ],
        "languageFrameworkTriage": {
            "python": [
                "Flask/FastAPI/Django 中 request.args/form/json/path、Depends、decorator、middleware 可能形成 source 或 guard。",
                "SQLAlchemy text/raw、cursor.execute 字符串拼接、subprocess/os.system、pickle/yaml.load、send_file/open 路径是重点 sink。",
                "Django 模板默认转义；mark_safe、safe、autoescape off、format_html 使用方式会改变 XSS 判断。",
            ],
            "javascript_typescript": [
                "Express/Koa/Nest route 中 req.query/body/params/header/cookies 是常见 source；middleware 可能提供 auth/authz guard。",
                "关注 sequelize.query/raw、child_process、template engine raw、innerHTML、fetch/axios URL、deserialize/eval/new Function。",
                "React 默认转义；dangerouslySetInnerHTML、服务端模板 raw 输出或 URL/JS/CSS 上下文需要单独判断。",
            ],
            "java": [
                "Spring MVC/JAX-RS 参数绑定、@PathVariable/@RequestParam/@RequestBody 是常见 source；filter/interceptor/annotation 可能是 guard。",
                "关注 JDBC 拼接、JPA nativeQuery、ProcessBuilder、RestTemplate/WebClient、ObjectInputStream、SpEL/模板执行。",
                "Spring Security 注解要区分认证、角色和对象级授权；仅 @Authenticated 不等于 ownership check。",
            ],
            "go": [
                "net/http、Gin、Echo、Fiber 的 query/form/path/body/header/cookie 是常见 source。",
                "关注 database/sql 拼接、exec.Command、template.HTML、http.Get/user URL、filepath.Join/open、json/yaml 反序列化。",
                "类型转换和 strconv.Atoi 只能降低部分注入风险，不能自动证明授权或 SSRF 安全。",
            ],
            "php": [
                "$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES、Laravel/Symfony request/input/route 参数是常见 source。",
                "关注 mysqli/PDO 拼接、DB::raw、shell_exec/system、include/require、unserialize、file_get_contents/curl URL、Blade {!! !!}。",
                "PDO prepared statement、Laravel policy/gate/middleware、CSRF token、escape helper 要按 sink 上下文判断是否有效。",
            ],
        },
        "vulnerabilityClassGuidance": {
            "injection": [
                "SQL 拼接、ORM raw query、命令执行、路径拼接、反序列化、模板字符串执行、危险文件上传都归入 injection。",
                "参数化 SQL、固定枚举 allowlist、强类型 ID 转换可能降低或消除注入候选。",
            ],
            "xss": [
                "关注 render_template_string、HTML safe/raw、innerHTML、document.write、模板 safe filter、富文本输出。",
                "区分反射型与存储型；若输入先写库再模板未转义输出，步骤应体现持久化链路。",
            ],
            "ssrf": [
                "关注 requests/urllib/fetch/http client/openConnection 等外部请求 sink。",
                "若有 scheme/host allowlist、私网/IP 校验，应降置信或作为 blocker。",
            ],
            "auth": [
                "关注登录、密码重置、token、session、remember-me、弱哈希、硬编码密钥、无速率限制等认证边界。",
                "仅凭出现 password/token 字样不能报；必须指出认证流程缺失或可伪造点。",
            ],
            "authz": [
                "关注对象 ID、tenant/account/user_id、role/admin 参数、所有权检查缺失、水平/垂直越权。",
                "若已有 current_user.id == object.owner_id 或 requireAdmin/authorize 等检查，不能高置信报告。",
            ],
        },
        "classSpecificFalsePositiveChecks": {
            "injection": [
                "确认危险字符串真的进入执行 API，而不是只进入日志、异常消息或页面展示。",
                "确认参数化 API 的变量没有被提前拼接成 raw SQL/命令/模板片段。",
                "路径类问题要检查 realpath/basename 后是否仍有目录边界校验。",
            ],
            "xss": [
                "确认输出上下文：HTML 文本、属性、JS、CSS、URL、Markdown 或富文本的编码规则不同。",
                "模板默认转义时，只有 safe/raw/autoescape off/innerHTML 等证据才适合提高置信。",
                "存储型 XSS 需要同时说明写入 source 和读取输出 sink。",
            ],
            "ssrf": [
                "确认用户能控制完整 URL、host、scheme 或重定向目标；仅固定域名路径参数通常不是 SSRF。",
                "检查 allowlist 是否覆盖 scheme、host、DNS 解析后 IP、私网地址和重定向。",
                "不要把服务端访问固定供应商 API 误判为 SSRF。",
            ],
            "auth": [
                "确认认证流程缺失的是凭证校验、token 绑定、过期、用途、随机性或密码哈希，而不是普通业务失败。",
                "仅看到 secret/token/password 字样不能作为漏洞证据。",
                "速率限制缺失可作为弱信号，但除非有明确认证绕过，不应高置信。",
            ],
            "authz": [
                "区分 authentication、role check、ownership check、tenant check；登录检查不等于对象级授权。",
                "确认低权限用户可控制 object_id/user_id/tenant_id/role/admin 参数并影响敏感对象。",
                "如果 policy/gate/authorize 在 sink 前覆盖对象和当前用户，应降置信或不输出。",
            ],
        },
        "confidenceRubric": {
            "high": "同一函数或清晰调用链中存在 source 到 sink，且无有效 sanitizer/blocker。",
            "medium": "跨函数或框架绑定基本可解释，但存在少量上下文不确定。",
            "low": "依赖命名、注释、模板约定或框架魔法推断，需要人工/运行时验证。",
        },
        "outputQualityGate": [
            "每条候选的 staticEvidence 至少回答：谁控制 source、哪个变量传播、哪个 sink 产生影响、为什么现有防护不足。",
            "每条候选的 steps 不能全是空泛描述；至少一个 step 要提到具体变量名、函数名、参数名、字段名或框架绑定。",
            "sanitizers 只列真实出现的防护锚点；不确定防护写入 blockers，不要编造 sanitizer。",
            "verificationHint 必须避免真实攻击 payload，可使用 AF_MARKER、只读请求、权限对比、沙箱复现或本地 mock。",
            "同一 source 到同一 sink 的重复漏洞只保留一条，必要时在 notes 中说明多个入口或影响。",
        ],
        "negativeExamples": [
            "request.args['id'] 经 int() 后只用于参数化 SQL，不应输出 SQLi 高置信候选。",
            "对象读取前存在 object.owner_id == current_user.id，不应输出 authz 高置信候选。",
            "URL 经固定域名 allowlist、IP 私网拦截和禁止重定向后，不应输出 ssrf 高置信候选。",
            "模板默认自动转义且没有 safe/raw/innerHTML，不应输出 XSS 高置信候选。",
            "候选只有 source 和 sink 在同文件但没有传播关系，应降低置信或不输出。",
        ],
        "outputSchema": {
            "candidates": [
                {
                    "vulnClass": "injection|xss|ssrf|auth|authz",
                    "source": {"file": "path", "startLine": 1, "endLine": 1, "symbol": "optional"},
                    "sink": {"file": "path", "startLine": 1, "endLine": 1, "symbol": "optional"},
                    "steps": [
                        {
                            "kind": "assignment|call|return|branch|framework_binding|llm_inferred",
                            "from": {"file": "path", "startLine": 1, "endLine": 1, "symbol": "optional"},
                            "to": {"file": "path", "startLine": 1, "endLine": 1, "symbol": "optional"},
                            "explanation": "为什么该步骤传播数据",
                            "confidence": "low|medium|high",
                        }
                    ],
                    "sanitizers": [{"file": "path", "startLine": 1, "endLine": 1, "symbol": "optional"}],
                    "blockers": ["为什么仍需验证或哪里不确定"],
                    "confidence": "low|medium|high",
                    "staticEvidence": "简洁中文证据说明",
                    "verificationHint": "非破坏性验证建议",
                    "notes": ["LLM 推断依据"],
                }
            ]
        },
        "facts": facts_payload,
        "connectedCallSubgraph": call_subgraph,
        "structureContext": structure_payload,
        "anchorContext": anchor_payload,
        "codeContext": code_payload,
    }
    if audit_task:
        prompt["agent"] = {
            "id": audit_task.agent.id,
            "name": audit_task.agent.name,
            "allowedVulnClasses": list(audit_task.agent.vuln_classes),
            "mission": audit_task.agent.mission,
        }
        prompt["scope"] = {
            "id": audit_task.id,
            "kind": audit_task.scope_kind,
            "files": list(audit_task.files),
            "functionIds": list(audit_task.function_ids),
            "focusAnchors": [{"file": file, "line": line} for file, line in audit_task.focus_anchor_lines],
            "blindspotReasons": list(audit_task.blindspot_reasons),
        }
        prompt["rules"].insert(
            2,
            f"当前 Agent 只输出 {', '.join(audit_task.agent.vuln_classes)} 类候选；其他类型交给对应专业 Agent。",
        )
        prompt["rules"].insert(
            3,
            "优先沿 connectedCallSubgraph 闭合入口、source 与 sink；structureContext 中的 imports、decorators 和全局配置用于解释框架绑定与 guard，不可仅凭命名定案。",
        )
        if audit_task.focus_anchor_lines:
            prompt["rules"].insert(
                4,
                "这是一次盲区专项补扫。优先从 scope.focusAnchors 向上追踪入口、向下追踪危险操作，并明确说明仍未解析的调用或框架边。",
            )
    return json.dumps(prompt, ensure_ascii=False)


def prompt_context_manifest(
    prompt: str,
    facts: CodeFacts,
    task: LLMAuditTask,
    context_budget: int,
) -> dict[str, Any]:
    """Record what a specialist actually received without persisting source."""

    payload = json.loads(prompt)
    prompt_facts = payload.get("facts") if isinstance(payload.get("facts"), dict) else {}
    scoped = slice_code_facts(facts, task)
    applicable_sinks = [sink for sink in scoped.sinks if sink.vuln_class in task.agent.vuln_classes]
    expected = {
        "routes": len(scoped.routes),
        "functions": len(scoped.functions),
        "callSites": len(scoped.call_sites),
        "sources": len(scoped.sources),
        "sinks": len(applicable_sinks),
        "sanitizers": len(scoped.sanitizers),
        "dataFlows": len(scoped.data_flows),
        "controlFlows": len(scoped.control_flows),
    }
    included = {key: len(value) if isinstance(value, list) else 0 for key, value in prompt_facts.items() if key in expected}
    omitted = {key: max(0, total - included.get(key, 0)) for key, total in expected.items()}
    subgraph = payload.get("connectedCallSubgraph")
    focus = set(task.focus_anchor_lines)
    allowed = allowed_anchor_lines_from_prompt(prompt)
    return {
        "prompt_chars": len(prompt),
        "context_budget_chars": max(0, int(context_budget)),
        "expected_facts": expected,
        "included_facts": included,
        "omitted_facts": omitted,
        "code_chunks": len(payload.get("codeContext") or []),
        "structure_chunks": len(payload.get("structureContext") or []),
        "anchor_chunks": len(payload.get("anchorContext") or []),
        "call_subgraph_truncated": bool(isinstance(subgraph, dict) and subgraph.get("truncated")),
        "focus_anchors": len(focus),
        "focus_anchors_covered": len(focus & allowed),
        "truncated": any(omitted.values()) or bool(isinstance(subgraph, dict) and subgraph.get("truncated")),
    }


def build_anchor_context(repo_path: Path, facts: CodeFacts, max_chars: int) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    used = 0
    seen: set[tuple[str, int, str]] = set()
    fact_groups = [
        ("source", facts.sources[:80]),
        ("sink", facts.sinks[:80]),
        ("sanitizer", facts.sanitizers[:80]),
    ]
    max_items = max((len(items) for _, items in fact_groups), default=0)
    for index in range(max_items):
        for role, items in fact_groups:
            if index >= len(items):
                continue
            item = items[index]
            anchor = item.anchor
            key = (anchor.file, anchor.start_line, role)
            if key in seen:
                continue
            seen.add(key)
            snippet = code_window(repo_path, anchor, context=3)
            if snippet.error or not snippet.lines:
                continue
            text = "\n".join(f"{line.number}: {line.text}" for line in snippet.lines)
            if used + len(text) > max_chars:
                return chunks
            used += len(text)
            chunks.append(
                {
                    "role": role,
                    "kind": getattr(item, "kind", ""),
                    "expression": getattr(item, "expression", ""),
                    "file": anchor.file,
                    "startLine": anchor.start_line,
                    "endLine": anchor.end_line,
                    "code": text,
                }
            )
    return chunks


def build_code_context(
    repo_path: Path,
    facts: CodeFacts,
    max_chars: int,
    *,
    files: tuple[str, ...] | None = None,
    priority_function_ids: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    used = 0
    priority = set(priority_function_ids or ())
    ordered_functions = sorted(
        enumerate(facts.functions),
        key=lambda item: (0 if item[1].id in priority else 1, item[0]),
    )
    function_chunks = [(function, function_context_chunks(repo_path, function, facts)) for _, function in ordered_functions]

    # First pass gives every connected function a bounded primary window. A long
    # earlier function can no longer starve smaller functions that follow it.
    for _, candidates in function_chunks:
        if not candidates:
            continue
        text = str(candidates[0]["code"])
        if used + len(text) > max_chars:
            continue
        chunks.append(candidates[0])
        used += len(text)
    # Second pass fills remaining budget with additional source/sink/call windows.
    for _, candidates in function_chunks:
        for chunk in candidates[1:]:
            text = str(chunk["code"])
            if used + len(text) > max_chars:
                continue
            chunks.append(chunk)
            used += len(text)
    if not facts.functions:
        for file in files or ():
            lines = safe_context_file_lines(repo_path, file)
            if not lines:
                continue
            text = render_context_lines(lines, 1, min(len(lines), 24))
            if used + len(text) > max_chars:
                continue
            chunks.append({"type": "module_window", "file": file, "startLine": 1, "endLine": min(len(lines), 24), "code": text})
            used += len(text)
    return chunks


def function_context_chunks(repo_path: Path, function: Any, facts: CodeFacts) -> list[dict[str, Any]]:
    lines = safe_context_file_lines(repo_path, function.anchor.file)
    if not lines:
        return []
    start = max(1, function.anchor.start_line)
    end = min(len(lines), max(start, function.anchor.end_line))
    full = render_context_lines(lines, start, end)
    if len(full) <= MAX_FUNCTION_CONTEXT_CHARS:
        return [
            {
                "type": "function",
                "file": function.anchor.file,
                "name": function.qualified_name or function.name,
                "startLine": start,
                "endLine": end,
                "code": full,
            }
        ]

    critical_lines = {start, end}
    for collection in (
        facts.routes,
        facts.sources,
        facts.sinks,
        facts.sanitizers,
        facts.call_sites,
        facts.data_flows,
        facts.control_flows,
    ):
        related_items = [
            item
            for item in collection
            if getattr(item, "enclosing_function_id", None) == function.id or getattr(item, "handler_function_id", None) == function.id
        ]
        for item in select_prompt_items(related_items, 12):
            enclosing = getattr(item, "enclosing_function_id", None)
            handler = getattr(item, "handler_function_id", None)
            if enclosing == function.id or handler == function.id:
                critical_lines.add(item.anchor.start_line)
    ranges = merge_line_ranges([(max(start, line - 3), min(end, line + 3)) for line in sorted(critical_lines)])
    chunks: list[dict[str, Any]] = []
    for range_start, range_end in ranges:
        text = render_context_lines(lines, range_start, range_end)
        chunks.append(
            {
                "type": "function_window",
                "file": function.anchor.file,
                "name": function.qualified_name or function.name,
                "startLine": range_start,
                "endLine": range_end,
                "code": text,
            }
        )
    return chunks


def build_structure_context(repo_path: Path, files: tuple[str, ...], max_chars: int) -> list[dict[str, Any]]:
    per_file: dict[str, list[dict[str, Any]]] = {}
    for file in files:
        lines = safe_context_file_lines(repo_path, file)
        if not lines:
            continue
        selected: set[int] = set()
        for index, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            top_level = len(line) == len(line.lstrip())
            if re.match(r"^(?:from\s+\S+\s+import|import\s+|#include\b|using\s+|package\s+|use\s+)", stripped):
                selected.add(index)
            if stripped.startswith("@") or re.match(r"^\[[A-Za-z_][^]]*\]$", stripped):
                selected.add(index)
                if index < len(lines):
                    selected.add(index + 1)
            if re.match(r"^(?:class|interface|struct|enum)\s+", stripped):
                selected.add(index)
            if top_level and (
                re.match(r"^[A-Z][A-Z0-9_]*\s*(?::[^=]+)?=", stripped)
                or re.match(r"^(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=", stripped)
                or re.search(r"(?:config|settings|middleware|blueprint|router)\s*[.\[]", stripped, re.I)
            ):
                selected.add(index)
        ranges = merge_line_ranges([(line, line) for line in sorted(selected)], max_lines=8)
        per_file[file] = [
            {
                "type": "file_structure",
                "file": file,
                "startLine": start,
                "endLine": end,
                "code": render_context_lines(lines, start, end, max_line_chars=MAX_STRUCTURE_LINE_CHARS),
            }
            for start, end in ranges
        ]

    chunks: list[dict[str, Any]] = []
    used = 0
    while any(per_file.values()):
        progressed = False
        for file in files:
            candidates = per_file.get(file) or []
            if not candidates:
                continue
            chunk = candidates.pop(0)
            text = str(chunk["code"])
            if used + len(text) > max_chars:
                continue
            chunks.append(chunk)
            used += len(text)
            progressed = True
        if not progressed:
            break
    return chunks


def safe_context_file_lines(repo_path: Path, file: str) -> list[str]:
    unresolved = repo_path.resolve() / file
    if unresolved.is_symlink():
        return []
    target = unresolved.resolve()
    try:
        target.relative_to(repo_path.resolve())
    except ValueError:
        return []
    if not target.is_file():
        return []
    try:
        if target.stat().st_size > MAX_CONTEXT_FILE_BYTES:
            return []
        return target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def render_context_lines(lines: list[str], start: int, end: int, *, max_line_chars: int = 1000) -> str:
    return "\n".join(f"{number}: {lines[number - 1][:max_line_chars]}" for number in range(start, end + 1))


def merge_line_ranges(ranges: list[tuple[int, int]], *, max_lines: int | None = None) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1] + 1 or (max_lines and end - merged[-1][0] + 1 > max_lines):
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def load_llm_response(prompt: str, config: LLMConfig) -> str:
    return load_llm_json_response(
        prompt,
        config,
        system_prompt=with_output_contract(
            (config.system_prompt or DEFAULT_CANDIDATE_SYSTEM_PROMPT).strip() or DEFAULT_CANDIDATE_SYSTEM_PROMPT,
            CANDIDATE_OUTPUT_CONTRACT,
        ),
        temperature=0.1,
    )


def with_output_contract(system_prompt: str, contract: str) -> str:
    prompt = system_prompt.strip() or "你是严格 JSON 输出器。"
    return (
        f"{prompt}\n\n"
        "【不可变输出契约】\n"
        f"{contract.strip()}\n\n"
        "服务端会按该契约做字段、类型、枚举值和源码锚点校验；不符合契约的条目会被拒绝。"
    )


def load_llm_json_response(prompt: str, config: LLMConfig, *, system_prompt: str, temperature: float = 0.1) -> str:
    if config.provider == "fixture":
        if not config.response_file:
            raise ValueError("fixture provider requires response_file")
        return Path(config.response_file).read_text(encoding="utf-8")
    if config.provider != "openai-compatible":
        raise ValueError(f"unsupported llm provider: {config.provider}")

    api_key = config.api_key or os.getenv(config.api_key_env) or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError(f"missing API key; set {config.api_key_env} or OPENAI_API_KEY")
    url = validate_llm_base_url(config.base_url).rstrip("/") + "/chat/completions"
    payload = {
        "model": config.model,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with llm_url_opener().open(request, timeout=config.timeout_seconds) as response:
        body = json.loads(read_bounded_response(response).decode("utf-8", errors="replace"))
    return body["choices"][0]["message"]["content"]


def test_llm_connection(config: LLMConfig) -> dict[str, Any]:
    if config.provider == "fixture":
        return {
            "ok": True,
            "provider": "fixture",
            "model": config.model,
            "message": "fixture provider 不需要远程连接，配置格式可用。",
        }
    if config.provider != "openai-compatible":
        raise ValueError(f"unsupported llm provider: {config.provider}")

    api_key = config.api_key or os.getenv(config.api_key_env) or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError(f"missing API key; set {config.api_key_env} or OPENAI_API_KEY")

    url = validate_llm_base_url(config.base_url).rstrip("/") + "/chat/completions"
    payload = {
        "model": config.model,
        "temperature": 0,
        "max_tokens": 16,
        "messages": [
            {"role": "system", "content": "You are a connection health checker. Reply with a short acknowledgement."},
            {"role": "user", "content": "ping"},
        ],
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with llm_url_opener().open(request, timeout=min(config.timeout_seconds, 20)) as response:
            raw = read_bounded_response(response).decode("utf-8", errors="replace")
            body = json.loads(raw)
    except urllib.error.HTTPError as exc:
        exc.read(4096)
        raise ValueError(f"LLM provider returned HTTP {exc.code}") from exc
    latency_ms = int((time.monotonic() - started) * 1000)
    content = str(((body.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
    return {
        "ok": True,
        "provider": config.provider,
        "model": config.model,
        "base_url": config.base_url,
        "latency_ms": latency_ms,
        "reply": content[:240],
        "message": "LLM 测试消息发送成功。",
    }


class NoLLMRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201 - urllib callback signature
        return None


def llm_url_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(NoLLMRedirectHandler())


def validate_llm_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("LLM base URL must use http or https and include a host")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("LLM base URL must not contain credentials, query parameters, or fragments")
    if parsed.scheme.lower() == "http" and parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("remote LLM base URL must use HTTPS")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("LLM base URL contains an invalid port") from exc
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path.rstrip("/"), "", ""))


def read_bounded_response(response) -> bytes:  # noqa: ANN001 - urllib response protocol has no stable public type
    payload = response.read(MAX_LLM_RESPONSE_BYTES + 1)
    if len(payload) > MAX_LLM_RESPONSE_BYTES:
        raise ValueError(f"LLM response exceeds {MAX_LLM_RESPONSE_BYTES} bytes")
    return payload


def parse_json_object(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw, re.S)
    if fenced:
        raw = fenced.group(1)
    if not raw.startswith("{"):
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            raw = raw[start : end + 1]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM response is not valid JSON object: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("LLM response must be a JSON object")
    return data


def normalize_llm_candidates(
    repo_path: Path,
    parsed: dict[str, Any],
    existing_candidates: list[TraceCandidate],
    max_candidates: int,
    diagnostics: dict[str, Any],
    allowed_anchor_lines: set[tuple[str, int]],
) -> list[TraceCandidate]:
    if "candidates" not in parsed:
        diagnostics["rejected"].append(
            {
                "reason": "schema_error: missing required root key candidates",
                "root_keys": sorted(str(key) for key in parsed.keys())[:20],
            }
        )
        return []
    raw_candidates = parsed.get("candidates") or []
    if not isinstance(raw_candidates, list):
        diagnostics["rejected"].append(
            {
                "reason": "schema_error: candidates must be a list",
                "actual_type": type(raw_candidates).__name__,
            }
        )
        return []

    existing_keys = {
        (
            candidate.vuln_class,
            normalize_path(candidate.source.file).lower(),
            candidate.source.start_line,
            normalize_path(candidate.sink.file).lower(),
            candidate.sink.start_line,
        )
        for candidate in existing_candidates
    }
    existing_fingerprints = {candidate.fingerprint for candidate in existing_candidates}
    seen = set(existing_keys)
    seen_fingerprints = set(existing_fingerprints)
    accepted: list[TraceCandidate] = []
    for raw in raw_candidates[:max_candidates]:
        try:
            candidate = normalize_one_candidate(repo_path, raw, len(accepted) + 1, allowed_anchor_lines)
        except Exception as exc:  # noqa: BLE001 - keep scanning after bad LLM item
            diagnostics["rejected"].append({"reason": str(exc), "candidate": raw})
            continue
        key = (
            candidate.vuln_class,
            normalize_path(candidate.source.file).lower(),
            candidate.source.start_line,
            normalize_path(candidate.sink.file).lower(),
            candidate.sink.start_line,
        )
        if key in seen or candidate.fingerprint in seen_fingerprints:
            diagnostics["rejected"].append({"reason": "duplicate", "candidate": raw})
            continue
        seen.add(key)
        seen_fingerprints.add(candidate.fingerprint)
        accepted.append(candidate)
    return accepted


def normalize_one_candidate(
    repo_path: Path,
    raw: dict[str, Any],
    sequence: int,
    allowed_anchor_lines: set[tuple[str, int]],
) -> TraceCandidate:
    if not isinstance(raw, dict):
        raise ValueError("candidate must be an object")
    vuln_class = str(raw.get("vulnClass") or raw.get("vuln_class") or "")
    if vuln_class not in ALLOWED_VULN_CLASSES:
        raise ValueError(f"invalid vulnClass: {vuln_class}")
    confidence = require_confidence(raw.get("confidence"), "confidence")
    source = normalize_anchor(repo_path, raw.get("source"), "source", allowed_anchor_lines)
    sink = normalize_anchor(repo_path, raw.get("sink"), "sink", allowed_anchor_lines)
    steps = normalize_steps(repo_path, raw.get("steps"), source, sink, allowed_anchor_lines)
    raw_sanitizers = raw.get("sanitizers") or []
    if not isinstance(raw_sanitizers, list):
        raise ValueError("sanitizers must be a list")
    raw_blockers = raw.get("blockers") or []
    if not isinstance(raw_blockers, list):
        raise ValueError("blockers must be a list")
    raw_notes = raw.get("notes") or []
    if not isinstance(raw_notes, list):
        raise ValueError("notes must be a list")
    static_evidence = required_text(raw, ("staticEvidence", "static_evidence"), "staticEvidence", 1200)
    verification_hint = required_text(raw, ("verificationHint", "verification_hint"), "verificationHint", 800)
    sanitizers = [normalize_anchor(repo_path, item, "sanitizer", allowed_anchor_lines) for item in raw_sanitizers]
    return TraceCandidate(
        id=f"LLM-{vuln_class.upper()}-TRACE-{sequence:03d}",
        vuln_class=vuln_class,  # type: ignore[arg-type]
        source=source,
        sink=sink,
        steps=steps,
        sanitizers=sanitizers,
        blockers=[str(item)[:400] for item in raw_blockers],
        confidence=confidence,
        static_evidence=static_evidence,
        verification_hint=verification_hint,
        route_id=None,
        origin="llm",
        reviewer_notes=[str(item)[:500] for item in raw_notes],
    )


def normalize_steps(
    repo_path: Path,
    raw_steps: Any,
    source: CodeAnchor,
    sink: CodeAnchor,
    allowed_anchor_lines: set[tuple[str, int]],
) -> list[TraceStep]:
    if not isinstance(raw_steps, list) or not raw_steps:
        return [
            TraceStep(
                kind="llm_inferred",
                from_anchor=source,
                to_anchor=sink,
                explanation="LLM 基于上下文推断该 source 可能到达 sink。",
                confidence="low",
            )
        ]
    steps: list[TraceStep] = []
    for raw in raw_steps:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind") or "llm_inferred")
        if kind not in {"assignment", "call", "return", "branch", "framework_binding", "llm_inferred"}:
            kind = "llm_inferred"
        from_anchor = normalize_anchor(
            repo_path,
            raw.get("from") or raw.get("from_anchor") or source,
            "step.from",
            allowed_anchor_lines,
        )
        to_anchor = normalize_anchor(
            repo_path,
            raw.get("to") or raw.get("to_anchor") or sink,
            "step.to",
            allowed_anchor_lines,
        )
        steps.append(
            TraceStep(
                kind=kind,  # type: ignore[arg-type]
                from_anchor=from_anchor,
                to_anchor=to_anchor,
                explanation=str(raw.get("explanation") or "LLM 推断传播步骤。"),
                confidence=normalize_confidence(raw.get("confidence")),
            )
        )
    return steps or normalize_steps(repo_path, [], source, sink, allowed_anchor_lines)


def normalize_anchor(
    repo_path: Path,
    raw: Any,
    field_name: str,
    allowed_anchor_lines: set[tuple[str, int]],
) -> CodeAnchor:
    if isinstance(raw, CodeAnchor):
        if (normalize_path(raw.file), raw.start_line) not in allowed_anchor_lines:
            raise ValueError(f"{field_name} anchor was not included in the LLM prompt context")
        return raw
    if not isinstance(raw, dict):
        raise ValueError(f"{field_name} anchor must be an object")
    file = str(raw.get("file") or "")
    start_line = int(raw.get("startLine") or raw.get("start_line") or 0)
    end_line = int(raw.get("endLine") or raw.get("end_line") or start_line)
    if not file or start_line <= 0 or end_line < start_line:
        raise ValueError(f"invalid {field_name} anchor")
    normalized_file = normalize_path(file)
    if (normalized_file, start_line) not in allowed_anchor_lines or (normalized_file, end_line) not in allowed_anchor_lines:
        raise ValueError(f"{field_name} anchor was not included in the LLM prompt context")
    target = (repo_path / file).resolve()
    repo = repo_path.resolve()
    try:
        target.relative_to(repo)
    except ValueError as exc:
        raise ValueError(f"{field_name} anchor escapes repo") from exc
    if not target.exists():
        raise ValueError(f"{field_name} file does not exist: {file}")
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if start_line > len(lines):
        raise ValueError(f"{field_name} line is outside file: {file}:{start_line}")
    end_line = min(end_line, len(lines))
    snippet = "\n".join(lines[start_line - 1 : end_line])
    return CodeAnchor(
        file=file,
        start_line=start_line,
        end_line=end_line,
        snippet_hash=sha256_text(snippet)[:16],
        symbol=raw.get("symbol"),
    )


def allowed_anchor_lines_from_prompt(prompt: str) -> set[tuple[str, int]]:
    payload = json.loads(prompt)
    allowed: set[tuple[str, int]] = set()

    def visit(value: Any, *, expand_ranges: bool = True) -> None:
        if isinstance(value, dict):
            file = value.get("file")
            if isinstance(file, str) and file:
                line = value.get("line")
                start = value.get("startLine", value.get("start_line", line))
                end = value.get("endLine", value.get("end_line", start))
                try:
                    start_line = int(start)
                    end_line = int(end)
                except (TypeError, ValueError):
                    pass
                else:
                    if 0 < start_line <= end_line and end_line - start_line <= 10000:
                        normalized = normalize_path(file)
                        if expand_ranges:
                            allowed.update((normalized, number) for number in range(start_line, end_line + 1))
                        else:
                            allowed.add((normalized, start_line))
            for item in value.values():
                visit(item, expand_ranges=expand_ranges)
        elif isinstance(value, list):
            for item in value:
                visit(item, expand_ranges=expand_ranges)

    facts = payload.get("facts")
    if isinstance(facts, dict):
        for key, value in facts.items():
            # A FunctionFact contains its full body range, but the facts payload
            # does not contain those body lines. Only actual codeContext may
            # authorize arbitrary anchors inside a function.
            visit(value, expand_ranges=key not in {"functions"})
    visit(payload.get("anchorContext"))
    visit(payload.get("codeContext"))
    return allowed


def normalize_confidence(value: Any) -> Confidence:
    confidence = str(value or "low").lower()
    return confidence if confidence in ALLOWED_CONFIDENCE else "low"  # type: ignore[return-value]


def require_confidence(value: Any, field_name: str) -> Confidence:
    confidence = str(value or "").lower()
    if confidence not in ALLOWED_CONFIDENCE:
        raise ValueError(f"{field_name} must be one of low|medium|high")
    return confidence  # type: ignore[return-value]


def required_text(raw: dict[str, Any], keys: tuple[str, ...], field_name: str, limit: int) -> str:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return re.sub(r"\s+", " ", value.strip())[:limit]
    raise ValueError(f"missing required field: {field_name}")
