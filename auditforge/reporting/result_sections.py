from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from .logging_config import redact
from .models import ScanResult, VerificationResult
from .validation_dsl import ValidationEvidenceResult
from .web_security import redact_url

DECLARATIVE_VALIDATION_TYPES = frozenset(
    {
        "declarative_validation",
        "declarative_validation_plan",
        "declarative_validation_result",
    }
)
_VALIDATION_RESULT_KEYS = (
    "plan_id",
    "candidate_id",
    "status",
    "evidence",
    "cleanup_status",
    "notes",
)
_VALIDATION_PLAN_KEYS = (
    "version",
    "id",
    "candidate_id",
    "steps",
    "cleanup",
    "description",
)
_DISPLAY_BODY_LIMIT = 4_096
_QUOTED_SECRET_VALUE = re.compile(
    r"(?i)([\"'](?:api[-_]?key|authorization|password|passwd|secret|access[-_]?token|refresh[-_]?token|"
    r"id[-_]?token|cookie|session)[\"']\s*:\s*)"
    r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^,\s}\]]+)',
)


def build_result_sections(result: ScanResult) -> dict[str, Any]:
    results_by_id = {item.candidate_id: item for item in result.verification_results}
    sections = {
        "dependency_vulnerabilities": {
            "label": "依赖漏洞",
            "description": "来自 requirements.txt、pom.xml、package.json、go.mod 等依赖清单的组件/CVE 风险候选。",
            "items": [finding.to_dict() for finding in result.dependency_findings],
        },
        "confirmed_vulnerabilities": {
            "label": "已确认漏洞",
            "description": "已绑定运行时复现证据的漏洞，可进入正式漏洞报告。",
            "items": [],
        },
        "sandbox_executed_reviews": {
            "label": "沙箱执行待复核",
            "description": "LLM 生成的代码片段测试已在隔离容器中执行，但这不是目标环境漏洞确认。",
            "items": [],
        },
        "candidate_vulnerabilities": {
            "label": "候选漏洞",
            "description": "静态分析或 LLM 补全生成的 source-to-sink 候选，尚未获得确认复现证据。",
            "items": [],
        },
        "archived_results": {
            "label": "验证归档",
            "description": "已标记为误报、未复现或验证受阻的候选结果。",
            "items": [],
        },
    }

    for candidate in result.candidates:
        verification = results_by_id.get(candidate.id)
        payload = {
            "candidate": candidate.to_dict(),
            "verification": verification.to_dict() if verification else None,
            "section_reason": section_reason(verification),
        }
        sections[section_id_for_verification(verification)]["items"].append(payload)

    return {
        "summary": {key: len(value["items"]) for key, value in sections.items()},
        "sections": sections,
    }


def section_id_for_verification(verification: VerificationResult | None) -> str:
    status = verification.status if verification else "not_run"
    if status == "confirmed":
        return "confirmed_vulnerabilities"
    if status in {"sandbox_executed", "sandbox_confirmed"}:
        return "sandbox_executed_reviews"
    if status in {"false_positive", "not_reproducible"}:
        # LLM prose and transport failures are not negative proof. Keep the
        # candidate visible unless an actual HTTP response, sandbox negative
        # assertion, or explicit deterministic checker supports the verdict.
        return "archived_results" if has_runtime_negative_evidence(verification) else "candidate_vulnerabilities"
    return "candidate_vulnerabilities"


def has_runtime_negative_evidence(verification: VerificationResult | Mapping[str, Any] | None) -> bool:
    payload = verification_payload(verification)
    if payload is None:
        return False
    request_log = payload.get("request_log")
    if not isinstance(request_log, list):
        return False
    candidate_id = str(payload.get("candidate_id") or "")
    if has_declarative_runner_negative_evidence(
        request_log,
        candidate_id=candidate_id,
        verification_status=str(payload.get("status") or ""),
    ):
        return True
    for item in request_log:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "sandbox_python" and item.get("ok") and item.get("negative_proof_valid"):
            return True
        if item.get("type") == "deterministic_negative" and item.get("valid"):
            return True
        # HttpResponseRecord entries have method/url/status. A concrete HTTP
        # status is runtime evidence; status=None/error is a transport failure.
        if item.get("method") and item.get("url") and isinstance(item.get("status"), int) and not item.get("error"):
            return True
    return False


def verification_payload(verification: VerificationResult | Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return a persisted verification payload from either models or dashboard rows."""

    if verification is None:
        return None
    if isinstance(verification, VerificationResult):
        return verification.to_dict()
    if not isinstance(verification, Mapping):
        return None
    payload_json = verification.get("payload_json")
    if isinstance(payload_json, str):
        try:
            decoded = json.loads(payload_json)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, dict):
            if "candidate_id" not in decoded and verification.get("candidate_id"):
                decoded["candidate_id"] = verification.get("candidate_id")
            return decoded
    return dict(verification)


def collect_declarative_validation_runs(request_log: object) -> list[dict[str, Any]]:
    """Pair persisted declaration plans and runner results without trusting their prose."""

    if not isinstance(request_log, list):
        return []
    runs: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for index, raw in enumerate(request_log):
        if not isinstance(raw, Mapping):
            continue
        entry_type = str(raw.get("type") or "")
        if entry_type not in DECLARATIVE_VALIDATION_TYPES:
            continue
        plan = raw.get("plan") if isinstance(raw.get("plan"), Mapping) else None
        if plan is None and entry_type == "declarative_validation_plan":
            plan = _validation_plan_payload(raw)
        nested_result = raw.get("result") if isinstance(raw.get("result"), Mapping) else None
        result = _validation_result_payload(nested_result or raw) if entry_type != "declarative_validation_plan" else None
        plan_id = str(
            raw.get("plan_id")
            or (plan.get("id") if plan else "")
            or (plan.get("plan_id") if plan else "")
            or (result.get("plan_id") if result else "")
        )
        key = plan_id or f"entry-{index}"
        if key not in runs:
            runs[key] = {"plan_id": plan_id, "entry_types": []}
            order.append(key)
        run = runs[key]
        run["entry_types"].append(entry_type)
        if plan is not None:
            run["plan"] = dict(plan)
        if result is not None:
            run["result"] = result
        runner = raw.get("runner")
        if isinstance(runner, Mapping):
            run["runner"] = dict(runner)
        elif isinstance(runner, str):
            mode = runner.strip().lower()
            run["runner"] = {"mode": mode, "configured": mode in {"inline", "queue"}}
    return [runs[key] for key in order]


def has_declarative_runner_negative_evidence(
    request_log: object,
    *,
    candidate_id: str = "",
    verification_status: str = "",
) -> bool:
    """Accept negative deep-verification verdicts only from a paired real runner result.

    A plan, LLM verdict, timeout, or transport error cannot archive a candidate. The
    structured result must parse under the runner DSL and contain a concrete HTTP
    response whose assertion failed.
    """

    for run in collect_declarative_validation_runs(request_log):
        plan = run.get("plan")
        raw_result = run.get("result")
        runner = run.get("runner")
        entry_types = set(run.get("entry_types") or [])
        if not isinstance(plan, Mapping) or not isinstance(raw_result, Mapping):
            continue
        if not entry_types.intersection({"declarative_validation", "declarative_validation_result"}):
            continue
        if not isinstance(runner, Mapping) or runner.get("configured") is not True:
            continue
        if str(runner.get("mode") or "") not in {"inline", "queue"}:
            continue
        try:
            result = ValidationEvidenceResult.from_dict(raw_result)
        except (TypeError, ValueError):
            continue
        plan_id = str(plan.get("id") or plan.get("plan_id") or plan.get("planId") or "")
        plan_candidate_id = str(plan.get("candidate_id") or plan.get("candidateId") or "")
        if not plan_id or result.plan_id != plan_id or not plan_candidate_id or result.candidate_id != plan_candidate_id:
            continue
        if candidate_id and result.candidate_id != candidate_id:
            continue
        if result.status == "not_reproduced" and verification_status in {"", "not_reproducible"}:
            if any(_is_concrete_failed_risk_assertion(plan, item.to_dict()) for item in result.evidence):
                return True
        if result.status == "runtime_confirmed" and verification_status in {"", "false_positive"}:
            if any(_is_concrete_passed_safe_control(plan, item.to_dict()) for item in result.evidence):
                return True
    return False


def redact_validation_payload(value: Any, *, key: str = "") -> Any:
    """Build a bounded presentation-only copy of runner evidence."""

    normalized_key = key.lower().replace("-", "_")
    if normalized_key in {"url", "target_url", "base_url"} and isinstance(value, str):
        return redact_url(value)
    if normalized_key == "body_sample" and isinstance(value, str):
        safe_body = _redact_response_body(value)
        if len(safe_body) > _DISPLAY_BODY_LIMIT:
            return safe_body[:_DISPLAY_BODY_LIMIT] + "\n…（响应正文已截断）"
        return safe_body
    if isinstance(value, Mapping):
        safe_mapping = redact(value)
        return {str(item_key): redact_validation_payload(item, key=str(item_key)) for item_key, item in safe_mapping.items()}
    if isinstance(value, (list, tuple)):
        return [redact_validation_payload(item, key=key) for item in value]
    return redact(value)


def _redact_response_body(value: str) -> str:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        safe = str(redact(value))
        return _QUOTED_SECRET_VALUE.sub(r'\1"[REDACTED]"', safe)
    safe_json = redact(parsed)
    return json.dumps(safe_json, ensure_ascii=False, separators=(",", ":"))


def _validation_result_payload(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    if not isinstance(raw.get("evidence"), list) or not raw.get("status"):
        return None
    payload = {key: raw.get(key) for key in _VALIDATION_RESULT_KEYS}
    payload["plan_id"] = payload.get("plan_id") or raw.get("planId")
    payload["candidate_id"] = payload.get("candidate_id") or raw.get("candidateId")
    payload["cleanup_status"] = payload.get("cleanup_status") or raw.get("cleanupStatus") or "not_run"
    payload["notes"] = payload.get("notes") or ""
    return payload


def _validation_plan_payload(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    if not isinstance(raw.get("steps"), list) or not isinstance(raw.get("cleanup"), Mapping):
        return None
    payload = {key: raw.get(key) for key in _VALIDATION_PLAN_KEYS}
    payload["id"] = payload.get("id") or raw.get("plan_id") or raw.get("planId")
    payload["candidate_id"] = payload.get("candidate_id") or raw.get("candidateId")
    return payload


def _is_concrete_failed_risk_assertion(plan: Mapping[str, Any], raw: Mapping[str, Any]) -> bool:
    step = _plan_step(plan, str(raw.get("step_id") or ""))
    if step is None or not _request_for_assertion_contains_marker(plan, step):
        return False
    expected = step.get("expected")
    if not isinstance(expected, Mapping) or not any(
        _json_value_contains_marker(expected.get(key)) for key in ("body_contains", "json_contains", "json_path_equals")
    ):
        return False
    return _is_concrete_assertion_response(
        raw,
        evidence_status="failed",
        assertion_names={"body_contains", "json_contains", "json_path_equals"},
        assertion_value=False,
    )


def _is_concrete_passed_safe_control(plan: Mapping[str, Any], raw: Mapping[str, Any]) -> bool:
    step = _plan_step(plan, str(raw.get("step_id") or ""))
    if step is None or not _request_for_assertion_contains_marker(plan, step):
        return False
    expected = step.get("expected")
    if not isinstance(expected, Mapping) or not _json_value_contains_marker(expected.get("body_not_contains")):
        return False
    return _is_concrete_assertion_response(
        raw,
        evidence_status="passed",
        assertion_names={"body_not_contains"},
        assertion_value=True,
    )


def _is_concrete_assertion_response(
    raw: Mapping[str, Any],
    *,
    evidence_status: str,
    assertion_names: set[str],
    assertion_value: bool,
) -> bool:
    if raw.get("status") != evidence_status:
        return False
    observed = raw.get("observed")
    if not isinstance(observed, Mapping) or observed.get("error"):
        return False
    response_status = observed.get("status")
    assertions = observed.get("assertions")
    return (
        isinstance(observed.get("method"), str)
        and isinstance(observed.get("url"), str)
        and isinstance(response_status, int)
        and 200 <= response_status < 300
        and isinstance(assertions, Mapping)
        and any(assertions.get(name) is assertion_value for name in assertion_names)
    )


def _plan_step(plan: Mapping[str, Any], step_id: str) -> Mapping[str, Any] | None:
    steps = plan.get("steps")
    if not isinstance(steps, list):
        return None
    return next((step for step in steps if isinstance(step, Mapping) and str(step.get("id") or "") == step_id), None)


def _request_for_assertion_contains_marker(plan: Mapping[str, Any], assertion_step: Mapping[str, Any]) -> bool:
    action = str(assertion_step.get("action") or assertion_step.get("type") or "")
    if action == "http_request":
        request_step = assertion_step
    else:
        request_step = _plan_step(plan, str(assertion_step.get("request_id") or assertion_step.get("requestId") or ""))
    if request_step is None:
        return False
    return any(_json_value_contains_marker(request_step.get(key)) for key in ("url", "query", "body", "headers"))


def _json_value_contains_marker(value: Any) -> bool:
    if isinstance(value, str):
        return "AF_MARKER" in value
    if isinstance(value, Mapping):
        return any(_json_value_contains_marker(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_json_value_contains_marker(item) for item in value)
    return False


def section_reason(verification: VerificationResult | None) -> str:
    status = verification.status if verification else "not_run"
    if status in {"false_positive", "not_reproducible"} and not has_runtime_negative_evidence(verification):
        return "负面判断缺少确定性或运行时证据，候选继续保留并等待人工复核。"
    return {
        "confirmed": "运行时复现确认。",
        "sandbox_executed": "容器沙箱测试已执行，仍需人工或目标环境复核。",
        "sandbox_confirmed": "旧版本容器沙箱结果；按待复核处理，不自动视为漏洞确认。",
        "false_positive": "验证结果指向误报。",
        "not_reproducible": "当前环境未复现。",
        "blocked": "缺少凭证、环境或安全前置条件，验证受阻；候选继续保留在工作队列。",
        "needs_manual_review": "需要人工复核。",
        "not_run": "尚未执行验证。",
    }.get(status, status)
