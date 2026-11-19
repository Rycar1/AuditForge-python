"""Bounded, declarative runtime-validation plans.

The DSL deliberately describes observations instead of executable code.  It is
safe to persist LLM-produced JSON only after :func:`normalize_validation_plan`
has accepted it with a runner-controlled ``target_url``.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal, TypeAlias
from urllib.parse import unquote, urlsplit

ActionType = Literal["http_request", "browser_assert", "oast_probe", "runtime_assert"]
StepType = Literal["http_request", "assert_response", "oast_placeholder", "playwright_placeholder"]
CleanupStrategy = Literal["none", "rollback", "delete_test_data", "reset_environment"]
StepExecutionStatus = Literal["ready", "unsupported"]
EvidenceStatus = Literal["passed", "failed", "blocked", "unsupported", "error"]
EvidenceResultStatus = Literal["runtime_confirmed", "not_reproduced", "inconclusive", "blocked", "error"]
CleanupStatus = Literal["not_required", "succeeded", "failed", "not_run"]

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

PLAN_VERSION = 1
MAX_STEPS = 12
MAX_HEADERS = 24
MAX_HEADER_VALUE_LENGTH = 2_048
MAX_HEADER_BYTES = 8_192
MAX_QUERY_FIELDS = 32
MAX_BODY_BYTES = 32_768
MAX_EXPECTED_BYTES = 16_384
MAX_EXPECTED_ASSERTIONS = 16
MAX_EVIDENCE_BYTES = 65_536
MAX_URL_LENGTH = 2_048
MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 30_000

ACTION_TYPES = frozenset({"http_request", "browser_assert", "oast_probe", "runtime_assert"})
STEP_TYPES = frozenset({"http_request", "assert_response", "oast_placeholder", "playwright_placeholder"})
HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
READ_ONLY_HTTP_METHODS = frozenset({"GET", "HEAD"})
CLEANUP_STRATEGIES = frozenset({"none", "rollback", "delete_test_data", "reset_environment"})

_STEP_TYPE_TO_ACTION: dict[str, ActionType] = {
    "http_request": "http_request",
    "assert_response": "runtime_assert",
    "oast_placeholder": "oast_probe",
    "playwright_placeholder": "browser_assert",
}
_ACTION_TO_STEP_TYPE: dict[str, StepType] = {
    "http_request": "http_request",
    "runtime_assert": "assert_response",
    "oast_probe": "oast_placeholder",
    "browser_assert": "playwright_placeholder",
}
_PLACEHOLDER_TYPES = frozenset({"oast_placeholder", "playwright_placeholder"})

_HTTP_ASSERTIONS = frozenset(
    {
        "status",
        "status_code",
        "status_in",
        "body_contains",
        "body_not_contains",
        "header_equals",
        "json_contains",
        "json_path_equals",
    }
)
_BROWSER_ASSERTIONS = frozenset(
    {
        "selector_exists",
        "selector_not_exists",
        "visible",
        "text_contains",
        "text_not_contains",
        "url_equals",
        "attribute_equals",
        "count",
    }
)
_OAST_ASSERTIONS = frozenset({"interaction_received", "protocol", "minimum_interactions"})

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}\Z")
_FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "forwarded",
        "host",
        "proxy-authenticate",
        "proxy-authorization",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-forwarded-host",
        "x-original-url",
        "x-rewrite-url",
    }
)
_METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data",
        "169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)
_URL_REFERENCE_RE = re.compile(r"(?i)(?:https?:)?//(?:\[[0-9a-f:.%]+\]|[^\s/?#]+)")
_IPV4_REFERENCE_RE = re.compile(r"(?<![0-9A-Za-z])(?:0x[0-9a-f]+|[0-9]{1,10})(?:\.(?:0x[0-9a-f]+|[0-9]{1,10})){0,3}(?![0-9A-Za-z])", re.I)
_IPV6_REFERENCE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_PLACEHOLDER_REASONS = {
    "oast_placeholder": "OAST execution is unsupported until an allowlisted callback provider is configured.",
    "playwright_placeholder": "Playwright execution is unsupported until an isolated browser runner is configured.",
}


class ValidationPlanError(ValueError):
    """Raised when untrusted plan JSON violates the declarative contract."""

    def __init__(self, message: str, *, path: str = "plan") -> None:
        self.path = path
        self.message = message
        super().__init__(f"{path}: {message}")


@dataclass(frozen=True, slots=True)
class CleanupPolicy:
    strategy: CleanupStrategy
    always: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"strategy": self.strategy, "always": self.always}

    @classmethod
    def from_dict(cls, raw: str | Mapping[str, Any]) -> CleanupPolicy:
        return _normalize_cleanup(raw)


@dataclass(frozen=True, slots=True)
class ValidationStep:
    id: str
    type: StepType
    action: ActionType
    expected: dict[str, JsonValue]
    method: str | None = None
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str | list[str]] = field(default_factory=dict)
    body: JsonValue = None
    request_id: str | None = None
    selector: str | None = None
    channel: str | None = None
    identity: str | None = None
    timeout_ms: int = 5_000
    execution_status: StepExecutionStatus = "ready"
    blocked_reason: str | None = None

    @property
    def is_executable(self) -> bool:
        return self.execution_status == "ready"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "action": self.action,
            "expected": _copy_json(self.expected),
            "timeout_ms": self.timeout_ms,
            "execution_status": self.execution_status,
        }
        if self.method is not None:
            payload["method"] = self.method
        if self.url is not None:
            payload["url"] = self.url
        if self.headers:
            payload["headers"] = dict(self.headers)
        if self.query:
            payload["query"] = {key: list(value) if isinstance(value, list) else value for key, value in self.query.items()}
        if self.body is not None:
            payload["body"] = _copy_json(self.body)
        if self.request_id is not None:
            payload["request_id"] = self.request_id
        if self.selector is not None:
            payload["selector"] = self.selector
        if self.channel is not None:
            payload["channel"] = self.channel
        if self.identity is not None:
            payload["identity"] = self.identity
        if self.blocked_reason is not None:
            payload["blocked_reason"] = self.blocked_reason
        return payload

    @classmethod
    def from_dict(
        cls,
        raw: Mapping[str, Any],
        *,
        target_url: str | None = None,
        index: int = 0,
    ) -> ValidationStep:
        step = _normalize_step(raw, target_url=target_url, index=index)
        _validate_step(step, target_url=target_url, path=f"plan.steps[{index}]")
        return step


@dataclass(frozen=True, slots=True)
class DeclarativeValidationPlan:
    version: int
    id: str
    candidate_id: str
    steps: tuple[ValidationStep, ...]
    cleanup: CleanupPolicy
    description: str = ""

    @property
    def executable_steps(self) -> tuple[ValidationStep, ...]:
        return tuple(step for step in self.steps if step.is_executable)

    @property
    def blocked_steps(self) -> tuple[ValidationStep, ...]:
        return tuple(step for step in self.steps if not step.is_executable)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "version": self.version,
            "id": self.id,
            "candidate_id": self.candidate_id,
            "steps": [step.to_dict() for step in self.steps],
            "cleanup": self.cleanup.to_dict(),
        }
        if self.description:
            payload["description"] = self.description
        return payload

    @classmethod
    def from_dict(
        cls,
        raw: Mapping[str, Any],
        *,
        target_url: str | None = None,
    ) -> DeclarativeValidationPlan:
        return normalize_validation_plan(raw, target_url=target_url)


# A short name is useful to callers that import this module explicitly.  The
# existing auditforge.core.models.VerificationPlan remains a separate legacy model.
ValidationPlan = DeclarativeValidationPlan


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    step_id: str
    action: ActionType
    status: EvidenceStatus
    summary: str
    observed: dict[str, JsonValue] = field(default_factory=dict)
    elapsed_ms: int | None = None
    artifacts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "step_id": self.step_id,
            "action": self.action,
            "status": self.status,
            "summary": self.summary,
            "observed": _copy_json(self.observed),
            "artifacts": list(self.artifacts),
        }
        if self.elapsed_ms is not None:
            payload["elapsed_ms"] = self.elapsed_ms
        return payload

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> EvidenceRecord:
        if not isinstance(raw, Mapping):
            raise ValidationPlanError("must be an object", path="evidence")
        _reject_unknown_keys(
            raw,
            {"step_id", "stepId", "action", "type", "status", "summary", "observed", "elapsed_ms", "elapsedMs", "artifacts"},
            path="evidence",
        )
        step_id = _normalize_identifier(_pick(raw, "step_id", "stepId"), path="evidence.step_id")
        action, step_type = _normalize_action_and_type(raw, path="evidence")
        status = _required_text(raw.get("status"), path="evidence.status", maximum=32).lower()
        if status not in {"passed", "failed", "blocked", "unsupported", "error"}:
            raise ValidationPlanError("unsupported evidence status", path="evidence.status")
        if step_type in _PLACEHOLDER_TYPES and status not in {"blocked", "unsupported"}:
            raise ValidationPlanError("placeholder evidence must be blocked or unsupported", path="evidence.status")
        summary = _required_text(raw.get("summary"), path="evidence.summary", maximum=2_000)
        observed_raw = raw.get("observed", {})
        if not isinstance(observed_raw, Mapping):
            raise ValidationPlanError("must be an object", path="evidence.observed")
        observed = _normalize_json_mapping(observed_raw, path="evidence.observed", maximum_bytes=MAX_EVIDENCE_BYTES)
        elapsed_value = _pick(raw, "elapsed_ms", "elapsedMs", default=None)
        elapsed_ms: int | None = None
        if elapsed_value is not None:
            elapsed_ms = _bounded_int(elapsed_value, path="evidence.elapsed_ms", minimum=0, maximum=86_400_000)
        artifacts_raw = raw.get("artifacts", [])
        if not isinstance(artifacts_raw, list) or len(artifacts_raw) > 16:
            raise ValidationPlanError("must be an array with at most 16 items", path="evidence.artifacts")
        artifacts = tuple(
            _required_text(item, path=f"evidence.artifacts[{index}]", maximum=1_024) for index, item in enumerate(artifacts_raw)
        )
        return cls(
            step_id=step_id,
            action=action,
            status=status,  # type: ignore[arg-type]
            summary=summary,
            observed=observed,
            elapsed_ms=elapsed_ms,
            artifacts=artifacts,
        )

    @classmethod
    def unsupported_step(cls, step: ValidationStep) -> EvidenceRecord:
        if step.is_executable:
            raise ValidationPlanError("only unsupported steps can produce placeholder evidence", path=f"step.{step.id}")
        return cls(
            step_id=step.id,
            action=step.action,
            status="unsupported",
            summary=step.blocked_reason or "The runner does not support this step.",
            observed={},
        )


StepEvidence = EvidenceRecord


@dataclass(frozen=True, slots=True)
class ValidationEvidenceResult:
    plan_id: str
    candidate_id: str
    status: EvidenceResultStatus
    evidence: tuple[EvidenceRecord, ...]
    cleanup_status: CleanupStatus = "not_run"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "candidate_id": self.candidate_id,
            "status": self.status,
            "evidence": [item.to_dict() for item in self.evidence],
            "cleanup_status": self.cleanup_status,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ValidationEvidenceResult:
        if not isinstance(raw, Mapping):
            raise ValidationPlanError("must be an object", path="result")
        _reject_unknown_keys(
            raw,
            {
                "plan_id",
                "planId",
                "candidate_id",
                "candidateId",
                "status",
                "evidence",
                "cleanup_status",
                "cleanupStatus",
                "notes",
            },
            path="result",
        )
        plan_id = _normalize_identifier(_pick(raw, "plan_id", "planId"), path="result.plan_id")
        candidate_id = _normalize_identifier(_pick(raw, "candidate_id", "candidateId"), path="result.candidate_id")
        status = _required_text(raw.get("status"), path="result.status", maximum=32).lower()
        allowed_statuses = {"runtime_confirmed", "not_reproduced", "inconclusive", "blocked", "error"}
        if status not in allowed_statuses:
            raise ValidationPlanError("unsupported result status", path="result.status")
        evidence_raw = raw.get("evidence")
        if not isinstance(evidence_raw, list) or not evidence_raw or len(evidence_raw) > MAX_STEPS:
            raise ValidationPlanError(f"must contain between 1 and {MAX_STEPS} records", path="result.evidence")
        evidence = tuple(EvidenceRecord.from_dict(item) for item in evidence_raw)
        cleanup_status = _required_text(
            _pick(raw, "cleanup_status", "cleanupStatus", default="not_run"),
            path="result.cleanup_status",
            maximum=32,
        ).lower()
        if cleanup_status not in {"not_required", "succeeded", "failed", "not_run"}:
            raise ValidationPlanError("unsupported cleanup status", path="result.cleanup_status")
        notes_raw = raw.get("notes", "")
        notes = _optional_text(notes_raw, path="result.notes", maximum=4_000)
        _validate_evidence_result_status(status, evidence)
        return cls(
            plan_id=plan_id,
            candidate_id=candidate_id,
            status=status,  # type: ignore[arg-type]
            evidence=evidence,
            cleanup_status=cleanup_status,  # type: ignore[arg-type]
            notes=notes,
        )


ValidationResult = ValidationEvidenceResult


def normalize_validation_plan(
    raw: Mapping[str, Any],
    *,
    target_url: str | None = None,
) -> DeclarativeValidationPlan:
    """Normalize untrusted JSON data and return a validated immutable plan.

    ``target_url`` is trusted runner configuration, not a value from ``raw``.
    Absolute step URLs are accepted only when their origin exactly matches it.
    """

    if not isinstance(raw, Mapping):
        raise ValidationPlanError("must be an object")
    _reject_unknown_keys(
        raw,
        {"version", "id", "plan_id", "planId", "candidate_id", "candidateId", "steps", "cleanup", "description"},
        path="plan",
    )
    version = _bounded_int(raw.get("version", PLAN_VERSION), path="plan.version", minimum=PLAN_VERSION, maximum=PLAN_VERSION)
    plan_id = _normalize_identifier(_pick(raw, "id", "plan_id", "planId"), path="plan.id")
    candidate_id = _normalize_identifier(_pick(raw, "candidate_id", "candidateId"), path="plan.candidate_id")
    description = _optional_text(raw.get("description", ""), path="plan.description", maximum=1_000)
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise ValidationPlanError("must be a non-empty array", path="plan.steps")
    if len(steps_raw) > MAX_STEPS:
        raise ValidationPlanError(f"must contain at most {MAX_STEPS} steps", path="plan.steps")
    steps = tuple(_normalize_step(item, target_url=target_url, index=index) for index, item in enumerate(steps_raw))
    steps = _resolve_response_references(steps)
    cleanup = _normalize_cleanup(raw.get("cleanup", "none"))
    plan = DeclarativeValidationPlan(
        version=version,
        id=plan_id,
        candidate_id=candidate_id,
        steps=steps,
        cleanup=cleanup,
        description=description,
    )
    validate_validation_plan(plan, target_url=target_url)
    return plan


def validate_validation_plan(
    plan: DeclarativeValidationPlan,
    *,
    target_url: str | None = None,
) -> DeclarativeValidationPlan:
    """Validate an already-normalized plan, returning it for fluent callers."""

    if not isinstance(plan, DeclarativeValidationPlan):
        raise ValidationPlanError("must be a DeclarativeValidationPlan")
    if plan.version != PLAN_VERSION:
        raise ValidationPlanError(f"only version {PLAN_VERSION} is supported", path="plan.version")
    _normalize_identifier(plan.id, path="plan.id")
    _normalize_identifier(plan.candidate_id, path="plan.candidate_id")
    if not plan.steps or len(plan.steps) > MAX_STEPS:
        raise ValidationPlanError(f"must contain between 1 and {MAX_STEPS} steps", path="plan.steps")
    if not isinstance(plan.cleanup, CleanupPolicy):
        raise ValidationPlanError("must be a CleanupPolicy", path="plan.cleanup")
    if plan.cleanup.strategy not in CLEANUP_STRATEGIES:
        raise ValidationPlanError("unsupported cleanup strategy", path="plan.cleanup.strategy")

    seen_ids: set[str] = set()
    http_ids: set[str] = set()
    covered_http_ids: set[str] = set()
    has_assertions = False
    has_state_change = False
    for index, step in enumerate(plan.steps):
        path = f"plan.steps[{index}]"
        _validate_step(step, target_url=target_url, path=path)
        if step.id in seen_ids:
            raise ValidationPlanError("step id must be unique", path=f"{path}.id")
        seen_ids.add(step.id)
        has_assertions = has_assertions or bool(step.expected)
        if step.type == "http_request":
            http_ids.add(step.id)
            if step.expected:
                covered_http_ids.add(step.id)
            has_state_change = has_state_change or step.method not in READ_ONLY_HTTP_METHODS
        elif step.type == "assert_response":
            if step.request_id not in http_ids:
                raise ValidationPlanError("must reference an earlier http_request step", path=f"{path}.request_id")
            covered_http_ids.add(step.request_id)

    if not has_assertions:
        raise ValidationPlanError("at least one expected assertion is required", path="plan.steps")
    uncovered = http_ids - covered_http_ids
    if uncovered:
        missing = ", ".join(sorted(uncovered))
        raise ValidationPlanError(f"http_request steps require expected assertions: {missing}", path="plan.steps")
    if has_state_change and plan.cleanup.strategy == "none":
        raise ValidationPlanError("state-changing HTTP methods require a cleanup strategy", path="plan.cleanup.strategy")
    if has_state_change and not plan.cleanup.always:
        raise ValidationPlanError("cleanup must run even after a failed state-changing step", path="plan.cleanup.always")
    return plan


# Concise aliases for runner code.
normalize_plan = normalize_validation_plan
validate_plan = validate_validation_plan


def _normalize_step(raw: Mapping[str, Any], *, target_url: str | None, index: int) -> ValidationStep:
    path = f"plan.steps[{index}]"
    if not isinstance(raw, Mapping):
        raise ValidationPlanError("must be an object", path=path)
    allowed_keys = {
        "id",
        "step_id",
        "stepId",
        "type",
        "action",
        "method",
        "url",
        "headers",
        "query",
        "body",
        "expected",
        "assertions",
        "request_id",
        "requestId",
        "selector",
        "channel",
        "identity",
        "timeout_ms",
        "timeoutMs",
        "supported",
        "execution_status",
        "executionStatus",
        "blocked_reason",
        "blockedReason",
    }
    _reject_unknown_keys(raw, allowed_keys, path=path)
    step_id = _normalize_identifier(_pick(raw, "id", "step_id", "stepId"), path=f"{path}.id")
    action, step_type = _normalize_action_and_type(raw, path=path)
    expected_raw = _pick(raw, "expected", "assertions", default={})
    expected = _normalize_expected(expected_raw, step_type=step_type, path=f"{path}.expected")
    timeout_ms = _bounded_int(
        _pick(raw, "timeout_ms", "timeoutMs", default=5_000),
        path=f"{path}.timeout_ms",
        minimum=MIN_TIMEOUT_MS,
        maximum=MAX_TIMEOUT_MS,
    )
    identity_raw = raw.get("identity")
    identity = _normalize_identifier(identity_raw, path=f"{path}.identity") if identity_raw is not None else None

    execution_status: StepExecutionStatus = "unsupported" if step_type in _PLACEHOLDER_TYPES else "ready"
    supplied_supported = raw.get("supported")
    if supplied_supported is not None:
        if not isinstance(supplied_supported, bool):
            raise ValidationPlanError("must be a boolean", path=f"{path}.supported")
        if supplied_supported is not (execution_status == "ready"):
            raise ValidationPlanError("contradicts the runner capability for this step type", path=f"{path}.supported")
    supplied_execution = _pick(raw, "execution_status", "executionStatus", default=None)
    if supplied_execution is not None and supplied_execution != execution_status:
        raise ValidationPlanError("contradicts the runner capability for this step type", path=f"{path}.execution_status")
    supplied_reason = _pick(raw, "blocked_reason", "blockedReason", default=None)
    blocked_reason = _PLACEHOLDER_REASONS.get(step_type)
    if supplied_reason is not None:
        supplied_reason = _required_text(supplied_reason, path=f"{path}.blocked_reason", maximum=1_000)
        if execution_status == "ready":
            raise ValidationPlanError("executable steps cannot declare a blocked reason", path=f"{path}.blocked_reason")
        blocked_reason = supplied_reason

    method: str | None = None
    url: str | None = None
    headers: dict[str, str] = {}
    query: dict[str, str | list[str]] = {}
    body: JsonValue = None
    request_id: str | None = None
    selector: str | None = None
    channel: str | None = None

    if step_type == "http_request":
        method = _required_text(raw.get("method"), path=f"{path}.method", maximum=16).upper()
        if method not in HTTP_METHODS:
            raise ValidationPlanError("unsupported HTTP method", path=f"{path}.method")
        url = _normalize_step_url(raw.get("url"), target_url=target_url, path=f"{path}.url")
        headers = _normalize_headers(raw.get("headers", {}), path=f"{path}.headers")
        query = _normalize_query(raw.get("query", {}), path=f"{path}.query")
        body = _normalize_body(raw.get("body"), path=f"{path}.body")
        if method in READ_ONLY_HTTP_METHODS and body is not None:
            raise ValidationPlanError("GET and HEAD requests cannot contain a body", path=f"{path}.body")
    elif step_type == "assert_response":
        request_raw = _pick(raw, "request_id", "requestId", default=None)
        request_id = _normalize_identifier(request_raw, path=f"{path}.request_id") if request_raw is not None else None
    elif step_type == "playwright_placeholder":
        url = _normalize_step_url(raw.get("url"), target_url=target_url, path=f"{path}.url")
        selector = _required_text(raw.get("selector"), path=f"{path}.selector", maximum=1_000)
    elif step_type == "oast_placeholder":
        channel = _optional_text(raw.get("channel", "http"), path=f"{path}.channel", maximum=16).lower()
        if channel not in {"http", "dns"}:
            raise ValidationPlanError("must be http or dns", path=f"{path}.channel")

    _reject_irrelevant_step_fields(raw, step_type=step_type, path=path)
    return ValidationStep(
        id=step_id,
        type=step_type,
        action=action,
        expected=expected,
        method=method,
        url=url,
        headers=headers,
        query=query,
        body=body,
        request_id=request_id,
        selector=selector,
        channel=channel,
        identity=identity,
        timeout_ms=timeout_ms,
        execution_status=execution_status,
        blocked_reason=blocked_reason,
    )


def _validate_step(step: ValidationStep, *, target_url: str | None, path: str) -> None:
    if not isinstance(step, ValidationStep):
        raise ValidationPlanError("must be a ValidationStep", path=path)
    _normalize_identifier(step.id, path=f"{path}.id")
    if step.type not in STEP_TYPES or step.action not in ACTION_TYPES:
        raise ValidationPlanError("unsupported step action or type", path=path)
    if _STEP_TYPE_TO_ACTION[step.type] != step.action:
        raise ValidationPlanError("step type and action do not match", path=path)
    expected = _normalize_expected(step.expected, step_type=step.type, path=f"{path}.expected")
    if step.type != "http_request" and not expected:
        raise ValidationPlanError("expected assertions are required", path=f"{path}.expected")
    _bounded_int(step.timeout_ms, path=f"{path}.timeout_ms", minimum=MIN_TIMEOUT_MS, maximum=MAX_TIMEOUT_MS)
    if step.type in _PLACEHOLDER_TYPES:
        if step.execution_status != "unsupported" or not step.blocked_reason:
            raise ValidationPlanError("placeholder steps must be explicitly unsupported", path=f"{path}.execution_status")
    elif step.execution_status != "ready" or step.blocked_reason is not None:
        raise ValidationPlanError("executable steps must be ready and unblocked", path=f"{path}.execution_status")
    if step.type == "http_request":
        if step.method not in HTTP_METHODS:
            raise ValidationPlanError("unsupported HTTP method", path=f"{path}.method")
        _normalize_step_url(step.url, target_url=target_url, path=f"{path}.url")
        _normalize_headers(step.headers, path=f"{path}.headers")
        _normalize_query(step.query, path=f"{path}.query")
        _normalize_body(step.body, path=f"{path}.body")
        if step.method in READ_ONLY_HTTP_METHODS and step.body is not None:
            raise ValidationPlanError("GET and HEAD requests cannot contain a body", path=f"{path}.body")
    elif step.type == "assert_response" and step.request_id is None:
        raise ValidationPlanError("must reference an earlier http_request step", path=f"{path}.request_id")
    elif step.type == "playwright_placeholder":
        _normalize_step_url(step.url, target_url=target_url, path=f"{path}.url")
        _required_text(step.selector, path=f"{path}.selector", maximum=1_000)
    elif step.type == "oast_placeholder" and step.channel not in {"http", "dns"}:
        raise ValidationPlanError("must be http or dns", path=f"{path}.channel")


def _resolve_response_references(steps: tuple[ValidationStep, ...]) -> tuple[ValidationStep, ...]:
    previous_http_id: str | None = None
    resolved: list[ValidationStep] = []
    for index, step in enumerate(steps):
        if step.type == "http_request":
            previous_http_id = step.id
        elif step.type == "assert_response" and step.request_id is None:
            if previous_http_id is None:
                raise ValidationPlanError("requires an earlier http_request step", path=f"plan.steps[{index}].request_id")
            step = replace(step, request_id=previous_http_id)
        resolved.append(step)
    return tuple(resolved)


def _normalize_action_and_type(raw: Mapping[str, Any], *, path: str) -> tuple[ActionType, StepType]:
    raw_action = raw.get("action")
    raw_type = raw.get("type")
    if raw_action is None and raw_type is None:
        raise ValidationPlanError("action or type is required", path=f"{path}.action")

    action: ActionType | None = None
    step_type: StepType | None = None
    if raw_action is not None:
        action_text = _required_text(raw_action, path=f"{path}.action", maximum=40).lower()
        if action_text not in ACTION_TYPES:
            raise ValidationPlanError("unsupported action", path=f"{path}.action")
        action = action_text  # type: ignore[assignment]
        step_type = _ACTION_TO_STEP_TYPE[action_text]
    if raw_type is not None:
        type_text = _required_text(raw_type, path=f"{path}.type", maximum=40).lower()
        if type_text in ACTION_TYPES:
            type_action = type_text
            type_step = _ACTION_TO_STEP_TYPE[type_text]
        elif type_text in STEP_TYPES:
            type_step = type_text
            type_action = _STEP_TYPE_TO_ACTION[type_text]
        else:
            raise ValidationPlanError("unsupported step type", path=f"{path}.type")
        if action is not None and action != type_action:
            raise ValidationPlanError("action and type do not match", path=path)
        action = type_action  # type: ignore[assignment]
        step_type = type_step  # type: ignore[assignment]
    if action is None or step_type is None:  # pragma: no cover - guarded above
        raise ValidationPlanError("could not determine action", path=path)
    return action, step_type


def _normalize_cleanup(raw: str | Mapping[str, Any]) -> CleanupPolicy:
    path = "plan.cleanup"
    always = True
    if isinstance(raw, str):
        strategy_raw = raw
    elif isinstance(raw, Mapping):
        _reject_unknown_keys(raw, {"strategy", "always"}, path=path)
        strategy_raw = raw.get("strategy")
        always_raw = raw.get("always", True)
        if not isinstance(always_raw, bool):
            raise ValidationPlanError("must be a boolean", path=f"{path}.always")
        always = always_raw
    else:
        raise ValidationPlanError("must be a strategy string or object", path=path)
    strategy = _required_text(strategy_raw, path=f"{path}.strategy", maximum=40).lower().replace("-", "_")
    aliases = {"delete": "delete_test_data", "reset": "reset_environment"}
    strategy = aliases.get(strategy, strategy)
    if strategy not in CLEANUP_STRATEGIES:
        raise ValidationPlanError("unsupported cleanup strategy", path=f"{path}.strategy")
    return CleanupPolicy(strategy=strategy, always=always)  # type: ignore[arg-type]


def _normalize_expected(raw: Any, *, step_type: StepType, path: str) -> dict[str, JsonValue]:
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise ValidationPlanError("must be an object of declarative assertions", path=path)
    if len(raw) > MAX_EXPECTED_ASSERTIONS:
        raise ValidationPlanError(f"must contain at most {MAX_EXPECTED_ASSERTIONS} assertions", path=path)
    expected = _normalize_json_mapping(raw, path=path, maximum_bytes=MAX_EXPECTED_BYTES)
    if step_type in {"http_request", "assert_response"}:
        allowed = _HTTP_ASSERTIONS
    elif step_type == "playwright_placeholder":
        allowed = _BROWSER_ASSERTIONS
    else:
        allowed = _OAST_ASSERTIONS
    unknown = sorted(set(expected) - allowed)
    if unknown:
        raise ValidationPlanError(f"unsupported assertions: {', '.join(unknown)}", path=path)
    _validate_assertion_values(expected, step_type=step_type, path=path)
    return expected


def _validate_assertion_values(expected: Mapping[str, JsonValue], *, step_type: StepType, path: str) -> None:
    status_value = expected.get("status", expected.get("status_code"))
    if status_value is not None:
        _validate_status_code(status_value, path=f"{path}.status")
    if "status_in" in expected:
        values = expected["status_in"]
        if not isinstance(values, list) or not values or len(values) > 16:
            raise ValidationPlanError("must be a non-empty array with at most 16 status codes", path=f"{path}.status_in")
        for index, value in enumerate(values):
            _validate_status_code(value, path=f"{path}.status_in[{index}]")
    for key in ("body_contains", "body_not_contains", "text_contains", "text_not_contains"):
        if key in expected:
            _validate_text_or_text_list(expected[key], path=f"{path}.{key}")
    if "header_equals" in expected:
        _normalize_headers(expected["header_equals"], path=f"{path}.header_equals", allow_sensitive=False)
    if "selector_exists" in expected and not isinstance(expected["selector_exists"], bool):
        raise ValidationPlanError("must be a boolean", path=f"{path}.selector_exists")
    if "selector_not_exists" in expected and not isinstance(expected["selector_not_exists"], bool):
        raise ValidationPlanError("must be a boolean", path=f"{path}.selector_not_exists")
    if "visible" in expected and not isinstance(expected["visible"], bool):
        raise ValidationPlanError("must be a boolean", path=f"{path}.visible")
    if "interaction_received" in expected and not isinstance(expected["interaction_received"], bool):
        raise ValidationPlanError("must be a boolean", path=f"{path}.interaction_received")
    if "protocol" in expected and expected["protocol"] not in {"http", "dns"}:
        raise ValidationPlanError("must be http or dns", path=f"{path}.protocol")
    if "minimum_interactions" in expected:
        _bounded_int(expected["minimum_interactions"], path=f"{path}.minimum_interactions", minimum=1, maximum=100)
    if "count" in expected:
        _bounded_int(expected["count"], path=f"{path}.count", minimum=0, maximum=10_000)
    if step_type == "oast_placeholder" and expected.get("interaction_received") is not True:
        raise ValidationPlanError("must explicitly expect an interaction", path=f"{path}.interaction_received")


def _validate_status_code(value: JsonValue, *, path: str) -> None:
    _bounded_int(value, path=path, minimum=100, maximum=599)


def _validate_text_or_text_list(value: JsonValue, *, path: str) -> None:
    if isinstance(value, str):
        _required_text(value, path=path, maximum=4_096)
        return
    if not isinstance(value, list) or not value or len(value) > 16:
        raise ValidationPlanError("must be text or a non-empty text array with at most 16 items", path=path)
    for index, item in enumerate(value):
        _required_text(item, path=f"{path}[{index}]", maximum=4_096)


def _normalize_step_url(value: Any, *, target_url: str | None, path: str) -> str:
    url = _required_text(value, path=path, maximum=MAX_URL_LENGTH)
    if any(character == "\\" or ord(character) < 0x20 or character.isspace() for character in url):
        raise ValidationPlanError("contains forbidden whitespace, controls, or backslashes", path=path)
    parsed = urlsplit(url)
    if parsed.fragment:
        raise ValidationPlanError("fragments are not allowed", path=path)
    if parsed.scheme or parsed.netloc:
        _validate_absolute_http_url(url, path=path)
        if target_url is None:
            raise ValidationPlanError("absolute URLs require a runner-controlled target_url", path=path)
        _validate_absolute_http_url(target_url, path="target_url")
        if _origin(url, path=path) != _origin(target_url, path="target_url"):
            raise ValidationPlanError("absolute URL must match the controlled target origin", path=path)
        return url
    if not url.startswith("/") or url.startswith("//"):
        raise ValidationPlanError("must be an absolute path beginning with one slash", path=path)
    decoded = url
    for _ in range(3):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    if decoded.startswith("//") or "\\" in decoded or any(ord(character) < 0x20 for character in decoded):
        raise ValidationPlanError("contains an encoded authority or control character", path=path)
    return url


def _validate_absolute_http_url(url: str, *, path: str) -> None:
    if len(url) > MAX_URL_LENGTH or any(character == "\\" or ord(character) < 0x20 or character.isspace() for character in url):
        raise ValidationPlanError("contains forbidden whitespace, controls, or backslashes", path=path)
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValidationPlanError("only HTTP(S) URLs are allowed", path=path)
    if not parsed.hostname:
        raise ValidationPlanError("hostname is required", path=path)
    if parsed.username is not None or parsed.password is not None:
        raise ValidationPlanError("embedded credentials are forbidden", path=path)
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValidationPlanError("contains an invalid port", path=path) from exc
    _validate_target_host(parsed.hostname, path=path)


def _origin(url: str, *, path: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    _validate_absolute_http_url(url, path=path)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").rstrip(".").casefold()
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, hostname, port


def _validate_target_host(hostname: str, *, path: str) -> None:
    host = hostname.rstrip(".").casefold()
    if "%" in host:
        raise ValidationPlanError("IPv6 zone identifiers are forbidden", path=path)
    labels = set(host.split("."))
    if host in _METADATA_HOSTS or "metadata" in labels or "instance-data" in labels:
        raise ValidationPlanError("metadata service targets are forbidden", path=path)
    candidate = host.strip("[]")
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        ip = _parse_obfuscated_ipv4(candidate)
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_link_local or ip in ipaddress.ip_network("169.254.0.0/16") or ip in ipaddress.ip_network("fe80::/10"):
            raise ValidationPlanError("link-local targets are forbidden", path=path)
        if str(ip) in _METADATA_HOSTS:
            raise ValidationPlanError("metadata service targets are forbidden", path=path)


def _parse_obfuscated_ipv4(host: str) -> ipaddress.IPv4Address | None:
    try:
        parts = host.split(".")
        if len(parts) > 4:
            return None
        numbers = [_parse_ipv4_component(part) for part in parts]
        if len(numbers) == 1:
            value = numbers[0]
        elif len(numbers) == 2 and numbers[0] <= 0xFF and numbers[1] <= 0xFFFFFF:
            value = (numbers[0] << 24) | numbers[1]
        elif len(numbers) == 3 and numbers[0] <= 0xFF and numbers[1] <= 0xFF and numbers[2] <= 0xFFFF:
            value = (numbers[0] << 24) | (numbers[1] << 16) | numbers[2]
        elif len(numbers) == 4 and all(number <= 0xFF for number in numbers):
            value = (numbers[0] << 24) | (numbers[1] << 16) | (numbers[2] << 8) | numbers[3]
        else:
            return None
        return ipaddress.IPv4Address(value)
    except (ValueError, OverflowError):
        return None


def _parse_ipv4_component(component: str) -> int:
    if not component:
        raise ValueError("empty IPv4 component")
    if component.lower().startswith("0x"):
        return int(component, 16)
    if len(component) > 1 and component.startswith("0"):
        return int(component, 8)
    return int(component, 10)


def _normalize_headers(raw: Any, *, path: str, allow_sensitive: bool = False) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise ValidationPlanError("must be an object", path=path)
    if len(raw) > MAX_HEADERS:
        raise ValidationPlanError(f"must contain at most {MAX_HEADERS} headers", path=path)
    result: dict[str, str] = {}
    seen: set[str] = set()
    total = 0
    for key, value in raw.items():
        if not isinstance(key, str) or not _HEADER_NAME_RE.fullmatch(key):
            raise ValidationPlanError("contains an invalid header name", path=path)
        lowered = key.casefold()
        if lowered in seen:
            raise ValidationPlanError("contains duplicate case-insensitive header names", path=path)
        if not allow_sensitive and lowered in _FORBIDDEN_HEADERS:
            raise ValidationPlanError(f"header {key!r} is controlled by the runner", path=path)
        if not isinstance(value, str):
            raise ValidationPlanError("header values must be strings", path=f"{path}.{key}")
        if not value or len(value) > MAX_HEADER_VALUE_LENGTH or "\r" in value or "\n" in value or "\0" in value:
            raise ValidationPlanError("contains an empty, oversized, or unsafe header value", path=f"{path}.{key}")
        _reject_forbidden_network_reference(value, path=f"{path}.{key}")
        total += len(key.encode("utf-8")) + len(value.encode("utf-8"))
        if total > MAX_HEADER_BYTES:
            raise ValidationPlanError(f"serialized headers exceed {MAX_HEADER_BYTES} bytes", path=path)
        seen.add(lowered)
        result[key] = value
    return result


def _normalize_query(raw: Any, *, path: str) -> dict[str, str | list[str]]:
    if not isinstance(raw, Mapping):
        raise ValidationPlanError("must be an object", path=path)
    if len(raw) > MAX_QUERY_FIELDS:
        raise ValidationPlanError(f"must contain at most {MAX_QUERY_FIELDS} fields", path=path)
    result: dict[str, str | list[str]] = {}
    for key, value in raw.items():
        normalized_key = _required_text(key, path=f"{path}.key", maximum=256)
        if isinstance(value, list):
            if not value or len(value) > 16:
                raise ValidationPlanError("query arrays must contain between 1 and 16 values", path=f"{path}.{normalized_key}")
            result[normalized_key] = [_query_scalar(item, path=f"{path}.{normalized_key}") for item in value]
        else:
            result[normalized_key] = _query_scalar(value, path=f"{path}.{normalized_key}")
    return result


def _query_scalar(value: Any, *, path: str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise ValidationPlanError("query values must be strings, numbers, booleans, or arrays of them", path=path)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationPlanError("non-finite numbers are forbidden", path=path)
    text = str(value)
    if len(text) > 2_048 or "\0" in text:
        raise ValidationPlanError("query value is oversized or unsafe", path=path)
    _reject_forbidden_network_reference(text, path=path)
    return text


def _normalize_body(raw: Any, *, path: str) -> JsonValue:
    if raw is None:
        return None
    normalized = _normalize_json_value(raw, path=path)
    if _json_size(normalized) > MAX_BODY_BYTES:
        raise ValidationPlanError(f"serialized body exceeds {MAX_BODY_BYTES} bytes", path=path)
    _scan_json_network_references(normalized, path=path)
    return normalized


def _scan_json_network_references(value: JsonValue, *, path: str) -> None:
    if isinstance(value, str):
        _reject_forbidden_network_reference(value, path=path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_json_network_references(item, path=f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _scan_json_network_references(item, path=f"{path}.{key}")


def _reject_forbidden_network_reference(value: str, *, path: str) -> None:
    decoded = value
    for _ in range(3):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    lowered = decoded.casefold()
    if any(re.search(rf"(?<![a-z0-9-]){re.escape(host)}(?![a-z0-9-])", lowered) for host in _METADATA_HOSTS):
        raise ValidationPlanError("metadata service references are forbidden", path=path)
    for match in _URL_REFERENCE_RE.finditer(decoded):
        candidate = match.group(0)
        absolute = candidate if candidate.lower().startswith(("http://", "https://")) else f"http:{candidate}"
        parsed = urlsplit(absolute)
        if parsed.hostname:
            _validate_target_host(parsed.hostname, path=path)
    for match in _IPV4_REFERENCE_RE.finditer(decoded):
        candidate_ip = _parse_obfuscated_ipv4(match.group(0))
        if candidate_ip is not None and (candidate_ip.is_link_local or str(candidate_ip) in _METADATA_HOSTS):
            raise ValidationPlanError("link-local references are forbidden", path=path)
    for match in _IPV6_REFERENCE_RE.finditer(decoded):
        try:
            candidate_ip6 = ipaddress.IPv6Address(match.group(0))
        except ValueError:
            continue
        if candidate_ip6.is_link_local or str(candidate_ip6) in _METADATA_HOSTS:
            raise ValidationPlanError("link-local references are forbidden", path=path)


def _normalize_json_mapping(raw: Mapping[str, Any], *, path: str, maximum_bytes: int) -> dict[str, JsonValue]:
    normalized = _normalize_json_value(dict(raw), path=path)
    if not isinstance(normalized, dict):  # pragma: no cover - dict input guarantees this
        raise ValidationPlanError("must be an object", path=path)
    if _json_size(normalized) > maximum_bytes:
        raise ValidationPlanError(f"serialized value exceeds {maximum_bytes} bytes", path=path)
    return normalized


def _normalize_json_value(raw: Any, *, path: str) -> JsonValue:
    budget = [0]
    ancestors: set[int] = set()

    def visit(value: Any, current_path: str, depth: int) -> JsonValue:
        budget[0] += 1
        if budget[0] > 1_024:
            raise ValidationPlanError("contains too many JSON values", path=path)
        if depth > 12:
            raise ValidationPlanError("nesting is too deep", path=current_path)
        if value is None or isinstance(value, (str, bool, int)):
            if isinstance(value, str) and len(value) > 16_384:
                raise ValidationPlanError("string is too long", path=current_path)
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValidationPlanError("non-finite numbers are forbidden", path=current_path)
            return value
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in ancestors:
                raise ValidationPlanError("cyclic values are forbidden", path=current_path)
            if len(value) > 128:
                raise ValidationPlanError("object contains too many keys", path=current_path)
            ancestors.add(identity)
            result: dict[str, JsonValue] = {}
            for key, item in value.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise ValidationPlanError("object keys must be non-empty strings of at most 256 characters", path=current_path)
                result[key] = visit(item, f"{current_path}.{key}", depth + 1)
            ancestors.remove(identity)
            return result
        if isinstance(value, list):
            identity = id(value)
            if identity in ancestors:
                raise ValidationPlanError("cyclic values are forbidden", path=current_path)
            if len(value) > 256:
                raise ValidationPlanError("array contains too many items", path=current_path)
            ancestors.add(identity)
            result = [visit(item, f"{current_path}[{index}]", depth + 1) for index, item in enumerate(value)]
            ancestors.remove(identity)
            return result
        raise ValidationPlanError("contains a non-JSON value", path=current_path)

    return visit(raw, path, 0)


def _reject_irrelevant_step_fields(raw: Mapping[str, Any], *, step_type: StepType, path: str) -> None:
    common = {
        "id",
        "step_id",
        "stepId",
        "type",
        "action",
        "expected",
        "assertions",
        "identity",
        "timeout_ms",
        "timeoutMs",
        "supported",
        "execution_status",
        "executionStatus",
        "blocked_reason",
        "blockedReason",
    }
    relevant = {
        "http_request": {"method", "url", "headers", "query", "body"},
        "assert_response": {"request_id", "requestId"},
        "playwright_placeholder": {"url", "selector"},
        "oast_placeholder": {"channel"},
    }[step_type]
    irrelevant = sorted(set(raw) - common - relevant)
    if irrelevant:
        raise ValidationPlanError(f"fields do not apply to {step_type}: {', '.join(irrelevant)}", path=path)


def _validate_evidence_result_status(status: str, evidence: tuple[EvidenceRecord, ...]) -> None:
    evidence_statuses = {item.status for item in evidence}
    if status == "runtime_confirmed" and evidence_statuses != {"passed"}:
        raise ValidationPlanError("runtime_confirmed requires every evidence record to pass", path="result.status")
    if status == "not_reproduced" and "failed" not in evidence_statuses:
        raise ValidationPlanError("not_reproduced requires failed runtime evidence", path="result.status")
    if status == "blocked" and not evidence_statuses.intersection({"blocked", "unsupported"}):
        raise ValidationPlanError("blocked requires blocked or unsupported evidence", path="result.status")
    if status == "error" and "error" not in evidence_statuses:
        raise ValidationPlanError("error requires an error evidence record", path="result.status")


def _pick(raw: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    present = [key for key in keys if key in raw]
    if len(present) > 1:
        first = raw[present[0]]
        if any(raw[key] != first for key in present[1:]):
            raise ValidationPlanError(f"conflicting aliases: {', '.join(present)}")
    return raw[present[0]] if present else default


def _reject_unknown_keys(raw: Mapping[str, Any], allowed: set[str], *, path: str) -> None:
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        raise ValidationPlanError(f"unknown fields: {', '.join(unknown)}", path=path)


def _normalize_identifier(value: Any, *, path: str) -> str:
    text = _required_text(value, path=path, maximum=128)
    if not _IDENTIFIER_RE.fullmatch(text):
        raise ValidationPlanError("must use only letters, numbers, dot, underscore, colon, or hyphen", path=path)
    return text


def _required_text(value: Any, *, path: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValidationPlanError("must be a string", path=path)
    text = value.strip()
    if not text:
        raise ValidationPlanError("must not be empty", path=path)
    if len(text) > maximum or "\0" in text:
        raise ValidationPlanError(f"must contain at most {maximum} safe characters", path=path)
    return text


def _optional_text(value: Any, *, path: str, maximum: int) -> str:
    if value == "":
        return ""
    return _required_text(value, path=path, maximum=maximum)


def _bounded_int(value: Any, *, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValidationPlanError("must be an integer", path=path)
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValidationPlanError(f"must be an integer between {minimum} and {maximum}", path=path)
    return value


def _json_size(value: JsonValue) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _copy_json(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {key: _copy_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_json(item) for item in value]
    return value


__all__ = [
    "ACTION_TYPES",
    "CLEANUP_STRATEGIES",
    "HTTP_METHODS",
    "MAX_BODY_BYTES",
    "MAX_HEADERS",
    "MAX_STEPS",
    "PLAN_VERSION",
    "STEP_TYPES",
    "CleanupPolicy",
    "DeclarativeValidationPlan",
    "EvidenceRecord",
    "StepEvidence",
    "ValidationEvidenceResult",
    "ValidationPlan",
    "ValidationPlanError",
    "ValidationResult",
    "ValidationStep",
    "normalize_plan",
    "normalize_validation_plan",
    "validate_plan",
    "validate_validation_plan",
]
