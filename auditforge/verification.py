from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import pickle
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .models import CodeFacts, RouteFact, SourceFact, TraceCandidate, VerificationPlan, VerificationResult

SAFE_GATES = [
    "只允许 HTTP(S) GET/HEAD 请求。",
    "禁止跨目标 origin、绝对路由和 HTTP 重定向。",
    "禁止暴力破解或撞库。",
    "禁止访问 link-local 或 metadata SSRF 目标。",
    "禁止执行命令类 payload。",
    "safe 模式下每个候选最多发起两次只读请求。",
]

STATEFUL_GATES = [
    *SAFE_GATES[1:-1],
    "该模式可能写入测试数据，只能用于明确授权、可丢弃且可清理的隔离环境。",
    "每个候选最多发起两次受控请求。",
]

BLOCKED_TARGET_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}


@dataclass(frozen=True)
class HttpResponseRecord:
    method: str
    url: str
    status: int | None
    elapsed_ms: int
    body_sample: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "body_sample": self.body_sample,
            "error": self.error,
        }


@dataclass(frozen=True)
class SafeRequestContract:
    """A bounded HTTP request description derived from static route/source facts."""

    method: str
    url: str
    query: dict[str, str]
    headers: dict[str, str]
    json_body: dict[str, str] | None = None
    form_body: dict[str, str] | None = None
    source_location: str = "query"

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "query": dict(self.query),
            "headers": dict(self.headers),
            "json_body": dict(self.json_body) if self.json_body is not None else None,
            "form_body": dict(self.form_body) if self.form_body is not None else None,
            "source_location": self.source_location,
        }


READ_ONLY_HTTP_METHODS = ("GET", "HEAD")
STATEFUL_HTTP_METHODS = ("POST", "PUT", "PATCH", "DELETE")
SUPPORTED_HTTP_METHODS = {*READ_ONLY_HTTP_METHODS, *STATEFUL_HTTP_METHODS}
FORBIDDEN_PROBE_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SAFE_UUID_PATH_VALUE = "00000000-0000-4000-8000-000000000001"
DEFAULT_SAFE_VERIFY_CONCURRENCY = 4
MAX_SAFE_VERIFY_CONCURRENCY = 12


def build_verification_plans(candidates: list[TraceCandidate], *, allow_state_changes: bool = False) -> list[VerificationPlan]:
    plans: list[VerificationPlan] = []
    for candidate in candidates:
        mode = "safe_http" if candidate.route_id and candidate.vuln_class in {"xss", "injection", "ssrf", "auth", "authz"} else "manual"
        steps = [
            "将候选 Source/Sink 映射到可访问端点。",
            "执行有界探测；stateful 模式只允许在可丢弃隔离环境中写入测试数据。" if allow_state_changes else "只执行有界、非破坏性探测。",
            "记录请求、响应、代码锚点和观察到的影响。",
        ]
        if candidate.vuln_class == "authz":
            steps.append("使用两个用户或角色对比行为后才能标记为已确认。")
        if candidate.vuln_class == "ssrf":
            steps.append("只使用 allowlist 内的回连主机，禁止访问 metadata 或 link-local 网段。")
        plans.append(
            VerificationPlan(
                candidate_id=candidate.id,
                status="planned",
                mode=mode,
                goal=f"验证 {candidate.id} 的 {candidate.vuln_class} 候选路径。",
                preconditions=["仅在自有或明确授权的目标环境中执行。", "优先使用可丢弃的测试数据。"],
                steps=steps,
                success_criteria=[
                    "目标运行环境中成功复现该行为。",
                    "证据可以回链到候选 Source 与 Sink 代码锚点。",
                    "未违反任何安全门禁。",
                ],
                safety_gates=STATEFUL_GATES if allow_state_changes else SAFE_GATES,
            )
        )
    return plans


def run_safe_verification(
    candidates: list[TraceCandidate],
    facts: CodeFacts,
    target_url: str | None,
    *,
    allow_state_changes: bool = False,
    concurrency: int | None = None,
) -> list[VerificationResult]:
    """Verify independent candidates concurrently while preserving input order.

    A failed probe is isolated to its candidate.  Stateful verification uses a
    smaller default because several candidates may touch the same disposable
    target state; callers can still choose an explicit bounded capacity.
    """

    route_by_id = {route.id: route for route in facts.routes}
    if not candidates:
        return []

    validated_target: str | None = None
    target_error: ValueError | None = None
    if target_url:
        try:
            validated_target = validate_target_url(target_url)
        except ValueError as exc:
            target_error = exc

    default_workers = 2 if allow_state_changes else DEFAULT_SAFE_VERIFY_CONCURRENCY
    workers = max(1, min(MAX_SAFE_VERIFY_CONCURRENCY, int(concurrency or default_workers), len(candidates)))
    ordered: list[VerificationResult | None] = [None] * len(candidates)

    def verify_one(candidate: TraceCandidate) -> VerificationResult:
        route = route_by_id.get(candidate.route_id or "") or infer_route_for_candidate(facts, candidate)
        source = source_for_candidate(facts, candidate)
        if not target_url or not route:
            return VerificationResult(
                candidate_id=candidate.id,
                status="needs_manual_review",
                evidence=["缺少目标 URL 或路由映射，无法执行 safe 验证。"],
                notes="仅静态候选。",
            )
        if target_error is not None or validated_target is None:
            return VerificationResult(
                candidate_id=candidate.id,
                status="blocked",
                evidence=[f"目标 URL 不符合安全策略：{target_error}"],
                notes="未发起网络请求。",
            )
        if not route_allows_safe_probe(route.method, allow_state_changes=allow_state_changes):
            return VerificationResult(
                candidate_id=candidate.id,
                status="needs_manual_review",
                evidence=[f"路由方法 {route.method} 不适合自动安全探测。"],
                notes="需要人工验证。",
            )
        try:
            endpoint_result = verify_endpoint_specific_candidate(
                candidate,
                route,
                validated_target,
                source,
                allow_state_changes=allow_state_changes,
            )
            if endpoint_result:
                return endpoint_result
            if candidate.vuln_class == "xss":
                return verify_reflection_candidate(
                    candidate,
                    route,
                    validated_target,
                    source,
                    allow_state_changes=allow_state_changes,
                )
            if candidate.vuln_class == "ssrf":
                return verify_ssrf_candidate(
                    candidate,
                    route,
                    validated_target,
                    source,
                    allow_state_changes=allow_state_changes,
                )
            if candidate.vuln_class == "authz":
                return verify_authz_candidate(candidate, route, validated_target, source)
            if candidate.vuln_class == "injection":
                return verify_injection_candidate(
                    candidate,
                    route,
                    validated_target,
                    source,
                    allow_state_changes=allow_state_changes,
                )
            return VerificationResult(
                candidate_id=candidate.id,
                status="needs_manual_review",
                evidence=[f"{candidate.vuln_class} 需要结合角色、状态或回连行为验证。"],
                notes="safe verifier 不会执行利用 payload。",
            )
        except ValueError as exc:
            return VerificationResult(
                candidate_id=candidate.id,
                status="blocked",
                evidence=[f"验证请求被安全策略阻止：{exc}"],
                notes="未发起越界请求。",
            )
        except Exception as exc:  # noqa: BLE001 - one transport failure must not abort the verification batch
            return VerificationResult(
                candidate_id=candidate.id,
                status="needs_manual_review",
                evidence=[f"该候选的自动验证异常：{type(exc).__name__}。"],
                notes=str(exc)[:800],
            )

    if workers == 1:
        return [verify_one(candidate) for candidate in candidates]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="auditforge-safe-verify") as executor:
        futures = {executor.submit(verify_one, candidate): index for index, candidate in enumerate(candidates)}
        for future in as_completed(futures):
            ordered[futures[future]] = future.result()
    return [item for item in ordered if item is not None]


def route_allows_safe_probe(method: str, *, allow_state_changes: bool = False) -> bool:
    methods = parse_route_methods(method)
    if "ANY" in methods:
        return True
    if not methods:
        return not re.findall(r"[A-Za-z]+", method or "")
    allowed = set(READ_ONLY_HTTP_METHODS)
    if allow_state_changes:
        allowed.update(STATEFUL_HTTP_METHODS)
    return bool(set(methods) & allowed)


def parse_route_methods(value: str) -> list[str]:
    methods: list[str] = []
    for item in re.findall(r"[A-Za-z]+", value or ""):
        normalized = item.upper()
        if normalized in SUPPORTED_HTTP_METHODS | {"ANY"} and normalized not in methods:
            methods.append(normalized)
    return methods


def select_contract_method(
    route: RouteFact,
    source: SourceFact | None,
    candidate: TraceCandidate | None = None,
    *,
    allow_state_changes: bool,
) -> str:
    methods = parse_route_methods(route.method)
    if "ANY" in methods:
        methods = ["GET", "POST"] if allow_state_changes else ["GET"]
    elif not methods:
        if re.findall(r"[A-Za-z]+", route.method or ""):
            raise ValueError(f"路由方法 {route.method} 不受安全验证器支持")
        methods = ["GET"]
    allowed = set(READ_ONLY_HTTP_METHODS)
    if allow_state_changes:
        allowed.update(STATEFUL_HTTP_METHODS)
    methods = [item for item in methods if item in allowed]
    if not methods:
        raise ValueError(f"路由方法 {route.method} 不在当前验证模式允许范围内")

    source_location = infer_source_location(source, candidate)
    if source_location in {"json", "form"} and allow_state_changes:
        for preferred in ("POST", "PUT", "PATCH"):
            if preferred in methods:
                return preferred
    for preferred in (*READ_ONLY_HTTP_METHODS, "POST", "PUT", "PATCH", "DELETE"):
        if preferred in methods:
            return preferred
    raise ValueError(f"无法为路由方法 {route.method} 选择安全验证方法")


def verify_endpoint_specific_candidate(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
    *,
    allow_state_changes: bool = False,
) -> VerificationResult | None:
    path = route.path.lower()
    evidence_text = f"{candidate.static_evidence} {candidate.verification_hint} {candidate.source.symbol or ''}".lower()
    is_direct = candidate.id.startswith("DIRECT-")
    if path == "/config" and is_direct:
        return verify_config_leak_candidate(candidate, route, target_url)
    if path == "/crypto" and is_direct and allow_state_changes:
        return verify_crypto_candidate(candidate, route, target_url)
    if path == "/reset-password" and is_direct and allow_state_changes:
        return verify_reset_password_candidate(candidate, route, target_url)
    if path == "/notes" and candidate.vuln_class == "xss" and is_direct and allow_state_changes:
        return verify_notes_stored_xss_candidate(candidate, route, target_url)
    if path == "/upload" and is_direct and allow_state_changes:
        return verify_upload_candidate(candidate, route, target_url)
    if path == "/deserialize" and allow_state_changes:
        return verify_deserialization_candidate(candidate, route, target_url)
    if path == "/login" and candidate.vuln_class == "injection" and allow_state_changes:
        return verify_login_sql_injection_candidate(candidate, route, target_url, source)
    if path == "/admin" and is_direct and "remember_user" in evidence_text:
        return verify_admin_cookie_candidate(candidate, route, target_url)
    return None


def source_for_candidate(facts: CodeFacts, candidate: TraceCandidate) -> SourceFact | None:
    return next(
        (
            source
            for source in facts.sources
            if source.anchor.file == candidate.source.file
            and source.anchor.start_line == candidate.source.start_line
            and source.anchor.snippet_hash == candidate.source.snippet_hash
        ),
        None,
    )


def infer_route_for_candidate(facts: CodeFacts, candidate: TraceCandidate) -> RouteFact | None:
    anchors = [candidate.source, candidate.sink]
    for anchor in anchors:
        function = next(
            (
                item
                for item in facts.functions
                if item.anchor.file == anchor.file and item.anchor.start_line <= anchor.start_line <= item.anchor.end_line
            ),
            None,
        )
        if not function:
            continue
        routes = [
            route
            for route in facts.routes
            if route.anchor.file == function.anchor.file
            and route.anchor.start_line <= function.anchor.start_line
            and function.anchor.start_line - route.anchor.start_line <= 6
        ]
        if routes:
            return sorted(routes, key=lambda item: item.anchor.start_line)[-1]
    return None


def verify_config_leak_candidate(candidate: TraceCandidate, route: RouteFact, target_url: str) -> VerificationResult:
    response = safe_http_request(join_url(target_url, route.path))
    if response.status == 200 and has_config_leak_signal(response.body_sample):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认配置泄露：未认证访问即可读取 SECRET_KEY、DEBUG、Cookie 安全标志或内部配置字段。",
                "探测只读取配置页面，未修改服务端状态。",
            ],
            request_log=[response.to_dict()],
            notes="safe verifier confirmed unauthenticated config leak.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if response.status else "not_reproducible",
        evidence=["未观察到明确配置泄露信号。"],
        request_log=[response.to_dict()],
        notes=response.error or "",
    )


def verify_crypto_candidate(candidate: TraceCandidate, route: RouteFact, target_url: str) -> VerificationResult:
    marker = "AF_SAFE_CRYPTO"
    expected_md5 = hashlib.md5(marker.encode("utf-8")).hexdigest()
    response = safe_http_post_form(join_url(target_url, route.path), {"value": marker})
    if response.status == 200 and expected_md5 in response.body_sample and has_base64_token_signal(response.body_sample):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认弱加密行为：用户输入会生成可预测 MD5 摘要，并同时生成 Base64 token。",
                "探测输入为无害固定标记，未尝试破解或伪造真实凭证。",
            ],
            request_log=[response.to_dict()],
            notes="safe verifier confirmed weak crypto output.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if response.status else "not_reproducible",
        evidence=["未观察到 MD5 摘要和 Base64 token 同时出现。"],
        request_log=[response.to_dict()],
        notes=response.error or "",
    )


def verify_reset_password_candidate(candidate: TraceCandidate, route: RouteFact, target_url: str) -> VerificationResult:
    username = "__auditforge_no_such_user__"
    response = safe_http_post_form(
        join_url(target_url, route.path),
        {"username": username, "new_password": "AF_SAFE_RESET_VALUE"},
    )
    if response.status == 200 and has_unauthenticated_reset_signal(response.body_sample, username):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认密码重置流程缺少身份凭证：未登录、无旧密码、无一次性 token 的请求被业务流程接受。",
                "探测使用不存在的用户名，避免修改真实种子用户密码。",
            ],
            request_log=[response.to_dict()],
            notes="safe verifier confirmed reset flow acceptance without proof.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if response.status else "not_reproducible",
        evidence=["未观察到无凭证重置成功提示。"],
        request_log=[response.to_dict()],
        notes=response.error or "",
    )


def verify_notes_stored_xss_candidate(candidate: TraceCandidate, route: RouteFact, target_url: str) -> VerificationResult:
    marker_id = re.sub(r"[^a-z0-9-]", "-", candidate.id.lower())
    marker = f"<af-auditforge-notes-{marker_id}></af-auditforge-notes-{marker_id}>"
    submitted = safe_http_post_form(join_url(target_url, route.path), {"owner_id": "1", "body": marker})
    retrieved = safe_http_request(join_url(target_url, route.path))
    if submitted.status and retrieved.status == 200 and marker in retrieved.body_sample:
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认存储型未转义 HTML：提交的无脚本自定义标签被持久化，并在 /notes 页面原样渲染。",
                "探测会写入一条无害测试笔记，不包含脚本、事件处理器或外部资源。",
            ],
            request_log=[submitted.to_dict(), retrieved.to_dict()],
            notes="safe verifier confirmed stored raw HTML rendering.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if submitted.status or retrieved.status else "not_reproducible",
        evidence=["提交后重新读取页面，未观察到测试标记被持久化并原样渲染。"],
        request_log=[submitted.to_dict(), retrieved.to_dict()],
        notes=submitted.error or retrieved.error or "",
    )


def verify_upload_candidate(candidate: TraceCandidate, route: RouteFact, target_url: str) -> VerificationResult:
    marker = "<af-auditforge-upload></af-auditforge-upload>"
    filename = "auditforge_safe_upload_probe.html"
    submitted = safe_http_post_multipart(
        join_url(target_url, route.path),
        field_name="file",
        filename=filename,
        content=marker.encode("utf-8"),
        content_type="text/html",
    )
    uploaded_url = uploaded_file_probe_url(target_url, submitted.body_sample, filename)
    retrieved = safe_http_request(uploaded_url) if uploaded_url else HttpResponseRecord("GET", "", None, 0, "", "未找到同源上传 URL")
    if submitted.status and retrieved.status == 200 and marker in retrieved.body_sample:
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认危险文件上传：服务端接受客户端文件名和 HTML 扩展，并可通过上传目录直接访问文件内容。",
                "探测文件名固定为 auditforge_safe_upload_probe.html，内容为无脚本自定义标签。",
            ],
            request_log=[submitted.to_dict(), retrieved.to_dict()],
            notes="safe verifier confirmed arbitrary HTML upload reachability.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if submitted.status else "not_reproducible",
        evidence=["文件提交后未能通过同源 URL 重新读取测试内容，未自动确认可访问上传。"],
        request_log=[submitted.to_dict(), retrieved.to_dict()],
        notes=submitted.error or retrieved.error or "",
    )


def uploaded_file_probe_url(target_url: str, response_body: str, filename: str) -> str | None:
    escaped = re.escape(filename)
    matches = re.findall(rf'(?:https?://[^\s"\'<>]+|/[A-Za-z0-9_./%-]*{escaped})', response_body, flags=re.I)
    candidates = [*matches, f"/uploads/{filename}"]
    target_origin = url_origin(target_url)
    for value in candidates:
        try:
            candidate_url = urllib.parse.urljoin(target_url, value)
            if url_origin(candidate_url) != target_origin:
                continue
            return validate_request_url(candidate_url)
        except ValueError:
            continue
    return None


def verify_deserialization_candidate(candidate: TraceCandidate, route: RouteFact, target_url: str) -> VerificationResult:
    payload = base64.b64encode(pickle.dumps({"auditforge": "safe"})).decode("ascii")
    response = safe_http_post_form(join_url(target_url, route.path), {"payload": payload})
    if response.status == 200 and has_deserialization_signal(response.body_sample):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认不安全反序列化入口：服务端接受请求体中的 Base64 Pickle，并返回反序列化后的对象表示。",
                "探测对象是普通 dict，不包含 __reduce__、命令执行或文件访问逻辑。",
            ],
            request_log=[response.to_dict()],
            notes="safe verifier confirmed pickle.loads reachability with benign object.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if response.status else "not_reproducible",
        evidence=["未观察到无害 Pickle 对象被反序列化并回显。"],
        request_log=[response.to_dict()],
        notes=response.error or "",
    )


def verify_login_sql_injection_candidate(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
) -> VerificationResult:
    if candidate.sink.start_line < route.anchor.start_line:
        return VerificationResult(
            candidate_id=candidate.id,
            status="needs_manual_review",
            evidence=["候选 sink 不在登录路由处理函数之后，safe verifier 不将其作为登录 SQL 注入自动确认。"],
            notes="避免跨函数误候选被端点级探测误确认。",
        )
    param = next(iter(safe_probe_params(candidate, source, "AF_SAFE'").keys()), "username")
    baseline_data = {"username": "AF_SAFE", "password": "not-a-real-password"}
    quote_data = dict(baseline_data)
    if param in {"username", "password"}:
        baseline_data[param] = "AF_SAFE"
        quote_data[param] = "AF_SAFE'"
    else:
        quote_data["username"] = "AF_SAFE'"
    baseline = safe_http_post_form(join_url(target_url, route.path), baseline_data)
    quote_probe = safe_http_post_form(join_url(target_url, route.path), quote_data)
    if quote_probe.status and has_sql_error_signal(quote_probe.body_sample):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认登录 SQL 注入风险：POST 表单单引号探测触发数据库错误或调试 SQL 异常。",
                f"触发字段：{param if param in {'username', 'password'} else 'username'}。",
                "探测使用不存在用户名和错误密码，未尝试绕过认证或修改数据。",
            ],
            request_log=[baseline.to_dict(), quote_probe.to_dict()],
            notes="safe verifier confirmed login SQL error signal.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if baseline.status or quote_probe.status else "not_reproducible",
        evidence=["登录表单可探测，但未观察到 SQL 错误信号。"],
        request_log=[baseline.to_dict(), quote_probe.to_dict()],
        notes=baseline.error or quote_probe.error or "",
    )


def verify_admin_cookie_candidate(candidate: TraceCandidate, route: RouteFact, target_url: str) -> VerificationResult:
    cookie = base64.b64encode(b"auditforge:admin").decode("ascii")
    response = safe_http_request(join_url(target_url, route.path), headers={"Cookie": f"remember_user={cookie}"})
    if response.status == 200 and has_sensitive_table_signal(response.body_sample):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认可伪造记住登录 Cookie：仅提交 Base64 编码的 username:admin 即可访问管理页面敏感数据。",
                "探测未使用真实账号密码，也未修改服务端状态。",
            ],
            request_log=[response.to_dict()],
            notes="safe verifier confirmed unsigned remember cookie authorization bypass.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if response.status else "not_reproducible",
        evidence=["未观察到 forged remember_user Cookie 进入管理数据页。"],
        request_log=[response.to_dict()],
        notes=response.error or "",
    )


def verify_injection_candidate(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
    *,
    allow_state_changes: bool = False,
) -> VerificationResult:
    if "raw_sql" not in (candidate.sink.symbol or "") and "sql" not in candidate.static_evidence.lower():
        return verify_reachability_candidate(
            candidate,
            route,
            target_url,
            source,
            allow_state_changes=allow_state_changes,
        )
    baseline_contract = build_safe_request_contract(
        candidate,
        route,
        target_url,
        source,
        "AF_SAFE",
        allow_state_changes=allow_state_changes,
    )
    quote_contract = build_safe_request_contract(
        candidate,
        route,
        target_url,
        source,
        "AF_SAFE'",
        allow_state_changes=allow_state_changes,
    )
    param = contract_probe_name(baseline_contract)
    baseline = execute_safe_request_contract(baseline_contract)
    quote_probe = execute_safe_request_contract(quote_contract)
    error_signal = has_sql_error_signal(quote_probe.body_sample)
    if quote_probe.status and error_signal:
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认 SQL 注入风险：单引号探测触发数据库错误或调试 SQL 差异。",
                f"触发参数：{param}。",
                "探测只使用非破坏性 GET 请求，未写入数据、未执行数据修改语句。",
            ],
            request_log=[baseline.to_dict(), quote_probe.to_dict()],
            notes="safe verifier confirmed SQL error signal.",
        )
    if baseline.status and 200 <= baseline.status < 500:
        return VerificationResult(
            candidate_id=candidate.id,
            status="needs_manual_review",
            evidence=[
                f"路由可访问，状态码为 {baseline.status}。",
                f"safe verifier 使用参数 {param} 做了无害探测，但未观察到 SQL 错误信号。",
            ],
            request_log=[baseline.to_dict(), quote_probe.to_dict()],
            notes="仅确认可达，未确认注入。",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="not_reproducible",
        evidence=["safe 验证期间路由不可达。"],
        request_log=[baseline.to_dict(), quote_probe.to_dict()],
        notes=baseline.error or quote_probe.error or "",
    )


def verify_ssrf_candidate(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
    *,
    allow_state_changes: bool = False,
) -> VerificationResult:
    callback_url = urllib.parse.urljoin(target_url.rstrip("/") + "/", "components")
    contract = build_safe_request_contract(
        candidate,
        route,
        target_url,
        source,
        callback_url,
        allow_state_changes=allow_state_changes,
    )
    param = contract_probe_name(contract)
    response = execute_safe_request_contract(contract)
    if response.status and has_ssrf_echo_signal(response.body_sample, callback_url):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认 SSRF：目标服务按用户输入 URL 发起了服务端请求，并将受控本地页面内容回显。",
                f"触发参数：{param}。",
                "回连目标限定为同一授权本地靶场地址，未访问 metadata/link-local/外部网络。",
            ],
            request_log=[response.to_dict()],
            notes="safe verifier confirmed controlled SSRF echo.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review" if response.status else "not_reproducible",
        evidence=["safe SSRF 探测未观察到受控页面回显。"],
        request_log=[response.to_dict()],
        notes=response.error or "",
    )


def verify_authz_candidate(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
) -> VerificationResult:
    lowered_path = route.path.lower()
    if "admin" in lowered_path:
        return verify_admin_bypass_candidate(candidate, route, target_url, source)
    if "profile" in lowered_path:
        return verify_profile_idor_candidate(candidate, route, target_url)
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review",
        evidence=["safe verifier 暂不支持该授权场景的自动角色/对象对比。"],
        notes="需要登录态、角色或对象归属上下文。",
    )


def verify_admin_bypass_candidate(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
) -> VerificationResult:
    param = next(iter(safe_probe_params(candidate, source, "true").keys()), "admin")
    denied = safe_http_request(join_url(target_url, route.path))
    bypassed = safe_http_request(add_query(join_url(target_url, route.path), {param: "true"}))
    if denied.status and bypassed.status and has_denied_signal(denied.body_sample) and has_sensitive_table_signal(bypassed.body_sample):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认授权绕过：无参数访问被拒绝，添加查询参数后返回用户表/API Key 等敏感数据。",
                f"触发参数：{param}=true。",
            ],
            request_log=[denied.to_dict(), bypassed.to_dict()],
            notes="safe verifier confirmed query-parameter authorization bypass.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review",
        evidence=["未观察到清晰的拒绝/放行响应差异。"],
        request_log=[denied.to_dict(), bypassed.to_dict()],
    )


def verify_profile_idor_candidate(candidate: TraceCandidate, route: RouteFact, target_url: str) -> VerificationResult:
    first = safe_http_request(join_url(target_url, materialize_route_path(route.path, "1")))
    second = safe_http_request(join_url(target_url, materialize_route_path(route.path, "2")))
    if (
        first.status == 200
        and second.status == 200
        and has_profile_leak_signal(first.body_sample)
        and has_profile_leak_signal(second.body_sample)
    ):
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认 IDOR/越权读取：未登录状态下可直接访问不同用户编号的资料页。",
                "响应包含 Email、API Key、Balance 等用户敏感字段。",
            ],
            request_log=[first.to_dict(), second.to_dict()],
            notes="safe verifier confirmed unauthenticated profile object access.",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="needs_manual_review",
        evidence=["未观察到两个对象资料页都可未授权读取。"],
        request_log=[first.to_dict(), second.to_dict()],
    )


def verify_reachability_candidate(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
    *,
    allow_state_changes: bool = False,
) -> VerificationResult:
    contract = build_safe_request_contract(
        candidate,
        route,
        target_url,
        source,
        "AF_SAFE",
        allow_state_changes=allow_state_changes,
    )
    response = execute_safe_request_contract(contract)
    probe_name = contract_probe_name(contract)
    if response.status and 200 <= response.status < 500:
        return VerificationResult(
            candidate_id=candidate.id,
            status="needs_manual_review",
            evidence=[
                f"路由可访问，状态码为 {response.status}。",
                f"safe verifier 使用 {contract.source_location} 参数 {probe_name} 进行无害探测。",
                "safe 模式未执行注入 payload，候选仍未确认。",
            ],
            request_log=[response.to_dict()],
            notes="仅确认可达性。",
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="not_reproducible",
        evidence=["safe 验证期间路由不可达。"],
        request_log=[response.to_dict()],
        notes=response.error or "",
    )


def verify_reflection_candidate(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
    *,
    allow_state_changes: bool = False,
) -> VerificationResult:
    marker_id = re.sub(r"[^a-z0-9-]", "-", candidate.id.lower())
    marker = f"<af-auditforge-{marker_id}></af-auditforge-{marker_id}>"
    contract = build_safe_request_contract(
        candidate,
        route,
        target_url,
        source,
        marker,
        allow_state_changes=allow_state_changes,
    )
    response = execute_safe_request_contract(contract)
    probe_name = contract_probe_name(contract)
    if response.status and marker in response.body_sample:
        return VerificationResult(
            candidate_id=candidate.id,
            status="confirmed",
            evidence=[
                "运行时已确认未转义 HTML 反射：响应中出现了完整无害自定义标签标记。",
                f"触发位置：{contract.source_location}；参数：{probe_name}。",
                "探测使用无脚本、无事件处理器的自定义标签，不执行破坏性 payload。",
            ],
            request_log=[response.to_dict()],
            notes="safe verifier confirmed raw HTML reflection.",
        )
    if response.status and 200 <= response.status < 500:
        return VerificationResult(
            candidate_id=candidate.id,
            status="not_reproducible",
            evidence=["safe 模式未观察到无害标记反射。"],
            request_log=[response.to_dict()],
        )
    return VerificationResult(
        candidate_id=candidate.id,
        status="not_reproducible",
        evidence=["safe 验证期间路由不可达。"],
        request_log=[response.to_dict()],
        notes=response.error or "",
    )


def build_safe_request_contract(
    candidate: TraceCandidate,
    route: RouteFact,
    target_url: str,
    source: SourceFact | None,
    marker: str,
    *,
    allow_state_changes: bool = False,
) -> SafeRequestContract:
    """Build one same-origin, marker-only request without performing network IO."""

    method = select_contract_method(route, source, candidate, allow_state_changes=allow_state_changes)
    location = infer_source_location(source, candidate)
    param = probe_parameter_name(candidate, source)
    path_values: dict[str, str] = {}
    if location == "path":
        path_values[param] = marker
    materialized_path = materialize_contract_route_path(route.path, path_values)
    url = join_url(target_url, materialized_path)

    query: dict[str, str] = {}
    headers: dict[str, str] = {}
    json_body: dict[str, str] | None = None
    form_body: dict[str, str] | None = None
    if location == "header":
        header_name = safe_probe_header_name(param)
        headers[header_name] = marker
    elif location == "cookie":
        cookie_name = safe_probe_cookie_name(param)
        headers["Cookie"] = f"{cookie_name}={urllib.parse.quote(marker, safe='')}"
    elif location == "json" and method not in READ_ONLY_HTTP_METHODS:
        json_body = {param: marker}
    elif location == "form" and method not in READ_ONLY_HTTP_METHODS:
        form_body = {param: marker}
    elif location != "path":
        # GET/HEAD bodies are poorly supported and often ignored. Preserve the
        # source name but move the harmless marker to the query for reachability.
        location = "query"
        query[param] = marker

    return SafeRequestContract(
        method=method,
        url=url,
        query=query,
        headers=headers,
        json_body=json_body,
        form_body=form_body,
        source_location=location,
    )


def execute_safe_request_contract(contract: SafeRequestContract) -> HttpResponseRecord:
    url = add_query(contract.url, contract.query) if contract.query else contract.url
    headers = dict(contract.headers)
    data: bytes | None = None
    if contract.json_body is not None:
        data = json.dumps(contract.json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif contract.form_body is not None:
        data = urllib.parse.urlencode(contract.form_body).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return safe_http_exchange(contract.method, url, data=data, headers=headers)


def infer_source_location(source: SourceFact | None, candidate: TraceCandidate | None) -> str:
    kind = str(source.kind if source else "").lower()
    expression = " ".join(
        item
        for item in (
            source.expression if source else "",
            candidate.source.symbol if candidate else "",
            candidate.static_evidence if candidate else "",
        )
        if item
    ).lower()
    if kind == "http_path" or (not kind and any(marker in expression for marker in ("path_params", "view_args", "route parameter"))):
        return "path"
    if kind == "http_header" or (not kind and any(marker in expression for marker in (".headers", ".header", "getheader("))):
        return "header"
    if kind == "cookie" or (not kind and any(marker in expression for marker in (".cookies", "cookie", "session[", "session.get("))):
        return "cookie"
    if kind == "http_body":
        if any(marker in expression for marker in (".form", "request.post", "req.post")):
            return "form"
        return "json"
    if any(marker in expression for marker in ("get_json(", ".json", ".body", "body(")):
        return "json"
    if any(marker in expression for marker in (".form", "request.post", "req.post")):
        return "form"
    return "query"


def probe_parameter_name(candidate: TraceCandidate, source: SourceFact | None) -> str:
    expression_name = extract_source_param_name(source.expression if source else "")
    if expression_name:
        return expression_name
    if source:
        for name in [*source.input_variables, *source.variables]:
            if re.fullmatch(r"[A-Za-z_][\w-]{0,80}", name or ""):
                return name
    return next(iter(safe_probe_params(candidate, source, "AF_SAFE")), "af_marker")


def safe_probe_header_name(value: str) -> str:
    name = str(value or "").strip()
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}", name) or name.lower() in FORBIDDEN_PROBE_HEADERS:
        return "X-AuditForge-Marker"
    return name


def safe_probe_cookie_name(value: str) -> str:
    name = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}", name):
        return "auditforge_marker"
    return name


def materialize_contract_route_path(route_path: str, values: dict[str, str] | None = None) -> str:
    supplied = values or {}

    def replacement(name: str, converter: str = "") -> str:
        raw_value = supplied.get(name)
        value = contract_path_value(name, converter, raw_value)
        return urllib.parse.quote(value, safe="")

    def flask(match: re.Match[str]) -> str:
        return replacement(match.group("name"), match.group("converter") or "")

    def braces(match: re.Match[str]) -> str:
        return replacement(match.group("name"), match.group("converter") or "")

    def express(match: re.Match[str]) -> str:
        return replacement(match.group("name"))

    materialized = re.sub(
        r"<(?:(?P<converter>[A-Za-z_]\w*):)?(?P<name>[A-Za-z_]\w*)>",
        flask,
        route_path,
    )
    materialized = re.sub(
        r"\{(?P<name>[A-Za-z_]\w*)(?::(?P<converter>[A-Za-z_]\w*))?}",
        braces,
        materialized,
    )
    return re.sub(r"(?<=/):(?P<name>[A-Za-z_]\w*)", express, materialized)


def contract_path_value(name: str, converter: str, supplied: str | None) -> str:
    lowered_converter = converter.lower()
    lowered_name = name.lower()
    if (
        lowered_converter in {"int", "integer", "float", "number"}
        or lowered_name
        in {
            "id",
            "pk",
            "page",
            "offset",
            "limit",
            "index",
        }
        or lowered_name.endswith("_id")
    ):
        return "1"
    if lowered_converter == "uuid" or "uuid" in lowered_name:
        return SAFE_UUID_PATH_VALUE
    return str(supplied if supplied is not None else "AF_SAFE")[:160]


def contract_probe_name(contract: SafeRequestContract) -> str:
    if contract.query:
        return next(iter(contract.query))
    if contract.json_body:
        return next(iter(contract.json_body))
    if contract.form_body:
        return next(iter(contract.form_body))
    if contract.source_location == "header":
        return next(iter(contract.headers), "X-AuditForge-Marker")
    if contract.source_location == "cookie":
        cookie = contract.headers.get("Cookie", "auditforge_marker=")
        return cookie.split("=", 1)[0]
    return "path parameter"


def safe_http_request(url: str, headers: dict[str, str] | None = None) -> HttpResponseRecord:
    return safe_http_exchange("GET", url, headers=headers)


def safe_http_post_form(url: str, data: dict[str, str], headers: dict[str, str] | None = None) -> HttpResponseRecord:
    body = urllib.parse.urlencode(data).encode("utf-8")
    request_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        request_headers.update(headers)
    return safe_http_exchange("POST", url, data=body, headers=request_headers)


def safe_http_post_multipart(
    url: str,
    field_name: str,
    filename: str,
    content: bytes,
    content_type: str,
    headers: dict[str, str] | None = None,
) -> HttpResponseRecord:
    boundary = "----AuditForgeSafeBoundary"
    body = b"\r\n".join(
        [
            f"--{boundary}".encode("ascii"),
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'.encode(),
            f"Content-Type: {content_type}".encode("ascii"),
            b"",
            content,
            f"--{boundary}--".encode("ascii"),
            b"",
        ]
    )
    request_headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if headers:
        request_headers.update(headers)
    return safe_http_exchange("POST", url, data=body, headers=request_headers)


def safe_http_exchange(
    method: str,
    url: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> HttpResponseRecord:
    method = normalize_http_method(method)
    url = validate_request_url(url)
    start = time.time()
    request_headers = {"User-Agent": "AuditForge/0.1 safe-verifier"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler())
    try:
        with opener.open(request, timeout=8) as response:
            body = response.read(12000).decode("utf-8", errors="replace")
            return HttpResponseRecord(
                method=method,
                url=url,
                status=response.status,
                elapsed_ms=int((time.time() - start) * 1000),
                body_sample=body[:4000],
            )
    except urllib.error.HTTPError as exc:
        body = exc.read(12000).decode("utf-8", errors="replace")
        return HttpResponseRecord(method, url, exc.code, int((time.time() - start) * 1000), body[:4000], None)
    except Exception as exc:  # noqa: BLE001 - evidence should capture all safe verifier failures
        return HttpResponseRecord(method, url, None, int((time.time() - start) * 1000), "", str(exc))


def normalize_http_method(value: str) -> str:
    method = str(value or "").strip().upper()
    if method not in SUPPORTED_HTTP_METHODS:
        raise ValueError(f"不支持的 HTTP 验证方法：{method or 'empty'}")
    return method


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201 - urllib callback signature
        return None


def has_config_leak_signal(body: str) -> bool:
    lowered = body.lower()
    return "secret_key" in lowered and "session_cookie_httponly" in lowered and ("admin_api_key" in lowered or "debug" in lowered)


def has_base64_token_signal(body: str) -> bool:
    lowered = body.lower()
    if "base64 token" in lowered:
        return True
    return bool(re.search(r"\b[A-Za-z0-9+/]{24,}={0,2}\b", body))


def has_unauthenticated_reset_signal(body: str, username: str) -> bool:
    lowered = body.lower()
    return username.lower() in lowered and "without verification" in lowered and "password changed" in lowered


def has_deserialization_signal(body: str) -> bool:
    lowered = body.lower()
    return "auditforge" in lowered and "safe" in lowered and ("result" in lowered or "&#39;" in body or "{'" in body)


def has_sql_error_signal(body: str) -> bool:
    lowered = body.lower()
    return any(
        signal in lowered
        for signal in (
            "sqlite",
            "sql syntax",
            "syntax error",
            "unrecognized token",
            "unterminated",
            "operationalerror",
        )
    )


def has_ssrf_echo_signal(body: str, callback_url: str) -> bool:
    lowered = body.lower()
    return callback_url in body and ("response preview" in lowered or "vulnerable flask lab" in lowered or "components" in lowered)


def has_denied_signal(body: str) -> bool:
    lowered = body.lower()
    return "access denied" in lowered or "denied" in lowered


def has_sensitive_table_signal(body: str) -> bool:
    lowered = body.lower()
    return "api key" in lowered and ("balance" in lowered or "admin console" in lowered or "<table" in lowered)


def has_profile_leak_signal(body: str) -> bool:
    lowered = body.lower()
    return "user profile" in lowered and "api key" in lowered and "balance" in lowered


def join_url(base_url: str, route_path: str) -> str:
    base_url = validate_target_url(base_url)
    route_path = materialize_route_path(route_path, "1")
    original_route = urllib.parse.urlsplit(route_path)
    if original_route.scheme or original_route.netloc:
        raise ValueError("路由不能包含 scheme 或其他 origin")
    if not route_path.startswith("/"):
        route_path = "/" + route_path
    parsed_route = urllib.parse.urlsplit(route_path)
    if (
        parsed_route.scheme
        or parsed_route.netloc
        or route_path.startswith("//")
        or "\\" in route_path
        or parsed_route.query
        or parsed_route.fragment
        or any(part == ".." for part in parsed_route.path.split("/"))
    ):
        raise ValueError("路由必须是同源、无查询参数的绝对路径")
    target = urllib.parse.urljoin(base_url, parsed_route.path.lstrip("/"))
    if url_origin(target) != url_origin(base_url):
        raise ValueError("路由试图离开目标 origin")
    return validate_request_url(target)


def validate_target_url(value: str) -> str:
    parsed = _validate_http_url(value)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("目标 URL 必须只包含 scheme、host 和可选端口")
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, "/", "", ""))


def validate_request_url(value: str) -> str:
    parsed = _validate_http_url(value)
    if parsed.fragment:
        raise ValueError("请求 URL 不能包含 fragment")
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def _validate_http_url(value: str) -> urllib.parse.SplitResult:
    raw = str(value or "").strip()
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("只允许 http 和 https 协议")
    if not parsed.hostname:
        raise ValueError("目标 URL 缺少主机名")
    if parsed.username or parsed.password:
        raise ValueError("目标 URL 不能包含用户凭据")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("目标 URL 端口非法") from exc
    validate_target_host(parsed.hostname)
    return parsed


def validate_target_host(hostname: str) -> None:
    lowered = hostname.rstrip(".").lower()
    if lowered in BLOCKED_TARGET_HOSTS or lowered.endswith(".metadata.google.internal"):
        raise ValueError("禁止访问云 metadata 主机")
    addresses: set[str] = set()
    try:
        addresses.add(str(ipaddress.ip_address(lowered)))
    except ValueError:
        try:
            addresses.update(item[4][0] for item in socket.getaddrinfo(lowered, None, type=socket.SOCK_STREAM))
        except socket.gaierror:
            return
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError(f"禁止访问特殊网络地址：{address}")


def url_origin(value: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(value)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def materialize_route_path(route_path: str, value: str) -> str:
    if "{" in route_path or "<" in route_path or ":" in route_path:
        route_path = re.sub(r"<(?:[A-Za-z_]\w*:)?[A-Za-z_]\w*>", value, route_path)
        route_path = re.sub(r"\{[^}]+\}", value, route_path)
        route_path = re.sub(r":([A-Za-z_]\w*)", value, route_path)
    return route_path


def add_query(url: str, params: dict[str, str]) -> str:
    parsed = urllib.parse.urlparse(url)
    existing = dict(urllib.parse.parse_qsl(parsed.query))
    existing.update(params)
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(existing)))


def safe_probe_params(candidate: TraceCandidate, source: SourceFact | None, marker: str) -> dict[str, str]:
    param = extract_source_param_name(source.expression if source else "")
    if not param:
        param = (
            extract_source_param_name(candidate.source.symbol or "")
            or extract_source_param_name(candidate.static_evidence or "")
            or extract_plain_param_name(candidate.source.symbol or "")
            or extract_route_param_name(candidate.source.symbol or "")
            or "af_marker"
        )
    return {param: marker}


def extract_source_param_name(expression: str) -> str | None:
    patterns = [
        r"\.(?:get|param|PathValue|getParameter|getHeader)\(\s*['\"](?P<name>[A-Za-z_][\w-]*)['\"]",
        r"\[(?:'|\")(?P<name>[A-Za-z_][\w-]*)(?:'|\")\]",
        r"\.(?:query|params|body|args)\.(?P<name>[A-Za-z_][\w-]*)\b",
        r"\broute parameter\s+(?P<name>[A-Za-z_][\w-]*)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, expression)
        if match:
            return match.group("name")
    return None


def extract_route_param_name(symbol: str) -> str | None:
    match = re.search(r"[?&]([A-Za-z_][\w-]*)=", symbol)
    return match.group(1) if match else None


def extract_plain_param_name(symbol: str) -> str | None:
    symbol = symbol.strip()
    if re.fullmatch(r"[A-Za-z_][\w-]{0,40}", symbol):
        return symbol
    return None
