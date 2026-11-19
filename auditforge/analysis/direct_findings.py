# ruff: noqa: RUF001
# Chinese user-facing evidence intentionally uses full-width punctuation.

from __future__ import annotations

from pathlib import Path

from ..core.models import CodeAnchor, CodeFacts, TraceCandidate, TraceStep, VulnClass
from ..core.utils import sha256_text


def generate_direct_candidates(
    repo_path: Path,
    facts: CodeFacts,
    existing: list[TraceCandidate],
    *,
    enabled: bool = False,
) -> list[TraceCandidate]:
    """Generate legacy demo-route findings only when explicitly requested.

    Route names such as ``/admin`` or ``/upload`` are not vulnerability evidence.
    The old rules remain available for fixture demonstrations, but production scans
    (including the engine's default call) no longer emit them.
    """

    if not enabled:
        return []
    existing_keys = {(item.vuln_class, item.source.file, item.source.start_line, item.sink.file, item.sink.start_line) for item in existing}
    generated: list[TraceCandidate] = []
    for route in facts.routes:
        path = route.path.lower()
        if path == "/config":
            append_direct(
                generated,
                existing_keys,
                repo_path,
                "auth",
                route.anchor.file,
                route.anchor.start_line,
                route.anchor.file,
                route.anchor.start_line,
                "配置泄露/弱安全配置路由：页面暴露 DEBUG、SECRET_KEY、cookie flags 或内部配置。",
                "访问 /config，确认是否泄露敏感配置和弱 cookie 设置。",
                route.id,
                "配置暴露入口",
                "render_template(config)",
            )
        elif path == "/crypto":
            append_direct(
                generated,
                existing_keys,
                repo_path,
                "auth",
                route.anchor.file,
                route.anchor.start_line,
                route.anchor.file,
                route.anchor.start_line,
                "弱加密流程：可疑 MD5 哈希、可逆 Base64 token 或硬编码 secret。",
                "提交无害标记到 /crypto，确认响应是否生成 MD5 和可逆 token。",
                route.id,
                "crypto input",
                "weak crypto output",
            )
        elif path == "/reset-password":
            append_direct(
                generated,
                existing_keys,
                repo_path,
                "auth",
                route.anchor.file,
                route.anchor.start_line,
                route.anchor.file,
                route.anchor.start_line,
                "密码重置流程缺少登录态、旧密码、一次性 token、速率限制或审计证明。",
                "对不存在用户提交无害重置请求，确认流程是否接受无证明重置。",
                route.id,
                "reset form",
                "password update",
            )
        elif path == "/admin":
            append_direct(
                generated,
                existing_keys,
                repo_path,
                "authz",
                route.anchor.file,
                route.anchor.start_line,
                route.anchor.file,
                route.anchor.start_line,
                "认证/授权边界候选：应用信任可伪造 remember_user Cookie，role 字段由客户端可逆 Base64 控制。",
                "提交仅包含 username:admin 的无签名 remember_user Cookie，确认是否可进入管理页面。",
                route.id,
                "remember_user cookie",
                "admin authorization",
            )
        elif "profile" in path and any(marker in route.path for marker in ("<", "{", ":")):
            append_direct(
                generated,
                existing_keys,
                repo_path,
                "authz",
                route.anchor.file,
                route.anchor.start_line,
                route.anchor.file,
                route.anchor.start_line,
                "对象级越权候选：资料页使用路径 ID 选择用户对象，需要确认是否检查当前会话归属。",
                "访问 /profile/1 与 /profile/2，对比未登录状态下是否都能读取 Email、API Key、Balance 等字段。",
                route.id,
                "profile path id",
                "profile object render",
            )
        elif path == "/notes":
            append_direct(
                generated,
                existing_keys,
                repo_path,
                "xss",
                route.anchor.file,
                route.anchor.start_line,
                route.anchor.file,
                route.anchor.start_line,
                "存储型 XSS 候选：笔记正文由用户提交，模板可能按 trusted HTML 渲染。",
                "提交无脚本自定义标签并重新读取 /notes，确认是否未转义持久化渲染。",
                route.id,
                "note body",
                "notes template",
            )
        elif path == "/deserialize" and not has_existing_route_candidate(existing, route.id, "deserialization"):
            append_direct(
                generated,
                existing_keys,
                repo_path,
                "injection",
                route.anchor.file,
                route.anchor.start_line,
                route.anchor.file,
                route.anchor.start_line,
                "不安全反序列化候选：路由从请求表单读取 Base64 数据后直接进入 pickle.loads。",
                "提交只包含普通字典对象的无害 Pickle，确认服务端是否执行反序列化并回显结果。",
                route.id,
                "payload form field",
                "pickle.loads",
            )
        elif path == "/upload":
            append_direct(
                generated,
                existing_keys,
                repo_path,
                "injection",
                route.anchor.file,
                route.anchor.start_line,
                route.anchor.file,
                route.anchor.start_line,
                "不安全文件上传候选：文件名按客户端输入原样保存，可能导致路径穿越或危险扩展落地。",
                "人工使用隔离环境提交边界文件名，确认服务端保存路径和访问控制。",
                route.id,
                "uploaded filename",
                "uploaded.save",
            )
    return generated


def has_existing_route_candidate(existing: list[TraceCandidate], route_id: str | None, needle: str) -> bool:
    if not route_id:
        return False
    lowered_needle = needle.lower()
    for candidate in existing:
        if candidate.route_id != route_id:
            continue
        text = f"{candidate.sink.symbol or ''} {candidate.static_evidence}".lower()
        if lowered_needle in text:
            return True
    return False


def append_direct(
    out: list[TraceCandidate],
    existing_keys: set[tuple[str, str, int, str, int]],
    repo_path: Path,
    vuln_class: VulnClass,
    source_file: str,
    source_line: int,
    sink_file: str,
    sink_line: int,
    evidence: str,
    hint: str,
    route_id: str | None,
    source_symbol: str,
    sink_symbol: str,
) -> None:
    key = (vuln_class, source_file, source_line, sink_file, sink_line)
    if key in existing_keys:
        return
    source = make_anchor(repo_path, source_file, source_line, source_symbol)
    sink = make_anchor(repo_path, sink_file, sink_line, sink_symbol)
    out.append(
        TraceCandidate(
            id=f"DIRECT-{vuln_class.upper()}-{len(out) + 1:03d}",
            vuln_class=vuln_class,
            source=source,
            sink=sink,
            steps=[
                TraceStep(
                    kind="framework_binding",
                    from_anchor=source,
                    to_anchor=sink,
                    explanation="基于路由和安全敏感 API/模板模式生成的直接审计候选。",
                    confidence="medium",
                )
            ],
            sanitizers=[],
            blockers=[],
            confidence="medium",
            static_evidence=evidence,
            verification_hint=hint,
            route_id=route_id,
            origin="deterministic",
        )
    )
    existing_keys.add(key)


def make_anchor(repo_path: Path, file: str, line: int, symbol: str) -> CodeAnchor:
    absolute = repo_path / file
    return CodeAnchor(file=file, start_line=line, end_line=line, snippet_hash=snippet_hash_for_line(absolute, line), symbol=symbol)


def snippet_hash_for_line(path: Path, line_no: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        text = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
    except OSError:
        text = ""
    return sha256_text(text)[:16]
