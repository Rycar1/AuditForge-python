"""Safe, actionable error contracts shared by the CLI, worker and web UI.

Internal exceptions belong in protected logs.  Values produced by this module
are deliberately stable and safe to persist in scan history or return over the
HTTP API.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class ErrorTemplate:
    code: str
    message: str
    action: str
    status: int
    retryable: bool = False


@dataclass(frozen=True, slots=True)
class UserError:
    code: str
    message: str
    action: str
    status: int
    retryable: bool
    reference: str
    field: str | None = None


class UserFacingError(Exception):
    """An expected failure whose message is safe to show to a user."""

    def __init__(
        self,
        code: str,
        *,
        message: str | None = None,
        action: str | None = None,
        status: int | None = None,
        retryable: bool | None = None,
        field: str | None = None,
        reference: str | None = None,
    ) -> None:
        template = ERROR_CATALOG.get(code)
        if template is None and (message is None or action is None or status is None):
            raise ValueError(f"unknown user error code: {code}")
        self.code = code
        self.message = message if message is not None else template.message
        self.action = action if action is not None else template.action
        self.status = int(status if status is not None else template.status)
        self.retryable = bool(retryable if retryable is not None else template.retryable)
        self.field = field
        self.reference = reference
        super().__init__(self.message)


ERROR_CATALOG: dict[str, ErrorTemplate] = {
    item.code: item
    for item in (
        ErrorTemplate("AUTH_REQUIRED", "需要登录后才能继续。", "请重新登录，然后再执行此操作。", 401),
        ErrorTemplate("AUTH_INVALID_TOKEN", "访问令牌无效或已失效。", "请使用当前工作区生成的访问令牌重新登录。", 401),
        ErrorTemplate("REQUEST_HOST_REJECTED", "请求的主机地址不受信任。", "请从启动日志显示的 Dashboard 地址访问。", 421),
        ErrorTemplate("REQUEST_ORIGIN_REJECTED", "请求来源未通过安全校验。", "请刷新当前页面后重试，不要跨站调用此接口。", 403),
        ErrorTemplate("REQUEST_CSRF_REJECTED", "页面会话已失效，安全校验未通过。", "请刷新页面或重新登录后重试。", 403),
        ErrorTemplate("REQUEST_INVALID", "请求内容不完整或格式不正确。", "请检查输入内容后重试。", 400),
        ErrorTemplate("REQUEST_BODY_TOO_LARGE", "请求内容超过服务允许的大小。", "请减小请求或上传文件的体积后重试。", 413),
        ErrorTemplate("METHOD_NOT_ALLOWED", "当前接口不支持这个请求方法。", "请刷新页面；若问题持续，请检查客户端版本。", 405),
        ErrorTemplate("RESOURCE_NOT_FOUND", "请求的资源不存在或已被删除。", "请返回上一页并刷新任务列表。", 404),
        ErrorTemplate("UPLOAD_BUSY", "当前上传任务较多，暂时无法接收新文件。", "请稍候几秒后重试。", 429, True),
        ErrorTemplate("UPLOAD_INVALID", "上传内容无法解析。", "请确认文件是有效的 ZIP 代码包，并重新上传。", 400),
        ErrorTemplate("UPLOAD_TOO_LARGE", "上传文件超过大小限制。", "请移除构建产物或依赖目录后重新打包。", 413),
        ErrorTemplate("ZIP_UNSAFE", "压缩包包含不安全或异常的文件结构。", "请重新打包源码，避免链接、越界路径或异常压缩比。", 400),
        ErrorTemplate("REPO_PATH_INVALID", "代码仓库路径无效或不在允许范围内。", "请选择已授权根目录内的现有代码仓库。", 422),
        ErrorTemplate(
            "SCAN_CONCURRENCY_LIMIT", "当前已有较多扫描任务正在运行。", "请等待现有任务结束，或先停止不再需要的任务。", 429, True
        ),
        ErrorTemplate(
            "SCAN_WORKER_START_FAILED", "扫描进程启动失败。", "请查看诊断编号对应的日志，排除资源不足或环境配置问题后重试。", 503, True
        ),
        ErrorTemplate(
            "SCAN_WORKER_EXITED", "扫描进程意外退出，任务未完成。", "请根据诊断编号查看日志，确认资源和运行环境后重新扫描。", 500, True
        ),
        ErrorTemplate("SCAN_CANCELLED", "扫描任务已取消。", "如需继续，请重新创建扫描任务。", 409),
        ErrorTemplate("SCAN_FAILED", "扫描执行失败。", "请根据诊断编号查看日志，修正环境或配置问题后重试。", 500),
        ErrorTemplate("RUN_NOT_FOUND", "扫描任务不存在或已被删除。", "请返回任务列表并刷新页面。", 404),
        ErrorTemplate("RUN_STATE_CONFLICT", "任务当前状态不允许执行此操作。", "请刷新任务状态后再试。", 409),
        ErrorTemplate("RUN_UPDATE_FAILED", "任务信息更新失败。", "请刷新页面后重试；若问题持续，请查看诊断日志。", 500, True),
        ErrorTemplate("SETTINGS_INVALID", "设置内容无效，未能保存。", "请检查标记的配置项后重试。", 422),
        ErrorTemplate("LLM_KEY_MISSING", "未配置可用的 LLM API Key。", "请在模型设置中填写密钥或配置对应的环境变量。", 422),
        ErrorTemplate("LLM_ENDPOINT_INVALID", "LLM 服务地址无效或不受允许。", "请检查服务地址、协议和网络访问范围。", 422),
        ErrorTemplate("LLM_AUTH_FAILED", "LLM 服务拒绝了身份验证。", "请检查 API Key、模型权限和账户状态。", 502),
        ErrorTemplate("LLM_RATE_LIMITED", "LLM 服务当前请求过多。", "请稍候重试，或降低并发数。", 429, True),
        ErrorTemplate("LLM_TIMEOUT", "LLM 服务响应超时。", "请检查网络和服务状态，或适当增大超时时间。", 504, True),
        ErrorTemplate("LLM_PROVIDER_FAILED", "LLM 服务暂时不可用。", "请检查供应商状态和模型配置后重试。", 502, True),
        ErrorTemplate("SANDBOX_UNAVAILABLE", "隔离验证环境当前不可用。", "请检查容器运行时和沙箱镜像后重试。", 503, True),
        ErrorTemplate("SANDBOX_TIMEOUT", "隔离验证超过时间限制。", "请检查靶场服务状态，或降低验证并发后重试。", 504, True),
        ErrorTemplate("SERVER_BUSY", "服务当前请求较多，暂时无法处理新请求。", "请稍候几秒后重试。", 503, True),
        ErrorTemplate("SERVER_START_FAILED", "Dashboard 启动失败。", "请检查端口占用、目录权限和服务配置。", 503, True),
        ErrorTemplate("INTERNAL_ERROR", "系统处理请求时发生内部错误。", "请根据诊断编号查看日志；若问题持续，请重启服务后重试。", 500),
    )
}


def new_reference(prefix: str = "AF") -> str:
    """Return a short identifier suitable for UI, task history and logs."""

    safe_prefix = re.sub(r"[^A-Z0-9]", "", prefix.upper())[:8] or "AF"
    date = datetime.now(UTC).strftime("%Y%m%d")
    return f"{safe_prefix}-{date}-{uuid.uuid4().hex[:8].upper()}"


def user_error(code: str, *, reference: str | None = None, field: str | None = None) -> UserError:
    template = ERROR_CATALOG.get(code, ERROR_CATALOG["INTERNAL_ERROR"])
    return UserError(
        code=template.code,
        message=template.message,
        action=template.action,
        status=template.status,
        retryable=template.retryable,
        reference=reference or new_reference(),
        field=field,
    )


def classify_error(exc: BaseException, *, context: str = "internal", reference: str | None = None) -> UserError:
    """Map an internal exception to a conservative public error contract."""

    if isinstance(exc, UserFacingError):
        template = UserError(
            code=exc.code,
            message=exc.message,
            action=exc.action,
            status=exc.status,
            retryable=exc.retryable,
            reference=reference or exc.reference or new_reference(),
            field=exc.field,
        )
        return template

    normalized_context = context.strip().lower().replace("-", "_")
    text = str(exc).lower()
    code = _context_code(exc, normalized_context, text)
    return user_error(code, reference=reference)


def error_payload(error: UserError) -> dict[str, object]:
    payload: dict[str, object] = {
        "ok": False,
        "error": error.message,
        "error_code": error.code,
        "action": error.action,
        "retryable": error.retryable,
        "reference": error.reference,
    }
    if error.field:
        payload["field"] = error.field
    return payload


def failure_payload(error: UserError, *, stage: str | None = None) -> dict[str, object]:
    failure: dict[str, object] = {
        "code": error.code,
        "action": error.action,
        "retryable": error.retryable,
        "diagnostic_id": error.reference,
    }
    if stage:
        failure["stage"] = stage
    return failure


def format_cli_error(error: UserError) -> str:
    return f"错误 [{error.code}]：{error.message}\n处理建议：{error.action}\n诊断编号：{error.reference}"


def with_status(error: UserError, status: int) -> UserError:
    """Override an HTTP status without mutating the stable error meaning."""

    return replace(error, status=int(status))


def _context_code(exc: BaseException, context: str, text: str) -> str:
    if context in {"llm", "llm_test", "llm_provider"}:
        if "api key" in text or "api_key" in text or "missing key" in text:
            return "LLM_KEY_MISSING"
        if any(marker in text for marker in ("unauthorized", "forbidden", "status 401", "status 403", "http 401", "http 403")):
            return "LLM_AUTH_FAILED"
        if any(marker in text for marker in ("rate limit", "too many requests", "status 429", "http 429")):
            return "LLM_RATE_LIMITED"
        if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
            return "LLM_TIMEOUT"
        if any(marker in text for marker in ("base url", "base_url", "endpoint", "scheme", "host is not allowed")):
            return "LLM_ENDPOINT_INVALID"
        return "LLM_PROVIDER_FAILED"

    if context in {"sandbox", "verification"}:
        if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
            return "SANDBOX_TIMEOUT"
        return "SANDBOX_UNAVAILABLE"

    if context in {"settings", "configuration"}:
        return "SETTINGS_INVALID" if isinstance(exc, (TypeError, ValueError)) else "INTERNAL_ERROR"

    if context in {"upload", "multipart"}:
        if any(marker in text for marker in ("too large", "exceeds", "size limit", "maximum upload")):
            return "UPLOAD_TOO_LARGE"
        if any(marker in text for marker in ("zip", "archive", "symlink", "path traversal", "compression ratio")):
            return "ZIP_UNSAFE"
        return "UPLOAD_INVALID"

    if context in {"repo", "repository", "repo_path"}:
        return "REPO_PATH_INVALID"

    if context in {"run_lookup", "run_not_found"} or isinstance(exc, LookupError):
        return "RUN_NOT_FOUND"

    if context in {"run_state", "cancel", "delete"}:
        return "RUN_STATE_CONFLICT" if isinstance(exc, (ValueError, RuntimeError)) else "RUN_UPDATE_FAILED"

    if context in {"request", "json", "logs", "triage", "graph"} and isinstance(exc, (TypeError, ValueError)):
        return "REQUEST_INVALID"

    if context in {"scan", "scan_start"}:
        if "concurrency" in text or "capacity" in text or "already running" in text:
            return "SCAN_CONCURRENCY_LIMIT"
        if any(marker in text for marker in ("repository", "repo path", "outside", "not a directory")):
            return "REPO_PATH_INVALID"
        return "SCAN_FAILED"

    if context in {"worker_start", "scan_worker_start"}:
        return "SCAN_WORKER_START_FAILED"
    if context in {"worker", "scan_worker"}:
        return "SCAN_FAILED"
    if context in {"server", "server_start"}:
        return "SERVER_START_FAILED"
    return "INTERNAL_ERROR"
