from __future__ import annotations

import json
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..analysis.llm_candidates import (
    DEFAULT_BASE_URL,
    DEFAULT_CANDIDATE_SYSTEM_PROMPT,
    DEFAULT_CANDIDATE_USER_PROMPT,
    DEFAULT_MODEL,
    LLMConfig,
)
from ..sca.dependency_scan import DEFAULT_DEPENDENCY_SYSTEM_PROMPT, DEFAULT_DEPENDENCY_USER_PROMPT
from ..verification.deep_verification import DEFAULT_DEEP_SYSTEM_PROMPT, DEFAULT_DEEP_USER_PROMPT
from ..web.web_security import atomic_write_json, locked_path, redact_url
from .secret_store import clear_llm_api_key, load_llm_api_key, save_llm_api_key

SETTINGS_FILE = "auditforge_settings.json"
SETTINGS_LOCK = threading.RLock()
DEFAULT_LANGUAGE = "zh-CN"
SUPPORTED_LANGUAGES = {"zh-CN", "en-US"}
LLM_PROFILE_IDS = ("taint", "dependency", "deep")
LLM_CONNECTION_SETTING_KEYS = [
    "enabled",
    "provider",
    "base_url",
    "api_key_env",
    "response_file",
    "max_candidates",
    "timeout_seconds",
    "concurrency",
    "sandbox_concurrency",
]
LLM_PROFILE_SETTING_KEYS = [
    "model",
    "system_prompt",
    "user_prompt",
]
PROMPT_VERSION = 4
LEGACY_DEFAULT_MODELS = {"gpt-4o-mini", "gpt-5.4-mini"}
LLM_SETTING_KEYS = LLM_CONNECTION_SETTING_KEYS + LLM_PROFILE_SETTING_KEYS
LEGACY_PROFILE_CONNECTION_KEYS = set(LLM_CONNECTION_SETTING_KEYS + ["api_key", "clear_api_key", "has_api_key"])
LEGACY_DEFAULT_PROMPTS = {
    "taint": {
        "system_prompt": (
            "你是资深多语言白盒代码审计候选路径生成器，负责在确定性规则之外补充可能漏掉的 source-to-sink 候选。"
            "你的输出只进入验证队列，不能作为已确认漏洞结论。"
            "你必须优先保证源码锚点真实、传播解释可复核、置信度保守、去重严格。"
            "你应同时考虑框架路由绑定、跨函数调用、模板上下文、业务认证授权和 sanitizer 语义匹配。"
            "只输出严格 JSON object，并完全遵守输出契约。"
        ),
        "user_prompt": (
            "基于结构化 facts、调用/数据/控制流摘要和源码片段，补充确定性规则可能漏掉的候选路径。"
            "重点关注跨函数传播、框架绑定、模板上下文、业务授权条件、反序列化、SSRF、文件上传、弱认证/越权等语义型问题。"
            "只输出有明确源码锚点和非破坏性验证思路的候选；证据不足时降低置信度或不输出。"
        ),
    },
    "dependency": {
        "system_prompt": (
            "你是资深软件成分分析（SCA）审计员，负责基于依赖清单生成需要复核的依赖漏洞候选。"
            "你的结论只进入依赖风险候选区，不能作为已确认漏洞。"
            "你必须只分析输入 inventory 中真实存在的组件和版本约束，保守处理不确定 CVE、版本范围和生态差异。"
            "输出必须是严格 JSON object，并完全遵守输出契约。"
        ),
        "user_prompt": (
            "分析 requirements.txt、pom.xml、package.json、go.mod 等依赖清单，识别公开 CVE、受影响版本范围、"
            "明显过旧或高风险组件，并生成需要 OSV/NVD/GHSA/Maven/NPM/PyPI/Go advisory 复核的依赖风险候选。"
            "不要臆造 CVE；证据不足时降低置信度、写清复核原因，或返回空 findings。"
        ),
    },
    "deep": {
        "system_prompt": (
            "你是资深白盒代码审计二次验证器，负责把 source-to-sink 候选转化为安全的代码片段级验证。"
            "你的目标是减少误报：只有当源码片段行为能被无害 marker 和断言稳定复现时，才给 confirmed。"
            "只输出严格 JSON object；不要输出破坏性 payload，不要生成网络、文件、子进程、反射、导入、eval/exec 代码。"
            "平台会在容器级隔离沙箱中执行测试脚本，不会挂载目标仓库，也不会访问真实外部服务。"
        ),
        "user_prompt": (
            "对一个 source-to-sink 候选进行二次深入验证。请阅读候选路径、源码片段和上下文，判断漏洞是否能在代码片段层面被安全复现。"
            "优先构造最小化、纯内存、无副作用的 Python 沙箱测试：用 AF_MARKER 模拟外部输入，用字符串/字典/列表/函数模拟框架对象，"
            "用 sink() 占位危险调用，并用 assert 证明 marker 到达 sink、授权检查缺失、或 sanitizer 生效/不生效。"
            "如果候选依赖真实数据库、网络、文件系统、登录态、异步框架或业务状态而无法安全模拟，应返回 blocked 或 needs_manual_review。"
        ),
    },
}
LEGACY_DEFAULT_PROMPTS_V2 = {
    "taint": {
        "system_prompt": (
            "你是资深多语言白盒代码审计路径生成器，任务是在确定性 facts 的基础上补充可能漏掉的 source-to-sink 候选。"
            "你不是漏洞定案器；输出只进入验证队列，不能声明已确认、已利用或线上可复现。"
            "你必须像 SAST triager 一样保守：先证明入口可控、sink 有安全影响、传播链可解释、防护与上下文不匹配，再给候选。"
            "所有 file/startLine/endLine 必须来自输入 facts、anchorContext 或 codeContext；不能臆造源码、路由、函数、依赖或行号。"
            "遇到动态分发、框架魔法、业务状态、认证授权不明时，记录 blocker 并降低置信度。"
            "只输出严格 JSON object，中文解释，完全遵守输出契约。"
        ),
        "user_prompt": (
            "请按“入口盘点 -> 危险 sink -> 调用/数据流传播 -> 防护语义匹配 -> 误报排除 -> 验证提示”的流程审查输入。"
            "重点补充规则容易漏掉的跨函数传播、框架绑定、模板上下文、业务授权条件、反序列化、SSRF、文件上传、弱认证、水平/垂直越权等语义型问题。"
            "每条候选必须包含真实源码锚点、变量/参数如何流动、缺失或不匹配的 sanitizer/guard、保守置信度和非破坏性验证思路。"
            "证据不足、传播链断裂、行号不确定、已被有效防护覆盖或只能依赖命名猜测时，不输出或降为 low。"
        ),
    },
    "dependency": {
        "system_prompt": (
            "你是资深软件成分分析（SCA）审计员，负责基于依赖清单生成需要复核的依赖漏洞候选。"
            "你的输出只进入依赖风险候选区，不能作为已确认漏洞；没有联网事实源时必须保守，禁止编造 CVE、公告、修复版本或引用链接。"
            "你必须只分析输入 inventory 中真实存在的组件、生态、scope 和版本约束，严格区分 PyPI/npm/Maven/Go 生态与同名包。"
            "判断时先核对包名与生态，再判断版本约束是否可能落入受影响范围，最后给 severity/confidence。"
            "输出必须是严格 JSON object，中文解释，并完全遵守输出契约。"
        ),
        "user_prompt": (
            "分析 requirements.txt、pom.xml、package.json、go.mod 等依赖清单，识别公开 CVE/GHSA/OSV、受影响版本范围、"
            "明显过旧或高风险组件，并生成需要 OSV/NVD/GHSA/供应商公告/包生态 advisory 复核的依赖风险候选。"
            "优先输出包名、生态、当前版本和公告范围高度匹配的结果；版本为范围、变量、继承、未固定或不确定时必须降置信。"
            "不要臆造 CVE、引用链接、修复版本或确定性结论；证据不足时写清复核原因、降低 confidence，或返回空 findings。"
        ),
    },
    "deep": {
        "system_prompt": (
            "你是资深白盒代码审计二次验证器，负责把 source-to-sink 候选转化为安全的代码片段级验证。"
            "你的目标是减少误报：只有源码片段行为能被无害 AF_MARKER、最小化模型和明确 assert 稳定证明时，才给 confirmed。"
            "你必须 fail-closed：无法安全模拟、无法解释传播、需要真实网络/文件/数据库/登录态/外部服务时，返回 blocked 或 needs_manual_review。"
            "只输出严格 JSON object；不要输出破坏性 payload，不要生成网络、文件、子进程、反射、导入、eval/exec 代码。"
            "平台会在容器级隔离沙箱中执行测试脚本，不会挂载目标仓库，也不会访问真实外部服务。"
        ),
        "user_prompt": (
            "对一个 source-to-sink 候选进行二次深入验证。请阅读候选路径、源码片段和上下文，判断漏洞是否能在代码片段层面被安全复现。"
            "优先构造最小化、纯内存、无副作用的 Python 沙箱测试：用 AF_MARKER 模拟外部输入，用字符串/字典/列表/函数模拟框架对象，"
            "用 sink() 占位危险调用，并用 assert 证明 marker 到达 sink、授权检查缺失、或 sanitizer 生效/不生效。"
            "能写测试时尽量包含正向证明和一个安全控制断言；不能写出无副作用测试时，不要 confirmed。"
            "如果候选依赖真实数据库、网络、文件系统、登录态、异步框架或业务状态而无法安全模拟，应返回 blocked 或 needs_manual_review。"
        ),
    },
}

# Prompt version 3 asked the model to emit executable Python snippets for the
# legacy container sandbox.  Keep the exact defaults here so existing
# workspaces can be upgraded to the declarative validation contract while
# preserving genuinely customized prompts.
LEGACY_DEFAULT_PROMPTS_V3 = {
    "deep": {
        "system_prompt": (
            "你是资深白盒代码审计二次验证器，负责把 source-to-sink 候选转化为安全的代码片段级验证。"
            "你的目标是减少误报：只有源码片段行为能被无害 AF_MARKER、最小化模型和明确 assert 稳定证明时，才给 confirmed。"
            "你必须 fail-closed：无法安全模拟、无法解释传播、需要真实网络/文件/数据库/登录态/外部服务时，返回 blocked 或 needs_manual_review。"
            "你可以用 Python 重建纯数据流或纯授权逻辑，但不能把重建模型当成真实运行环境；语言/框架语义无法等价模拟时必须降级。"
            "只输出严格 JSON object；不要输出破坏性 payload，不要生成网络、文件、子进程、反射、导入、eval/exec 代码。"
            "平台会在容器级隔离沙箱中执行测试脚本，不会挂载目标仓库，也不会访问真实外部服务。"
        ),
        "user_prompt": (
            "对一个 source-to-sink 候选进行二次深入验证。请阅读候选路径、源码片段和上下文，判断漏洞是否能在代码片段层面被安全复现。"
            "优先构造最小化、纯内存、无副作用的 Python 沙箱测试：用 AF_MARKER 模拟外部输入，用字符串/字典/列表/函数模拟框架对象，"
            "用 sink() 占位危险调用，并用 assert 证明 marker 到达 sink、授权检查缺失、或 sanitizer 生效/不生效。"
            "能写测试时尽量包含正向证明和一个安全控制断言；不能写出无副作用测试时，不要 confirmed。"
            "测试必须复刻候选中的关键变量、分支和防护判断；如果只能写与源码无关的泛化示例，应返回 needs_manual_review。"
            "如果候选依赖真实数据库、网络、文件系统、登录态、异步框架或业务状态而无法安全模拟，应返回 blocked 或 needs_manual_review。"
        ),
    }
}


def default_llm_connection() -> dict[str, Any]:
    return {
        "enabled": False,
        "provider": "openai-compatible",
        "base_url": DEFAULT_BASE_URL,
        "api_key_env": "AUDITFORGE_LLM_API_KEY",
        "api_key": None,
        "response_file": None,
        "max_candidates": 200,
        "timeout_seconds": 60,
        "concurrency": 3,
        "sandbox_concurrency": 3,
    }


def default_llm_profile(profile: str) -> dict[str, Any]:
    if profile == "deep":
        system_prompt = DEFAULT_DEEP_SYSTEM_PROMPT
        user_prompt = DEFAULT_DEEP_USER_PROMPT
    elif profile == "dependency":
        system_prompt = DEFAULT_DEPENDENCY_SYSTEM_PROMPT
        user_prompt = DEFAULT_DEPENDENCY_USER_PROMPT
    else:
        system_prompt = DEFAULT_CANDIDATE_SYSTEM_PROMPT
        user_prompt = DEFAULT_CANDIDATE_USER_PROMPT
    return {
        "model": DEFAULT_MODEL,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "prompt_version": PROMPT_VERSION,
    }


def default_settings() -> dict[str, Any]:
    connection = default_llm_connection()
    taint_profile = default_llm_profile("taint")
    return {
        "language": DEFAULT_LANGUAGE,
        "llm": {
            **connection,
            **taint_profile,
            "connection": connection,
            "taint": taint_profile,
            "dependency": default_llm_profile("dependency"),
            "deep": default_llm_profile("deep"),
        },
    }


def settings_path(workspace: Path) -> Path:
    return workspace.resolve() / SETTINGS_FILE


def load_workspace_settings(workspace: Path) -> dict[str, Any]:
    workspace = workspace.resolve()
    path = settings_path(workspace)
    with SETTINGS_LOCK, locked_path(path):
        settings = default_settings()
        if not path.exists():
            return settings
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return settings
        legacy_key = extract_plaintext_api_key(payload)
        if isinstance(payload, dict):
            merge_settings(settings, payload)
            upgrade_llm_profiles(settings, payload)
        settings["language"] = normalize_language(settings.get("language"))
        normalize_llm_settings(settings)
        base_url = current_base_url(settings)
        if legacy_key:
            save_llm_api_key(workspace, legacy_key, base_url)
            atomic_write_json(path, settings_for_persistence(settings))
        apply_runtime_api_key(settings, load_llm_api_key(workspace, base_url))
        return settings


def save_workspace_settings(workspace: Path, payload: dict[str, Any]) -> dict[str, Any]:
    workspace = workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    path = settings_path(workspace)
    with SETTINGS_LOCK, locked_path(path):
        settings = load_workspace_settings(workspace)
        old_base_url = current_base_url(settings)
        old_api_key = current_api_key(settings)
        incoming_llm = payload.get("llm", payload)
        if not isinstance(incoming_llm, dict):
            raise ValueError("settings payload must contain an llm object")

        if "language" in payload:
            settings["language"] = normalize_language(payload.get("language"))

        llm = settings["llm"]
        incoming_connection = (
            incoming_llm.get("connection")
            if isinstance(incoming_llm.get("connection"), dict)
            else infer_legacy_connection_payload(incoming_llm)
        )
        incoming_connection = incoming_connection if isinstance(incoming_connection, dict) else {}
        supplied_key = str(incoming_connection.get("api_key") or "").strip()
        new_key_supplied = bool(supplied_key and supplied_key != mask_secret(old_api_key))
        clear_key = bool(incoming_connection.get("clear_api_key"))
        update_llm_connection(llm.setdefault("connection", default_llm_connection()), incoming_connection)
        sync_flat_llm_from_connection(llm)
        has_profile_payload = False
        for profile_id in LLM_PROFILE_IDS:
            incoming_profile = incoming_llm.get(profile_id)
            if isinstance(incoming_profile, dict):
                has_profile_payload = True
                update_llm_profile(
                    llm.setdefault(profile_id, default_llm_profile(profile_id)),
                    incoming_profile,
                )
        if has_profile_payload:
            sync_flat_llm_from_profile(llm, "taint")
        elif any(key in incoming_llm for key in LLM_PROFILE_SETTING_KEYS):
            # Backward compatibility for older clients that still post a single flat llm object.
            update_llm_profile(llm.setdefault("taint", default_llm_profile("taint")), incoming_llm)
            sync_flat_llm_from_profile(llm, "taint")
            sync_legacy_llm_to_profiles(llm)

        normalize_llm_settings(settings)
        new_base_url = current_base_url(settings)
        if clear_key:
            clear_llm_api_key(workspace)
            runtime_key = None
        elif new_key_supplied:
            save_llm_api_key(workspace, supplied_key, new_base_url)
            runtime_key = supplied_key
        elif redact_url(new_base_url).lower() != redact_url(old_base_url).lower():
            # A credential is bound to the endpoint for which it was entered. Changing
            # endpoints never silently forwards the prior credential.
            clear_llm_api_key(workspace)
            runtime_key = None
        else:
            runtime_key = old_api_key
        apply_runtime_api_key(settings, runtime_key)
        atomic_write_json(path, settings_for_persistence(settings))
        return settings


def normalize_language(value: Any) -> str:
    language = str(value or DEFAULT_LANGUAGE).strip()
    return language if language in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def merge_settings(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge_settings(base[key], value)
        else:
            base[key] = value


def normalize_setting_value(key: str, value: Any) -> Any:
    if key == "enabled":
        return bool(value)
    if key == "provider":
        provider = str(value).strip()
        return provider if provider in {"openai-compatible", "fixture"} else "openai-compatible"
    if key == "base_url":
        raw = str(value or "").strip().rstrip("/")
        redacted = redact_url(raw)
        if not redacted.startswith(("http://", "https://")) or redacted != raw:
            raise ValueError("LLM base_url must use http/https and cannot contain credentials, query, or fragment")
        parsed = urlsplit(redacted)
        if parsed.scheme == "http" and (parsed.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("remote LLM base_url must use HTTPS")
        return redacted
    if key == "max_candidates":
        try:
            return max(1, min(500, int(value)))
        except (TypeError, ValueError):
            return 200
    if key == "timeout_seconds":
        try:
            return max(10, min(600, int(value)))
        except (TypeError, ValueError):
            return 60
    if key in {"concurrency", "sandbox_concurrency"}:
        try:
            return max(1, min(12, int(value)))
        except (TypeError, ValueError):
            return 3
    if key in {"system_prompt", "user_prompt"}:
        return str(value or "").strip()[:12000]
    if key == "response_file":
        return str(value or "").strip() or None
    return str(value).strip()


def public_settings(settings: dict[str, Any]) -> dict[str, Any]:
    public = json.loads(json.dumps(settings))
    llm = public.setdefault("llm", {})
    connection = llm.setdefault("connection", default_llm_connection())
    if isinstance(connection, dict):
        connection["base_url"] = redact_url(connection.get("base_url"))
        connection["has_response_file"] = bool(connection.get("response_file"))
        connection.pop("response_file", None)
        mask_llm_connection(connection)
    llm["base_url"] = redact_url(llm.get("base_url"))
    llm["has_response_file"] = bool(llm.get("response_file"))
    llm.pop("response_file", None)
    mask_llm_connection(llm)
    for profile_id in LLM_PROFILE_IDS:
        profile = llm.setdefault(profile_id, default_llm_profile(profile_id))
        if isinstance(profile, dict):
            llm[profile_id] = public_llm_profile(profile, profile_id)
    return public


def update_llm_connection(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    for key in LLM_CONNECTION_SETTING_KEYS:
        if key == "response_file":
            continue
        if key in incoming:
            target[key] = normalize_setting_value(key, incoming[key])

    if incoming.get("clear_response_file"):
        target["response_file"] = None
    elif str(incoming.get("response_file") or "").strip():
        target["response_file"] = normalize_setting_value("response_file", incoming["response_file"])

    if incoming.get("clear_api_key"):
        target["api_key"] = None
    elif "api_key" in incoming:
        api_key = str(incoming.get("api_key") or "").strip()
        if api_key and api_key != mask_secret(target.get("api_key")):
            target["api_key"] = api_key


def update_llm_profile(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    for key in LLM_PROFILE_SETTING_KEYS:
        if key in incoming:
            target[key] = normalize_setting_value(key, incoming[key])


def mask_llm_connection(profile: dict[str, Any]) -> None:
    api_key = profile.get("api_key")
    profile["has_api_key"] = bool(api_key)
    profile["api_key"] = mask_secret(api_key)


def public_llm_profile(profile: dict[str, Any], profile_id: str) -> dict[str, Any]:
    public = default_llm_profile(profile_id)
    for key in LLM_PROFILE_SETTING_KEYS:
        if key in profile:
            public[key] = profile[key]
    return public


def upgrade_llm_profiles(settings: dict[str, Any], payload: dict[str, Any]) -> None:
    llm = settings.setdefault("llm", {})
    incoming_llm = payload.get("llm") if isinstance(payload.get("llm"), dict) else {}
    llm.setdefault("connection", default_llm_connection())
    incoming_connection = (
        incoming_llm.get("connection")
        if isinstance(incoming_llm.get("connection"), dict)
        else infer_legacy_connection_payload(incoming_llm)
    )
    if isinstance(incoming_connection, dict):
        update_llm_connection(llm["connection"], incoming_connection)
    for profile_id in LLM_PROFILE_IDS:
        llm.setdefault(profile_id, default_llm_profile(profile_id))
    for profile_id in LLM_PROFILE_IDS:
        if profile_id not in incoming_llm and profile_id == "taint":
            copy_legacy_llm_to_profile(llm, llm[profile_id], profile_id)
    sync_flat_llm_from_connection(llm)


def sync_legacy_llm_to_profiles(llm: dict[str, Any]) -> None:
    for profile_id in LLM_PROFILE_IDS:
        profile = llm.setdefault(profile_id, default_llm_profile(profile_id))
        copy_legacy_llm_to_profile(llm, profile, profile_id)


def sync_flat_llm_from_profile(llm: dict[str, Any], profile_id: str) -> None:
    profile = llm.get(profile_id)
    if not isinstance(profile, dict):
        return
    for key in LLM_PROFILE_SETTING_KEYS:
        if key in profile:
            llm[key] = profile[key]
    sync_flat_llm_from_connection(llm)


def sync_flat_llm_from_connection(llm: dict[str, Any]) -> None:
    connection = llm.get("connection")
    if not isinstance(connection, dict):
        return
    for key in LLM_CONNECTION_SETTING_KEYS + ["api_key"]:
        if key in connection:
            llm[key] = connection[key]


def copy_legacy_llm_to_profile(llm: dict[str, Any], profile: dict[str, Any], profile_id: str) -> None:
    for key in LLM_PROFILE_SETTING_KEYS:
        if key in llm and llm.get(key) not in {None, ""}:
            profile[key] = llm[key]


def infer_legacy_connection_payload(llm: dict[str, Any]) -> dict[str, Any]:
    inferred: dict[str, Any] = {}
    for key in LLM_CONNECTION_SETTING_KEYS + ["api_key", "clear_api_key"]:
        if key in llm:
            inferred[key] = llm[key]
    if inferred:
        return inferred
    for profile_id in ("taint", "deep", "dependency"):
        profile = llm.get(profile_id)
        if not isinstance(profile, dict):
            continue
        for key in LLM_CONNECTION_SETTING_KEYS + ["api_key", "clear_api_key"]:
            if key in profile:
                inferred[key] = profile[key]
        if inferred:
            return inferred
    return inferred


def normalize_llm_settings(settings: dict[str, Any]) -> None:
    llm = settings.setdefault("llm", {})
    connection = llm.setdefault("connection", default_llm_connection())
    if isinstance(connection, dict):
        for key, default_value in default_llm_connection().items():
            connection.setdefault(key, default_value)
    for profile_id in LLM_PROFILE_IDS:
        profile = llm.setdefault(profile_id, default_llm_profile(profile_id))
        if isinstance(profile, dict):
            for key, default_value in default_llm_profile(profile_id).items():
                profile.setdefault(key, default_value)
            upgrade_default_prompt_if_needed(profile_id, profile)
            strip_profile_connection_fields(profile)
    sync_flat_llm_from_connection(llm)
    sync_flat_llm_from_profile(llm, "taint")


def upgrade_default_prompt_if_needed(profile_id: str, profile: dict[str, Any]) -> None:
    try:
        version = int(profile.get("prompt_version") or 0)
    except (TypeError, ValueError):
        version = 0

    legacy_sets = [
        item
        for item in (
            LEGACY_DEFAULT_PROMPTS.get(profile_id),
            LEGACY_DEFAULT_PROMPTS_V2.get(profile_id),
            LEGACY_DEFAULT_PROMPTS_V3.get(profile_id),
        )
        if item
    ]
    if any(profile_matches_prompt_set(profile, legacy) for legacy in legacy_sets):
        defaults = default_llm_profile(profile_id)
        profile["system_prompt"] = defaults["system_prompt"]
        profile["user_prompt"] = defaults["user_prompt"]
        if str(profile.get("model") or "") in LEGACY_DEFAULT_MODELS:
            profile["model"] = DEFAULT_MODEL
        profile["prompt_version"] = PROMPT_VERSION
        return

    if version >= PROMPT_VERSION:
        return

    profile.setdefault("prompt_version", version or 1)


def profile_matches_prompt_set(profile: dict[str, Any], prompt_set: dict[str, str]) -> bool:
    return all(str(profile.get(key) or "") == prompt_set[key] for key in ("system_prompt", "user_prompt"))


def strip_profile_connection_fields(profile: dict[str, Any]) -> None:
    for key in LEGACY_PROFILE_CONNECTION_KEYS:
        profile.pop(key, None)


def mask_secret(value: str | None) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:3] + "*" * max(4, len(value) - 7) + value[-4:]


def extract_plaintext_api_key(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    llm = payload.get("llm") if isinstance(payload.get("llm"), dict) else payload
    if not isinstance(llm, dict):
        return None
    connection = llm.get("connection") if isinstance(llm.get("connection"), dict) else {}
    for source in (connection, llm):
        value = str(source.get("api_key") or "").strip()
        if value:
            return value
    return None


def current_base_url(settings: dict[str, Any]) -> str:
    llm = settings.get("llm") if isinstance(settings.get("llm"), dict) else {}
    connection = llm.get("connection") if isinstance(llm.get("connection"), dict) else {}
    return str(connection.get("base_url") or llm.get("base_url") or DEFAULT_BASE_URL)


def current_api_key(settings: dict[str, Any]) -> str | None:
    llm = settings.get("llm") if isinstance(settings.get("llm"), dict) else {}
    connection = llm.get("connection") if isinstance(llm.get("connection"), dict) else {}
    value = connection.get("api_key") if "api_key" in connection else llm.get("api_key")
    return str(value).strip() if value else None


def apply_runtime_api_key(settings: dict[str, Any], api_key: str | None) -> None:
    llm = settings.setdefault("llm", {})
    connection = llm.setdefault("connection", default_llm_connection())
    connection["api_key"] = api_key
    llm["api_key"] = api_key


def settings_for_persistence(settings: dict[str, Any]) -> dict[str, Any]:
    persisted = deepcopy(settings)

    def scrub(value: object) -> None:
        if isinstance(value, dict):
            for key in ("api_key", "clear_api_key", "has_api_key"):
                value.pop(key, None)
            for child in value.values():
                scrub(child)
        elif isinstance(value, list):
            for child in value:
                scrub(child)

    scrub(persisted)
    return persisted


def llm_config_from_settings(settings: dict[str, Any], profile: str = "taint") -> LLMConfig:
    llm = settings.get("llm") or {}
    profile_data = llm.get(profile) if profile in LLM_PROFILE_IDS and isinstance(llm.get(profile), dict) else {}
    if not isinstance(profile_data, dict) or not profile_data:
        profile_data = default_llm_profile(profile if profile in LLM_PROFILE_IDS else "taint")
    connection_data = llm.get("connection") if isinstance(llm.get("connection"), dict) else {}
    legacy_connection = infer_legacy_connection_payload(llm) if isinstance(llm, dict) else {}

    def connection_value(key: str, default: Any = None) -> Any:
        for source in (connection_data, llm, legacy_connection):
            if isinstance(source, dict) and key in source:
                candidate = source.get(key)
                if key in {"enabled", "api_key"}:
                    return candidate
                if candidate not in {None, ""}:
                    return candidate
        return default

    def profile_value(key: str, default: Any = None) -> Any:
        if isinstance(profile_data, dict) and key in profile_data:
            candidate = profile_data.get(key)
            if candidate not in {None, ""}:
                return candidate
        if profile == "taint" and key in llm and llm.get(key) not in {None, ""}:
            return llm.get(key)
        return llm.get(key, default)

    return LLMConfig(
        enabled=bool(connection_value("enabled", False)),
        provider=str(connection_value("provider", "openai-compatible") or "openai-compatible"),
        model=str(profile_value("model", DEFAULT_MODEL) or DEFAULT_MODEL),
        base_url=str(connection_value("base_url", DEFAULT_BASE_URL) or DEFAULT_BASE_URL),
        api_key=connection_value("api_key"),
        api_key_env=str(connection_value("api_key_env", "AUDITFORGE_LLM_API_KEY") or "AUDITFORGE_LLM_API_KEY"),
        response_file=str(connection_value("response_file", "") or "") or None,
        timeout_seconds=int(connection_value("timeout_seconds", 60) or 60),
        max_candidates=int(connection_value("max_candidates", 200) or 200),
        concurrency=int(connection_value("concurrency", 3) or 3),
        system_prompt=str(profile_value("system_prompt", None) or "") or None,
        user_prompt=str(profile_value("user_prompt", None) or "") or None,
    )


def sandbox_concurrency_from_settings(settings: dict[str, Any], default: int = 3) -> int:
    """Read independent sandbox capacity, falling back to legacy LLM concurrency."""

    llm = settings.get("llm") if isinstance(settings.get("llm"), dict) else {}
    connection = llm.get("connection") if isinstance(llm.get("connection"), dict) else {}
    value = connection.get("sandbox_concurrency")
    if value in {None, ""}:
        value = llm.get("sandbox_concurrency")
    if value in {None, ""}:
        value = connection.get("concurrency", llm.get("concurrency", default))
    try:
        return max(1, min(12, int(value)))
    except (TypeError, ValueError):
        return max(1, min(12, int(default)))
