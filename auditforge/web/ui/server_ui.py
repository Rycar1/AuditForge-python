"""Server-side presentation layer for the AuditForge web interface.

The HTTP module re-exports ``__all__`` for backward compatibility and injects
six data-access callbacks after its initialization. Those adapters are the only
boundary back into run persistence and progress normalization;
HTML/CSS/JavaScript generation stays in this file.
"""

from __future__ import annotations

import html
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ...analysis.project_inventory import inventory_summary
from ...core.settings import DEFAULT_LANGUAGE, default_settings, load_workspace_settings, public_settings
from ...core.snippets import candidate_flow_nodes, code_window, format_anchor
from ...reporting.report import (
    confidence_label,
    metric_label,
    origin_label,
    render_declarative_validation_html,
    severity_tag_class,
    status_label,
    vuln_label,
)
from ...reporting.result_sections import has_runtime_negative_evidence
from ...reporting.store import read_dashboard_detail
from ..web_security import configured_repo_roots
from . import ui_pages, ui_run_pages, ui_settings, ui_shell, ui_theme


@dataclass(frozen=True)
class _Backend:
    load_runs: Callable[[Path], list[dict]]
    load_triage_notes: Callable[[Path], dict]
    read_json_file: Callable[[Path, Any], Any]
    run_workspace_path: Callable[[Path, dict], Path]
    int_value: Callable[[Any], int]
    normalize_progress: Callable[[object, str, bool], dict]
    confirmed_verification_statuses: set[str]
    max_upload_bytes: int
    max_zip_uncompressed_bytes: int
    triage_status_options: dict[str, str]


_BACKEND: _Backend | None = None


def configure_backend(
    *,
    load_runs: Callable[[Path], list[dict]],
    load_triage_notes: Callable[[Path], dict],
    read_json_file: Callable[[Path, Any], Any],
    run_workspace_path: Callable[[Path, dict], Path],
    int_value: Callable[[Any], int],
    normalize_progress: Callable[[object, str, bool], dict],
    confirmed_verification_statuses: set[str],
    max_upload_bytes: int,
    max_zip_uncompressed_bytes: int,
    triage_status_options: dict[str, str],
) -> None:
    global _BACKEND
    _BACKEND = _Backend(
        load_runs=load_runs,
        load_triage_notes=load_triage_notes,
        read_json_file=read_json_file,
        run_workspace_path=run_workspace_path,
        int_value=int_value,
        normalize_progress=normalize_progress,
        confirmed_verification_statuses=confirmed_verification_statuses,
        max_upload_bytes=max_upload_bytes,
        max_zip_uncompressed_bytes=max_zip_uncompressed_bytes,
        triage_status_options=triage_status_options,
    )


def _backend() -> _Backend:
    if _BACKEND is None:
        raise RuntimeError("server UI backend is not configured")
    return _BACKEND


def _server_load_runs(workspace: Path) -> list[dict]:
    return _backend().load_runs(workspace)


def _server_load_triage_notes(run_workspace: Path) -> dict:
    return _backend().load_triage_notes(run_workspace)


def _server_read_json_file(path: Path, default: Any) -> Any:
    return _backend().read_json_file(path, default)


def _server_run_workspace_path(workspace: Path, run: dict) -> Path:
    return _backend().run_workspace_path(workspace, run)


def _server_int_value(value: Any) -> int:
    return _backend().int_value(value)


def _server_normalize_progress(progress: object, verify: str, dependency_scan: bool = False) -> dict:
    return _backend().normalize_progress(progress, verify, dependency_scan)


__all__ = [
    "SEVERITY_LEVELS",
    "SEVERITY_LABELS",
    "SEVERITY_COLORS",
    "UI_TRANSLATIONS",
    "ui_language",
    "translate_title",
    "build_home_overview",
    "load_run_candidates",
    "load_run_dependency_findings",
    "dependency_finding_severity",
    "dependency_stats_severity_counts",
    "count_confirmed_results",
    "count_confirmed_result_types",
    "count_sandbox_reviews",
    "load_run_verification_results",
    "candidate_origin",
    "candidate_severity",
    "render_severity_cards",
    "render_bar_chart",
    "render_pie_chart",
    "render_vuln_distribution",
    "APP_CSS",
    "SCAN_SCRIPT",
    "RUN_PROGRESS_SCRIPT",
    "RUN_DELETE_SCRIPT",
    "RUN_CANCEL_SCRIPT",
    "CANDIDATE_FILTER_SCRIPT",
    "FINDING_DRAWER_SCRIPT",
    "TRIAGE_SCRIPT",
    "LOGS_SCRIPT",
    "render_login_page",
    "render_home_page",
    "render_app_shell",
    "render_i18n_script",
    "render_sidebar",
    "render_sidebar_run_link",
    "render_page_head",
    "render_overview_page",
    "render_scan_page",
    "render_scan_form",
    "render_history_page",
    "render_logs_page",
    "render_delete_run_button",
    "render_run_row",
    "render_run_detail_page",
    "render_scan_diagnostics_panel",
    "diagnostics_stage_payload",
    "diagnostics_status",
    "diagnostics_metric_rows",
    "prompt_snapshot_rows",
    "diagnostics_notes",
    "render_diagnostics_card",
    "render_run_status_page",
    "partition_candidate_rows",
    "default_result_partition",
    "render_result_partition_tabs",
    "render_result_tab",
    "render_project_inventory_panel",
    "render_inventory_language_row",
    "render_result_partitions",
    "render_result_tab_panel",
    "render_dependency_result_zone",
    "render_candidate_result_zone",
    "render_dependency_detail_section",
    "render_dependency_item",
    "render_scan_progress_panel",
    "render_progress_stage",
    "progress_stage_status_label",
    "format_time",
    "render_dashboard",
    "render_settings_page",
    "render_llm_connection_settings",
    "render_llm_profile_settings",
    "render_language_settings",
    "render_cli_settings",
    "render_metric",
    "render_card",
    "render_triage_box",
    "triage_status_label",
    "triage_status_class",
    "render_verification_block",
    "render_sandbox_entry",
    "render_flow_html",
    "render_edge",
    "render_flow_node",
    "render_code_window",
    "flow_search_text",
    "step_kind_label",
    "role_label",
    "severity_tag_class_for_role",
    "dependency_severity_label",
    "dependency_severity_tag_class",
]


SEVERITY_LEVELS = ["critical", "high", "medium", "low"]
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}
SEVERITY_COLORS = {
    "critical": "#8b1e1e",
    "high": "#b45309",
    "medium": "#2457a6",
    "low": "#0d7f6e",
}

UI_TRANSLATIONS = {
    "en-US": {
        "AI 白盒审计平台": "AI White-box Audit Platform",
        "平台导航": "Platform navigation",
        "概况总览": "Overview",
        "新建扫描": "New Scan",
        "扫描历史": "Scan History",
        "全部扫描任务": "All scan tasks",
        "设置": "Settings",
        "运行日志": "Runtime Logs",
        "实时查看服务端运行日志，支持按级别和文本筛选。清屏只影响当前浏览器。": "View live server logs with level and text filters. Clear only affects this browser.",
        "日志级别": "Log level",
        "搜索日志": "Search logs",
        "暂停": "Pause",
        "继续": "Resume",
        "清屏": "Clear view",
        "等待日志数据…": "Waiting for log data…",
        "暂无扫描任务": "No scan tasks",
        "已完成": "Completed",
        "扫描中": "Running",
        "失败": "Failed",
        "候选": "Candidates",
        "依赖": "Dependencies",
        "依赖风险": "Dependency risks",
        "代码": "Code",
        "语言": "Languages",
        "只生成候选": "Candidates only",
        "safe 验证": "Safe verification",
        "LLM 深度验证": "LLM deep verification",
        "候选结果按风险等级聚合；未动态复现的候选不会被当作已确认漏洞。": "Candidate results are grouped by risk level; unverified candidates are not treated as confirmed vulnerabilities.",
        "代码候选与依赖风险按等级聚合；未动态复现的候选不会被当作已确认漏洞。": "Code candidates and dependency risks are grouped by severity; unverified candidates are not treated as confirmed vulnerabilities.",
        "查看历史": "View history",
        "扫描次数": "Scans",
        "风险总数": "Total risks",
        "候选总数": "Total candidates",
        "候选漏洞": "Candidate vulnerabilities",
        "依赖漏洞": "Dependency vulnerabilities",
        "已确认": "Confirmed",
        "确认合计": "Confirmed total",
        "运行确认": "Runtime confirmed",
        "二次确认": "Secondary confirmed",
        "严重": "Critical",
        "高危": "High",
        "中危": "Medium",
        "低危": "Low",
        "漏洞等级条形图": "Risk level bar chart",
        "漏洞等级占比": "Risk level share",
        "漏洞类型分布": "Vulnerability type distribution",
        "平台状态": "Platform status",
        "LLM 候选": "LLM candidates",
        "运行中": "Running",
        "等待中": "Pending",
        "进行中": "Running",
        "已跳过": "Skipped",
        "扫描阶段": "Scan stage",
        "首次候选生成": "Initial candidate generation",
        "LLM 依赖风险扫描": "LLM dependency risk scan",
        "二次深入验证": "Deep verification",
        "safe 受控验证": "Safe controlled verification",
        "二次验证": "Secondary verification",
        "最近扫描": "Recent scans",
        "完整列表已移到扫描历史页面，侧栏也可以直接展开进入任务。": "The full list is available in Scan History; the sidebar can also expand directly into a task.",
        "上传 zip 或填写本地路径；扫描完成后会自动进入本次任务详情。": "Upload a ZIP or enter a local path; after the scan completes, the task detail opens automatically.",
        "查看扫描历史": "View scan history",
        "配置 LLM": "Configure LLM",
        "扫描任务": "Scan task",
        "候选路径会先进入验证队列，只有复现成功的结果才进入正式漏洞报告。": "Candidate paths enter the verification queue first; only successfully reproduced results go into the formal report.",
        "扫描名称": "Scan name",
        "代码来源": "Code source",
        "本地路径": "Local path",
        "上传 ZIP": "Upload ZIP",
        "代码仓库路径": "Repository path",
        "ZIP 代码包": "ZIP source package",
        "验证模式": "Verification mode",
        "目标 URL": "Target URL",
        "LLM 二次深入验证（容器沙箱）": "LLM deep verification (container sandbox)",
        "使用 LLM 候选补全": "Use LLM candidate completion",
        "使用 LLM 依赖风险扫描": "Use LLM dependency risk scan",
        "二次深入验证会读取设置中的 LLM 配置，让模型生成安全测试，并在无网络、只读根文件系统、无仓库挂载的容器级 Python 沙箱中验证代码片段行为。": "Deep verification reads the LLM settings, asks the model to generate safe tests, and validates snippet behavior in a networkless, read-only container Python sandbox without mounting the repository.",
        "开始扫描": "Start scan",
        "执行策略": "Execution policy",
        "默认模式只生成候选路径；safe 验证只执行受控、非破坏性的复现动作。": "Default mode only generates candidate paths; safe verification only performs controlled, non-destructive checks.",
        "每次扫描都是独立任务；点击进入详情查看候选路径、验证结果和报告。": "Each scan is an independent task. Open a task to view candidate paths, verification results, and reports.",
        "暂无扫描历史。": "No scan history.",
        "进入详情": "Open details",
        "查看状态": "View status",
        "HTML 报告": "HTML report",
        "Markdown": "Markdown",
        "Markdown 报告": "Markdown report",
        "证据包": "Evidence bundle",
        "导出证据包": "Export evidence bundle",
        "删除": "Delete",
        "删除中...": "Deleting...",
        "删除失败": "Delete failed",
        "读取进度失败": "Failed to read progress",
        "扫描失败": "Scan failed",
        "停止任务失败": "Failed to stop task",
        "停止中...": "Stopping...",
        "确认停止扫描任务？已生成的部分制品可能不完整。": "Stop this scan? Generated artifacts may be incomplete.",
        "确认删除扫描任务": "Delete scan task",
        "该操作会删除本平台生成的报告和工作区文件，不会删除外部源码目录。": "This removes reports and workspace files generated by this platform, but does not delete external source directories.",
        "任务详情": "Task details",
        "运行目标": "Runtime target",
        "项目盘点": "Project inventory",
        "扫描指标": "Scan metrics",
        "报告规则": "Report rules",
        "静态结果只进入候选队列。": "Static results only enter the candidate queue.",
        "正式漏洞必须绑定复现证据。": "Formal findings must include reproduction evidence.",
        "safe verifier 只执行非破坏性请求。": "The safe verifier only sends non-destructive requests.",
        "已确认漏洞": "Confirmed vulnerabilities",
        "二次确认漏洞": "Secondary confirmed",
        "组件/CVE 风险候选": "Component/CVE risk candidates",
        "运行时复现定案": "Confirmed by runtime reproduction",
        "容器沙箱或二次复核通过": "Passed container sandbox or secondary review",
        "等待验证的代码路径": "Code paths awaiting verification",
        "搜索候选": "Search candidates",
        "全部类型": "All types",
        "全部状态": "All statuses",
        "未运行": "Not run",
        "需人工验证": "Needs manual review",
        "验证受阻": "Blocked",
        "误报": "False positive",
        "未复现": "Not reproducible",
        "容器沙箱验证通过": "Container sandbox passed",
        "输入点": "Source",
        "危险操作": "Sink",
        "传播节点": "Flow step",
        "数据流向图": "Data flow graph",
        "命中行已高亮，显示上下文源码": "Matched lines are highlighted with source context",
        "人工复核": "Manual triage",
        "处置状态": "Disposition",
        "复核备注": "Triage note",
        "保存复核": "Save triage",
        "待复核": "Needs review",
        "人工确认": "Manually confirmed",
        "标记误报": "Marked false positive",
        "修复中": "Fixing",
        "已修复": "Fixed",
        "记录人工判断、复现条件、误报原因或修复进展": "Record manual judgment, reproduction conditions, false-positive reason, or fix progress",
        "正在保存...": "Saving...",
        "依赖风险扫描": "Dependency risk scan",
        "已解析": "Parsed",
        "个依赖清单": "dependency manifests",
        "个依赖": "dependencies",
        "生成": "Generated",
        "条组件风险候选": "component risk candidates",
        "分别配置污点候选、依赖审计与二次审计提示词；API Key 只保存在当前工作区本地设置文件。": "Configure taint candidate, dependency audit, and secondary audit prompts separately. API keys are stored only in the local workspace settings file.",
        "统一维护 LLM 连接参数，并分别配置污点候选、依赖审计与二次审计的模型和提示词。": "Maintain one shared LLM connection, while configuring models and prompts separately for taint, dependency, and secondary audits.",
        "设置分类": "Settings categories",
        "LLM 配置": "LLM settings",
        "系统配置": "System settings",
        "LLM 详细设置": "LLM details",
        "全局连接": "Shared connection",
        "系统详细设置": "System details",
        "API Base URL、API Key、Provider、环境变量和输出数量为全局连接配置；每个审计阶段只单独维护模型和提示词。": "API Base URL, API key, provider, environment variable, and output limits are shared connection settings. Each audit stage only keeps its own model and prompts.",
        "配置平台界面语言和本地 CLI 使用方式。": "Configure the platform interface language and local CLI usage.",
        "界面语言": "Interface language",
        "选择 Web UI 的显示语言。默认使用中文，保存后刷新页面生效。": "Choose the Web UI display language. Chinese is the default; save and refresh to apply.",
        "中文": "Chinese",
        "English": "English",
        "LLM 审计配置": "LLM audit configuration",
        "污点分析 LLM 使用多个专业 Agent 并行补充 source-to-sink 候选路径；依赖审计只单独配置提示词，连接参数复用污点分析 LLM；二次审计 LLM 用于生成容器沙箱测试并复核候选。": "The taint analysis LLM uses parallel specialist agents to complement source-to-sink candidates. Dependency audit has separate prompts but reuses the taint LLM connection. Secondary audit generates container sandbox tests and reviews candidates.",
        "API key 会保存在当前扫描工作区的本地设置文件中；报告和 Dashboard 快照不会输出明文 key。留空表示不修改已有 key。": "API keys are stored in the current workspace settings file. Reports and dashboard snapshots do not output plaintext keys. Leave blank to keep the existing key.",
        "所有 LLM 审计阶段共用 Provider、API Base URL、API Key、环境变量、Fixture 响应文件和输出数量限制。": "All LLM audit stages share provider, API Base URL, API key, environment variable, fixture response file, and output limits.",
        "污点分析 LLM": "Taint analysis LLM",
        "使用数据流与注入、认证授权、SSRF 与 XSS 专业 Agent 并行补充候选路径。": "Uses parallel specialist agents for data flow and injection, authentication and authorization, SSRF, and XSS candidate completion.",
        "依赖审计 LLM": "Dependency audit LLM",
        "用于 requirements.txt、pom.xml、package.json、go.mod 等依赖清单的 CVE/高危组件候选分析。": "Used to analyze requirements.txt, pom.xml, package.json, go.mod, and other manifests for CVE/high-risk component candidates.",
        "二次审计 LLM": "Secondary audit LLM",
        "用于 LLM 二次深入验证，在容器级隔离沙箱中生成安全测试并复核候选是否成立。": "Used for LLM deep verification: generate safe tests in a container-isolated sandbox and review whether candidates hold.",
        "复用全局连接": "Uses shared connection",
        "该阶段可以使用与其他阶段不同的模型；连接仍复用全局 API 配置。": "This stage can use a different model from other stages; the API connection still uses the shared settings.",
        "启用": "Enable",
        "模型": "Model",
        "环境变量名": "Environment variable",
        "最大候选 / 验证数量": "Max candidates / verifications",
        "清除已保存的 API Key": "Clear saved API key",
        "Fixture 响应文件": "Fixture response file",
        "仅 provider 选择 fixture 时使用，用于离线回归测试。": "Used only when provider is fixture, for offline regression tests.",
        "约束模型角色、输出格式和安全边界。": "Constrains model role, output format, and safety boundaries.",
        "任务 Prompt": "Task Prompt",
        "定义该阶段如何判断候选、污点传播或二次审计结论。": "Defines how this stage judges candidates, taint propagation, or secondary audit conclusions.",
        "恢复默认提示词": "Restore default prompt",
        "恢复默认模型和提示词": "Restore default model and prompts",
        "发送测试消息": "Send test message",
        "复用污点分析连接": "Reuse taint analysis connection",
        "依赖审计复用污点分析 LLM 的 Provider、模型、API Base URL、API Key、环境变量、Fixture 响应文件和输出数量限制；这里只维护依赖审计专用提示词。": "Dependency audit reuses the taint analysis LLM provider, model, API base URL, API key, environment variable, fixture response file, and output limit. Only dependency-specific prompts are edited here.",
        "约束依赖组件安全分析器的角色、输出格式和安全边界。": "Constrains the role, output format, and safety boundaries of the dependency component analyzer.",
        "定义如何基于依赖清单判断 CVE、高危版本或过旧组件候选。": "Defines how to judge CVE, high-risk version, or outdated component candidates from dependency manifests.",
        "保存设置": "Save settings",
        "恢复表单": "Reset form",
        "CLI 使用": "CLI usage",
        "保存后可以运行：": "After saving, you can run:",
        "保存后可以在命令行复用当前工作区的 LLM 和系统设置。": "After saving, the command line can reuse the current workspace LLM and system settings.",
        "已保存": "Saved",
        "保存中...": "Saving...",
        "保存失败": "Save failed",
        "正在发送测试消息...": "Sending test message...",
        "测试失败": "Test failed",
        "测试成功": "Test succeeded",
        "错误代码": "Error code",
        "处理建议": "Action",
        "诊断编号": "Reference",
        "配置项": "Field",
        "重试提示": "Retry",
        "此错误通常可以重试。": "This error can usually be retried.",
        "请求失败。": "Request failed.",
        "无法读取服务响应。": "Could not read the service response.",
        "服务返回了空响应。": "The service returned an empty response.",
        "服务返回了无法识别的响应。": "The service returned an unrecognized response.",
        "无法连接服务。": "Could not connect to the service.",
        "扫描任务已创建，但服务未返回任务标识。": "The scan was created, but the service did not return a task identifier.",
        "请打开任务档案确认任务状态，或重新创建扫描。": "Open the task archive to confirm its status, or create the scan again.",
        "进度响应缺少任务信息。": "The progress response is missing task data.",
        "请根据诊断编号查看运行日志，修正环境或配置问题后重试。": "Use the reference to inspect runtime logs, correct the environment or configuration, and retry.",
        "请重新登录后重试。": "Sign in again and retry.",
        "请刷新页面或重新登录后重试。": "Refresh the page or sign in again, then retry.",
        "请返回任务列表并刷新页面。": "Return to the task list and refresh it.",
        "请减小请求或上传文件的体积后重试。": "Reduce the request or upload size, then retry.",
        "请稍候几秒后重试。": "Wait a few seconds and retry.",
        "请稍后重试；若问题持续，请根据诊断编号查看运行日志。": "Retry later. If the problem continues, use the reference to inspect runtime logs.",
        "请检查输入内容并重试。": "Check the input and retry.",
        "请刷新页面；若问题持续，请检查客户端版本。": "Refresh the page. If the problem continues, check the client version.",
        "请刷新任务状态后再试。": "Refresh the task status and retry.",
        "请检查服务是否可用和网络连接，然后重试。": "Check that the service and network connection are available, then retry.",
        "请刷新页面后重试；若问题持续，请查看运行日志。": "Refresh the page and retry. If the problem continues, inspect runtime logs.",
        "读取日志失败": "Failed to read logs",
        "日志响应缺少列表数据。": "The log response is missing list data.",
        "已连接，等待新日志": "Connected, waiting for new logs",
        "日志轮询已暂停": "Log polling paused",
        "日志轮询已继续": "Log polling resumed",
        "已清空当前浏览器中的日志；服务端日志未删除": "Cleared logs in this browser; server logs were not deleted",
        "任务执行失败。": "Task execution failed.",
        "未保存 key；也可以使用环境变量。": "No key saved; an environment variable can also be used.",
        "留空表示不修改。": "Leave blank to keep unchanged.",
        "示例：": "Example:",
        "当前：": "Current:",
        "已配置": "configured",
        "未启用": "disabled",
        "暂无候选类型数据。": "No candidate type data.",
        "暂无依赖风险候选；建议继续用 OSV/NVD 或企业 SCA 工具做权威复核。": "No dependency risk candidates. Continue to verify with OSV/NVD or an enterprise SCA tool.",
        "暂无静态候选漏洞。": "No static candidate vulnerabilities.",
        "暂无已确认漏洞。": "No confirmed vulnerabilities.",
        "暂无二次确认漏洞。": "No secondary confirmed vulnerabilities.",
    }
}


ERROR_TRANSLATIONS = {
    "en-US": {
        "AUTH_REQUIRED": {
            "message": "Sign in to continue.",
            "action": "Sign in again, then retry this action.",
        },
        "AUTH_INVALID_TOKEN": {
            "message": "The access token is invalid or has expired.",
            "action": "Sign in again with the access token generated for this workspace.",
        },
        "REQUEST_HOST_REJECTED": {
            "message": "The request host is not trusted.",
            "action": "Open the Dashboard using the address shown in the startup logs.",
        },
        "REQUEST_ORIGIN_REJECTED": {
            "message": "The request origin failed the security check.",
            "action": "Refresh this page and retry; do not call this endpoint cross-site.",
        },
        "REQUEST_CSRF_REJECTED": {
            "message": "The page session has expired and the security check failed.",
            "action": "Refresh the page or sign in again, then retry.",
        },
        "REQUEST_INVALID": {
            "message": "The request is incomplete or incorrectly formatted.",
            "action": "Check the input and retry.",
        },
        "REQUEST_BODY_TOO_LARGE": {
            "message": "The request exceeds the allowed size.",
            "action": "Reduce the request or upload size, then retry.",
        },
        "METHOD_NOT_ALLOWED": {
            "message": "This endpoint does not support the request method.",
            "action": "Refresh the page. If the problem continues, check the client version.",
        },
        "RESOURCE_NOT_FOUND": {
            "message": "The requested resource does not exist or has been deleted.",
            "action": "Return to the previous page and refresh the task list.",
        },
        "UPLOAD_BUSY": {
            "message": "Too many uploads are in progress to accept another file.",
            "action": "Wait a few seconds and retry.",
        },
        "UPLOAD_INVALID": {
            "message": "The upload could not be parsed.",
            "action": "Confirm the file is a valid ZIP source package and upload it again.",
        },
        "UPLOAD_TOO_LARGE": {
            "message": "The uploaded file exceeds the size limit.",
            "action": "Remove build artifacts or dependency directories, then package it again.",
        },
        "ZIP_UNSAFE": {
            "message": "The archive contains an unsafe or abnormal file structure.",
            "action": "Repackage the source without links, path traversal, or an abnormal compression ratio.",
        },
        "REPO_PATH_INVALID": {
            "message": "The repository path is invalid or outside the allowed roots.",
            "action": "Choose an existing repository under an authorized root.",
        },
        "SCAN_CONCURRENCY_LIMIT": {
            "message": "Several scans are already running.",
            "action": "Wait for an existing task to finish, or stop a task you no longer need.",
        },
        "SCAN_WORKER_START_FAILED": {
            "message": "The scan process could not start.",
            "action": "Use the reference to inspect logs, resolve resource or environment configuration issues, and retry.",
        },
        "SCAN_WORKER_EXITED": {
            "message": "The scan process exited unexpectedly before the task completed.",
            "action": "Use the reference to inspect logs, check resources and the runtime environment, then scan again.",
        },
        "SCAN_CANCELLED": {
            "message": "The scan was cancelled.",
            "action": "Create a new scan to continue.",
        },
        "SCAN_FAILED": {
            "message": "The scan failed.",
            "action": "Use the reference to inspect logs, correct environment or configuration issues, and retry.",
        },
        "RUN_NOT_FOUND": {
            "message": "The scan task does not exist or has been deleted.",
            "action": "Return to the task list and refresh the page.",
        },
        "RUN_STATE_CONFLICT": {
            "message": "The task's current state does not allow this action.",
            "action": "Refresh the task status and retry.",
        },
        "RUN_UPDATE_FAILED": {
            "message": "The task information could not be updated.",
            "action": "Refresh the page and retry. If the problem continues, inspect diagnostic logs.",
        },
        "SETTINGS_INVALID": {
            "message": "The settings are invalid and were not saved.",
            "action": "Check the highlighted settings and retry.",
        },
        "LLM_KEY_MISSING": {
            "message": "No usable LLM API key is configured.",
            "action": "Enter a key in model settings or configure the corresponding environment variable.",
        },
        "LLM_ENDPOINT_INVALID": {
            "message": "The LLM service URL is invalid or not allowed.",
            "action": "Check the service URL, protocol, and permitted network range.",
        },
        "LLM_AUTH_FAILED": {
            "message": "The LLM service rejected authentication.",
            "action": "Check the API key, model permissions, and account status.",
        },
        "LLM_RATE_LIMITED": {
            "message": "The LLM service is receiving too many requests.",
            "action": "Wait and retry, or reduce concurrency.",
        },
        "LLM_TIMEOUT": {
            "message": "The LLM service timed out.",
            "action": "Check the network and service status, or increase the timeout.",
        },
        "LLM_PROVIDER_FAILED": {
            "message": "The LLM service is temporarily unavailable.",
            "action": "Check the provider status and model configuration, then retry.",
        },
        "SANDBOX_UNAVAILABLE": {
            "message": "The isolated verification environment is unavailable.",
            "action": "Check the container runtime and sandbox image, then retry.",
        },
        "SANDBOX_TIMEOUT": {
            "message": "The isolated verification exceeded its time limit.",
            "action": "Check the target service or reduce verification concurrency, then retry.",
        },
        "SERVER_BUSY": {
            "message": "The service is handling too many requests.",
            "action": "Wait a few seconds and retry.",
        },
        "SERVER_START_FAILED": {
            "message": "The Dashboard could not start.",
            "action": "Check port availability, directory permissions, and service configuration.",
        },
        "INTERNAL_ERROR": {
            "message": "An internal error occurred while processing the request.",
            "action": "Use the reference to inspect logs. If the problem continues, restart the service and retry.",
        },
    }
}


def ui_language(workspace: Path) -> str:
    settings = load_workspace_settings(workspace)
    language = str(settings.get("language") or DEFAULT_LANGUAGE)
    return language if language in {"zh-CN", "en-US"} else DEFAULT_LANGUAGE


def translate_title(title: str, language: str) -> str:
    if language == DEFAULT_LANGUAGE:
        return title
    return UI_TRANSLATIONS.get(language, {}).get(title, title)


def build_home_overview(workspace: Path, runs: list[dict]) -> dict:
    severity_counts = {level: 0 for level in SEVERITY_LEVELS}
    vuln_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    confirmed = 0
    llm_candidates = 0
    total_candidates = 0
    dependency_findings_total = 0
    completed = 0
    runtime_confirmed = 0
    sandbox_reviewed = 0

    for run in runs:
        status = str(run.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        stats = run.get("stats") or {}
        if status == "completed":
            completed += 1
        candidates = load_run_candidates(workspace, run)
        total_candidates += len(candidates)
        llm_candidates += sum(1 for candidate in candidates if candidate_origin(candidate) == "llm")
        if not candidates and isinstance(stats, dict) and _server_run_workspace_path(workspace, run).exists():
            total_candidates += int(stats.get("candidates") or 0)
            llm_candidates += int(stats.get("llm_candidates") or 0)
        for candidate in candidates:
            vuln_class = str(candidate.get("vuln_class") or candidate.get("vulnClass") or "unknown")
            confidence = str(candidate.get("confidence") or "low")
            level = candidate_severity(vuln_class, confidence)
            severity_counts[level] += 1
            vuln_counts[vuln_class] = vuln_counts.get(vuln_class, 0) + 1
        dependency_findings = load_run_dependency_findings(workspace, run)
        if dependency_findings:
            dependency_findings_total += len(dependency_findings)
            vuln_counts["dependency"] = vuln_counts.get("dependency", 0) + len(dependency_findings)
            for finding in dependency_findings:
                if not isinstance(finding, dict):
                    continue
                level = dependency_finding_severity(str(finding.get("severity") or "unknown"))
                severity_counts[level] += 1
        elif isinstance(stats, dict):
            fallback_count = int(stats.get("dependency_findings") or 0)
            if fallback_count:
                dependency_findings_total += fallback_count
                vuln_counts["dependency"] = vuln_counts.get("dependency", 0) + fallback_count
                for level, count in dependency_stats_severity_counts(stats).items():
                    severity_counts[level] += count
        verification_results = load_run_verification_results(workspace, run)
        confirmed_types = count_confirmed_result_types(workspace, run, results=verification_results)
        runtime_confirmed += confirmed_types.get("confirmed", 0)
        confirmed += sum(confirmed_types.values())
        sandbox_reviewed += count_sandbox_reviews(workspace, run, results=verification_results)

    return {
        "total_runs": len(runs),
        "completed": completed,
        "total_candidates": total_candidates,
        "dependency_findings": dependency_findings_total,
        "total_risks": total_candidates + dependency_findings_total,
        "llm_candidates": llm_candidates,
        "runtime_confirmed": runtime_confirmed,
        "sandbox_reviewed": sandbox_reviewed,
        "confirmed": confirmed,
        "severity_counts": severity_counts,
        "vuln_counts": vuln_counts,
        "status_counts": status_counts,
    }


def load_run_candidates(workspace: Path, run: dict) -> list[dict]:
    path = _server_run_workspace_path(workspace, run) / "trace_candidates.json"
    candidates = _server_read_json_file(path, [])
    return candidates if isinstance(candidates, list) else []


def load_run_dependency_findings(workspace: Path, run: dict) -> list[dict]:
    run_workspace = _server_run_workspace_path(workspace, run)
    findings = _server_read_json_file(run_workspace / "dependency_findings.json", [])
    if isinstance(findings, list):
        return [item for item in findings if isinstance(item, dict)]
    if (run_workspace / "auditforge.db").exists():
        try:
            data = read_dashboard_detail(run_workspace)
            artifacts = data.get("artifacts") if isinstance(data, dict) else {}
            findings = artifacts.get("dependency_findings") if isinstance(artifacts, dict) else None
            if isinstance(findings, list):
                return [item for item in findings if isinstance(item, dict)]
        except Exception:  # noqa: BLE001 - overview should tolerate old or partial artifacts
            pass
    section = _server_read_json_file(run_workspace / "result_sections" / "dependency_vulnerabilities.json", {})
    items = section.get("items") if isinstance(section, dict) else None
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def dependency_finding_severity(severity: str) -> str:
    normalized = severity.lower()
    if normalized in SEVERITY_LEVELS:
        return normalized
    return "low"


def dependency_stats_severity_counts(stats: dict) -> dict[str, int]:
    counts = {level: _server_int_value(stats.get(f"dependency_{level}")) for level in SEVERITY_LEVELS}
    known_total = sum(counts.values())
    fallback_total = _server_int_value(stats.get("dependency_findings"))
    if fallback_total > known_total:
        counts["low"] += fallback_total - known_total
    return counts


def count_confirmed_results(workspace: Path, run: dict) -> int:
    return sum(count_confirmed_result_types(workspace, run).values())


def count_confirmed_result_types(workspace: Path, run: dict, *, results: list[dict] | None = None) -> dict[str, int]:
    counts = {status: 0 for status in _backend().confirmed_verification_statuses}
    if results is None:
        results = load_run_verification_results(workspace, run)
    if results:
        for item in results:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "")
            if status in counts:
                counts[status] += 1
        return counts
    return counts


def count_sandbox_reviews(workspace: Path, run: dict, *, results: list[dict] | None = None) -> int:
    if results is None:
        results = load_run_verification_results(workspace, run)
    if results:
        return sum(
            1 for item in results if isinstance(item, dict) and str(item.get("status") or "") in {"sandbox_executed", "sandbox_confirmed"}
        )
    stats = run.get("stats") or {}
    if not isinstance(stats, dict):
        return 0
    return _server_int_value(stats.get("sandbox_executed")) or _server_int_value(stats.get("sandbox_confirmed"))


def load_run_verification_results(workspace: Path, run: dict) -> list[dict]:
    run_workspace = _server_run_workspace_path(workspace, run)
    path = run_workspace / "verification_results.json"
    if path.exists():
        results = _server_read_json_file(path, [])
        if isinstance(results, list):
            return [item for item in results if isinstance(item, dict)]
    if (run_workspace / "auditforge.db").exists():
        try:
            data = read_dashboard_detail(run_workspace)
            db_results = data.get("verification_results") if isinstance(data, dict) else None
            if isinstance(db_results, list):
                return [item for item in db_results if isinstance(item, dict)]
        except Exception:  # noqa: BLE001 - overview should tolerate old or partial stores
            return []
    return []


def candidate_origin(candidate: dict) -> str:
    origin = candidate.get("origin")
    if origin:
        return str(origin)
    payload = candidate.get("payload_json")
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return "deterministic"
        return str(parsed.get("origin") or "deterministic") if isinstance(parsed, dict) else "deterministic"
    return "deterministic"


def candidate_severity(vuln_class: str, confidence: str) -> str:
    vuln_class = vuln_class.lower()
    confidence = confidence.lower()
    if vuln_class in {"injection", "ssrf", "auth", "authz"}:
        if confidence == "high":
            return "critical"
        if confidence == "medium":
            return "high"
        return "medium"
    if vuln_class == "xss":
        if confidence == "high":
            return "high"
        if confidence == "medium":
            return "medium"
        return "low"
    if confidence == "high":
        return "medium"
    return "low"


def render_severity_cards(severity_counts: dict[str, int]) -> str:
    return "\n".join(
        f"""
        <div class="severity-card {level}">
          <span>{html.escape(SEVERITY_LABELS[level])}</span>
          <strong>{severity_counts.get(level, 0)}</strong>
        </div>"""
        for level in SEVERITY_LEVELS
    )


def render_bar_chart(severity_counts: dict[str, int]) -> str:
    max_count = max([severity_counts.get(level, 0) for level in SEVERITY_LEVELS] + [1])
    rows = []
    for level in SEVERITY_LEVELS:
        count = severity_counts.get(level, 0)
        width = max(3, round(count / max_count * 100)) if count else 0
        rows.append(
            f"""
            <div class="bar-row">
              <div class="bar-label">{html.escape(SEVERITY_LABELS[level])}</div>
              <div class="bar-track"><span style="width:{width}%; background:{SEVERITY_COLORS[level]}"></span></div>
              <div class="bar-value">{count}</div>
            </div>"""
        )
    return "\n".join(rows)


def render_pie_chart(severity_counts: dict[str, int]) -> str:
    total = sum(severity_counts.get(level, 0) for level in SEVERITY_LEVELS)
    if total <= 0:
        gradient = "#edf0ea"
    else:
        start = 0.0
        segments = []
        for level in SEVERITY_LEVELS:
            value = severity_counts.get(level, 0)
            end = start + (value / total * 100)
            if value:
                segments.append(f"{SEVERITY_COLORS[level]} {start:.2f}% {end:.2f}%")
            start = end
        gradient = "conic-gradient(" + ", ".join(segments) + ")" if segments else "#edf0ea"
    legend = "\n".join(
        f"""
        <div class="legend-row">
          <span class="legend-dot" style="background:{SEVERITY_COLORS[level]}"></span>
          <span>{html.escape(SEVERITY_LABELS[level])}</span>
          <strong>{severity_counts.get(level, 0)}</strong>
        </div>"""
        for level in SEVERITY_LEVELS
    )
    return f"""
    <div class="pie-wrap">
      <div class="pie" style="background:{gradient}"><span>{total}</span></div>
      <div class="legend">{legend}</div>
    </div>"""


def render_vuln_distribution(vuln_counts: dict[str, int]) -> str:
    if not vuln_counts:
        return '<div class="empty compact">暂无候选类型数据。</div>'
    total = max(sum(vuln_counts.values()), 1)
    rows = []
    for vuln_class, count in sorted(vuln_counts.items(), key=lambda item: item[1], reverse=True):
        width = max(4, round(count / total * 100))
        rows.append(
            f"""
            <div class="type-row">
              <span>{html.escape(vuln_label(vuln_class))}</span>
              <div><i style="width:{width}%"></i></div>
              <strong>{count}</strong>
            </div>"""
        )
    return "\n".join(rows)


# Public compatibility constant for the greenfield forensic-console theme.
APP_CSS = (
    ui_theme.APP_CSS
    + r"""
.status[role="alert"],
.progress-detail[role="alert"],
[data-run-action-feedback] {
  max-width: 72ch;
  overflow-wrap: anywhere;
  white-space: normal;
}
.status[role="alert"], .progress-detail[role="alert"] {
  padding: 9px 11px;
  border: 1px solid #633532;
  background: var(--danger-soft);
  line-height: 1.5;
}
[data-run-action-feedback] {
  flex: 1 0 100%;
  margin-top: 2px;
  text-align: left;
}
.case-actions [data-run-action-feedback] { min-width: min(72ch, 100%); }
.validation-details { margin-top: 12px; border-top: 1px solid var(--border); }
.validation-details > summary { padding: 11px 0; color: #cbd2d5; font-size: 11px; cursor: pointer; }
.validation-runs, .validation-step-list, .validation-evidence-list { display: grid; gap: 9px; margin-top: 9px; }
.validation-run, .validation-step, .validation-evidence-item {
  min-width: 0;
  padding: 11px;
  border: 1px solid var(--border);
  background: var(--surface-inset);
}
.validation-run-head, .validation-step-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.validation-description, .validation-summary, .validation-note, .validation-target, .validation-artifacts {
  margin: 6px 0 0;
  color: var(--muted);
  font-size: 11px;
  overflow-wrap: anywhere;
}
.validation-meta { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-top: 9px; color: var(--muted); font-size: 10px; }
.validation-section { margin-top: 12px; }
.validation-section h4 { margin: 0; font-size: 11px; }
.validation-assertions { display: grid; gap: 6px; margin: 8px 0 0; padding: 0; list-style: none; }
.validation-assertions li {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 7px 8px;
  border: 1px solid var(--border);
  background: var(--surface);
  font-size: 10px;
  overflow-wrap: anywhere;
}
.validation-assertion-true { color: var(--success); font-weight: 800; }
.validation-assertion-false, .validation-error { color: var(--danger); font-weight: 800; }
.validation-observed { margin-top: 9px; padding-top: 9px; border-top: 1px dashed var(--border); }
.validation-response-line { margin: 0; color: var(--muted); font-size: 10px; overflow-wrap: anywhere; }
.validation-response { margin-top: 8px; }
.validation-response summary { cursor: pointer; color: #cbd2d5; font-size: 10px; }
.validation-response pre, .validation-generic { margin-top: 7px; padding: 9px; max-height: 260px; overflow: auto; }
"""
)


SCAN_SCRIPT = r"""
  <script>
    const form = document.getElementById('scanForm');
    const statusText = document.getElementById('scanStatus');
    const pathRadio = document.getElementById('sourcePath');
    const uploadRadio = document.getElementById('sourceUpload');
    const repoPathField = document.getElementById('repoPathField');
    const repoZipField = document.getElementById('repoZipField');

    function t(text) {
      return window.auditforgeTranslate ? window.auditforgeTranslate(text) : text;
    }

    function syncSourceFields() {
      repoPathField.classList.toggle('hidden', !pathRadio.checked);
      repoZipField.classList.toggle('hidden', !uploadRadio.checked);
    }
    pathRadio.addEventListener('change', syncSourceFields);
    uploadRadio.addEventListener('change', syncSourceFields);
    syncSourceFields();

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      window.auditforgeSetStatus(statusText, t('正在创建扫描任务...'));
      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      try {
        const data = await window.auditforgeRequestJson('/api/scan', {
          method: 'POST',
          headers: {'Accept': 'application/json'},
          body: new FormData(form),
        }, t('扫描失败'));
        window.auditforgeSetStatus(statusText, t('任务已创建，正在进入进度页...'), 'ok');
        if (data.run && data.run.id) {
          window.location.href = `/runs/${encodeURIComponent(data.run.id)}`;
          return;
        }
        throw window.auditforgeCreateError({
          message: t('扫描任务已创建，但服务未返回任务标识。'),
          code: 'RESPONSE_INVALID',
          action: t('请打开任务档案确认任务状态，或重新创建扫描。'),
        });
      } catch (error) {
        window.auditforgeShowError(statusText, error, t('扫描失败'));
        button.disabled = false;
      }
    });
  </script>
"""


RUN_PROGRESS_SCRIPT = r"""
  <script>
    const progressPanel = document.getElementById('runProgressPanel');
    const runStatusText = document.getElementById('runStatusText');
    const progressError = document.querySelector('[data-progress-error]');
    let progressPollFailures = 0;
    let progressPollTimer = null;

    function t(text) {
      return window.auditforgeTranslate ? window.auditforgeTranslate(text) : text;
    }

    const progressStateLabels = {
      pending: t('等待中'),
      running: t('进行中'),
      completed: t('已完成'),
      skipped: t('已跳过'),
      failed: t('失败'),
    };

    function clampProgress(value) {
      const number = Number(value);
      if (!Number.isFinite(number)) return 0;
      return Math.max(0, Math.min(100, Math.round(number)));
    }

    function scheduleProgressPoll(delay) {
      if (progressPollTimer) window.clearTimeout(progressPollTimer);
      progressPollTimer = window.setTimeout(pollRunProgress, delay);
    }

    function applyProgress(run) {
      if (!progressPanel || !run) return;
      const progress = run.progress || {};
      const stages = Array.isArray(progress.stages) ? progress.stages : [];
      progressPanel.dataset.status = run.status || 'unknown';
      progressPollFailures = 0;
      if (progressError) {
        progressError.hidden = true;
        window.auditforgeSetStatus(progressError, '');
      }
      const summary = progressPanel.querySelector('[data-progress-summary]');
      const summaryDetail = progressPanel.querySelector('[data-progress-summary-detail]');
      if (summary) {
        const total = clampProgress(progress.percent);
        summary.textContent = `${total}%`;
      }
      if (summaryDetail) summaryDetail.textContent = progress.detail || '';
      if (runStatusText) {
        runStatusText.textContent = run.status === 'running' ? t('扫描中') : (run.status === 'failed' ? t('失败') : t('已完成'));
        runStatusText.dataset.runState = run.status || 'unknown';
      }
      stages.forEach((stage) => {
        const node = progressPanel.querySelector(`[data-progress-stage="${stage.id}"]`);
        if (!node) return;
        const status = progressStateLabels[stage.status] ? stage.status : 'pending';
        const percent = clampProgress(stage.percent);
        node.className = `progress-stage status-${status}`;
        const state = node.querySelector('[data-progress-state]');
        const fill = node.querySelector('[data-progress-fill]');
        const detail = node.querySelector('[data-progress-detail]');
        const title = node.querySelector('.progress-title');
        const bar = node.querySelector('[role="progressbar"]');
        const label = t(stage.label || '扫描阶段');
        if (title) title.textContent = label;
        if (state) state.textContent = progressStateLabels[status] || status;
        if (fill) fill.style.width = `${percent}%`;
        if (detail) detail.textContent = stage.detail || '';
        if (bar) {
          bar.setAttribute('aria-valuenow', String(percent));
          bar.setAttribute('aria-label', `${label} ${percent}%`);
        }
      });
      if (run.status === 'completed') {
        window.setTimeout(() => {
          window.location.href = `/runs/${encodeURIComponent(run.id)}`;
        }, 700);
      } else if (run.status === 'failed' && progressError) {
        const failure = run.failure && typeof run.failure === 'object' ? run.failure : {};
        const terminalError = window.auditforgeCreateError({
          message: run.error || t('扫描失败'),
          code: failure.code || 'SCAN_FAILED',
          action: failure.action || t('请根据诊断编号查看运行日志，修正环境或配置问题后重试。'),
          reference: failure.diagnostic_id || failure.reference || '',
          retryable: Boolean(failure.retryable),
        });
        window.auditforgeShowError(progressError, terminalError, t('扫描失败'));
      }
    }

    async function pollRunProgress() {
      if (!progressPanel || progressPanel.dataset.status !== 'running') return;
      const runId = progressPanel.dataset.runId;
      if (!runId) return;
      try {
        const data = await window.auditforgeRequestJson(`/api/runs/${encodeURIComponent(runId)}`, {
          headers: {'Accept': 'application/json'},
        }, t('读取进度失败'));
        if (!data.run || typeof data.run !== 'object') {
          throw window.auditforgeCreateError({
            message: t('进度响应缺少任务信息。'),
            code: 'RESPONSE_INVALID',
            action: t('请刷新页面后重试；若问题持续，请查看运行日志。'),
          });
        }
        applyProgress(data.run);
        if (data.run && data.run.status === 'running') {
          scheduleProgressPoll(1000);
        }
      } catch (error) {
        progressPollFailures += 1;
        const normalized = window.auditforgeShowError(progressError, error, t('读取进度失败'));
        const terminal = normalized.status === 401 || normalized.status === 403 || normalized.status === 404 || normalized.status === 421;
        if (terminal) {
          progressPanel.dataset.status = 'polling-failed';
          return;
        }
        const retryDelay = normalized.retryAfter > 0
          ? normalized.retryAfter * 1000
          : Math.min(15000, 1200 * (2 ** Math.min(progressPollFailures, 4)));
        scheduleProgressPoll(retryDelay);
      }
    }

    if (progressPanel) {
      pollRunProgress();
    }
  </script>
"""


RUN_DELETE_SCRIPT = r"""
  <script>
    function t(text) {
      return window.auditforgeTranslate ? window.auditforgeTranslate(text) : text;
    }

    document.querySelectorAll('[data-delete-run]').forEach((button) => {
      button.addEventListener('click', async (event) => {
        event.preventDefault();
        event.stopPropagation();
        const runId = button.dataset.runId;
        const runName = button.dataset.runName || runId;
        if (!runId) return;
        const confirmed = window.confirm(`${t('确认删除扫描任务')}“${runName}”？\n${t('该操作会删除本平台生成的报告和工作区文件，不会删除外部源码目录。')}`);
        if (!confirmed) return;
        const previousText = button.textContent;
        const feedback = window.auditforgeActionFeedback(button);
        if (feedback) {
          feedback.hidden = false;
          window.auditforgeSetStatus(feedback, t('删除中...'));
        }
        button.disabled = true;
        button.textContent = t('删除中...');
        try {
          const data = await window.auditforgeRequestJson(`/api/runs/${encodeURIComponent(runId)}/delete`, {
            method: 'POST',
            headers: {'Accept': 'application/json'},
          }, t('删除失败'));
          if (data.ok !== true) {
            throw window.auditforgeCreateError({
              message: t('服务返回了无法识别的响应。'),
              code: 'RESPONSE_INVALID',
              action: t('请刷新页面后重试；若问题持续，请查看运行日志。'),
            });
          }
          window.location.href = data.redirect || '/history';
        } catch (error) {
          window.auditforgeShowError(feedback, error, t('删除失败'));
          button.disabled = false;
          button.textContent = previousText;
        }
      });
    });
  </script>
"""


RUN_CANCEL_SCRIPT = r"""
  <script>
    function t(text) {
      return window.auditforgeTranslate ? window.auditforgeTranslate(text) : text;
    }

    document.querySelectorAll('[data-cancel-run]').forEach((button) => {
      button.addEventListener('click', async (event) => {
        event.preventDefault();
        const runId = button.dataset.runId;
        if (!runId) return;
        if (!window.confirm(t('确认停止扫描任务？已生成的部分制品可能不完整。'))) return;
        const previousText = button.textContent;
        const feedback = window.auditforgeActionFeedback(button);
        if (feedback) {
          feedback.hidden = false;
          window.auditforgeSetStatus(feedback, t('停止中...'));
        }
        button.disabled = true;
        button.textContent = t('停止中...');
        try {
          const data = await window.auditforgeRequestJson(`/api/runs/${encodeURIComponent(runId)}/cancel`, {
            method: 'POST',
            headers: {'Accept': 'application/json'},
          }, t('停止任务失败'));
          if (data.ok !== true) {
            throw window.auditforgeCreateError({
              message: t('服务返回了无法识别的响应。'),
              code: 'RESPONSE_INVALID',
              action: t('请刷新页面后重试；若问题持续，请查看运行日志。'),
            });
          }
          window.location.reload();
        } catch (error) {
          window.auditforgeShowError(feedback, error, t('停止任务失败'));
          button.disabled = false;
          button.textContent = previousText;
        }
      });
    });
  </script>
"""


CANDIDATE_FILTER_SCRIPT = r"""
  <script>
    const filterButtons = Array.from(document.querySelectorAll('[data-filter]'));
    const resultTabs = Array.from(document.querySelectorAll('[data-result-tab]'));
    const resultPanels = Array.from(document.querySelectorAll('[data-result-panel]'));
    const candidateToolbar = document.querySelector('[data-candidate-toolbar]');
    const searchInput = document.getElementById('candidateSearch');
    const rows = Array.from(document.querySelectorAll('.candidate-row'));
    const emptyState = document.getElementById('emptyState');
    let activeFilter = 'all';
    let activeResultTab = resultTabs.length ? (resultTabs.find((button) => button.classList.contains('active'))?.dataset.resultTab || 'candidate') : 'all';

    function activateResultTab(tabId, updateHash = true) {
      activeResultTab = tabId;
      resultTabs.forEach((button) => {
        const active = button.dataset.resultTab === tabId;
        button.classList.toggle('active', active);
        button.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      resultPanels.forEach((panel) => {
        panel.hidden = panel.dataset.resultPanel !== tabId;
        panel.classList.toggle('active', panel.dataset.resultPanel === tabId);
      });
      if (candidateToolbar) {
        candidateToolbar.hidden = resultTabs.length > 0 && tabId === 'dependency';
      }
      if (updateHash && resultTabs.length && window.history && window.history.replaceState) {
        window.history.replaceState(null, '', `#${tabId}`);
      }
      applyFilters();
    }

    function applyFilters() {
      const keyword = searchInput ? searchInput.value.trim().toLowerCase() : '';
      const activePanel = resultPanels.find((panel) => panel.dataset.resultPanel === activeResultTab);
      const activeRows = activePanel ? Array.from(activePanel.querySelectorAll('.candidate-row')) : rows;
      let visible = 0;
      let total = 0;
      rows.forEach((row) => {
        if (activePanel && !activePanel.contains(row)) {
          row.hidden = false;
          return;
        }
        total += 1;
        const byType = activeFilter === 'all' || row.dataset.vuln === activeFilter;
        const byText = !keyword || row.textContent.toLowerCase().includes(keyword);
        const show = byType && byText;
        row.hidden = !show;
        if (show) visible += 1;
      });
      if (emptyState) {
        const filtering = Boolean(keyword) || activeFilter !== 'all';
        emptyState.hidden = (resultTabs.length > 0 && activeResultTab === 'dependency') || total === 0 || visible !== 0 || !filtering;
      }
    }

    resultTabs.forEach((button) => {
      button.addEventListener('click', () => activateResultTab(button.dataset.resultTab || 'dependency'));
    });
    filterButtons.forEach((button) => {
      button.addEventListener('click', () => {
        activeFilter = button.dataset.filter;
        filterButtons.forEach((item) => item.classList.toggle('active', item === button));
        applyFilters();
      });
    });
    if (searchInput) searchInput.addEventListener('input', applyFilters);
    window.addEventListener('hashchange', () => {
      const hashTab = window.location.hash ? window.location.hash.slice(1) : activeResultTab;
      if (resultTabs.some((button) => button.dataset.resultTab === hashTab)) {
        activateResultTab(hashTab, false);
      }
    });
    const initialTab = window.location.hash ? window.location.hash.slice(1) : activeResultTab;
    if (resultTabs.some((button) => button.dataset.resultTab === initialTab)) {
      activateResultTab(initialTab, false);
    } else if (resultTabs.length) {
      activateResultTab(activeResultTab, false);
    } else {
      applyFilters();
    }
  </script>
"""


FINDING_DRAWER_SCRIPT = r"""
  <script>
    (() => {
      const drawer = document.querySelector('[data-finding-drawer]');
      const drawerBody = drawer?.querySelector('[data-finding-drawer-body]');
      const drawerTitle = drawer?.querySelector('[data-finding-drawer-title]');
      const closeButtons = Array.from(drawer?.querySelectorAll('[data-finding-close]') || []);
      const openButtons = Array.from(document.querySelectorAll('[data-finding-open]'));
      if (!drawer || !drawerBody || !drawerTitle || !openButtons.length) return;

      let activeDetail = null;
      let activeHost = null;
      let activeTrigger = null;

      function restoreDetail() {
        if (!activeDetail || !activeHost) return;
        activeDetail.hidden = true;
        activeHost.append(activeDetail);
      }

      function closeDrawer({restoreFocus = true} = {}) {
        if (drawer.hidden) return;
        restoreDetail();
        drawer.hidden = true;
        document.body.classList.remove('finding-drawer-open');
        const trigger = activeTrigger;
        activeDetail = null;
        activeHost = null;
        activeTrigger = null;
        if (restoreFocus && trigger && !trigger.closest('[hidden]')) trigger.focus();
      }

      function openDrawer(trigger) {
        const row = trigger.closest('.candidate-row');
        const detail = row?.querySelector('[data-finding-detail]');
        if (!row || !detail) return;
        if (!drawer.hidden) closeDrawer({restoreFocus: false});
        activeDetail = detail;
        activeHost = detail.parentElement;
        activeTrigger = trigger;
        drawerTitle.textContent = trigger.dataset.findingTitle || '漏洞详情';
        detail.hidden = false;
        drawerBody.append(detail);
        drawer.hidden = false;
        document.body.classList.add('finding-drawer-open');
        drawer.querySelector('.finding-drawer-close')?.focus();
      }

      openButtons.forEach((button) => button.addEventListener('click', () => openDrawer(button)));
      closeButtons.forEach((button) => button.addEventListener('click', () => closeDrawer()));
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && !drawer.hidden) closeDrawer();
      });
      document.querySelectorAll('[data-result-tab], [data-filter]').forEach((control) => {
        control.addEventListener('click', () => closeDrawer({restoreFocus: false}));
      });
      document.getElementById('candidateSearch')?.addEventListener('input', () => closeDrawer({restoreFocus: false}));
    })();
  </script>
"""


TRIAGE_SCRIPT = r"""
  <script>
    const triageStatusLabels = {
      needs_review: '待复核',
      accepted: '人工确认',
      false_positive: '标记误报',
      fixing: '修复中',
      fixed: '已修复',
    };
    const triageStatusClasses = {
      needs_review: 'info',
      accepted: 'ok',
      false_positive: 'danger',
      fixing: 'warn',
      fixed: 'ok',
    };

    function currentTriageRunId() {
      const match = window.location.pathname.match(/^\/runs\/([^/]+)/);
      return match ? decodeURIComponent(match[1]) : '';
    }

    function applyTriageState(box, item) {
      const status = item.status || 'needs_review';
      const badge = box.querySelector('[data-triage-badge]');
      const select = box.querySelector('[data-triage-status]');
      const note = box.querySelector('[data-triage-note]');
      const message = box.querySelector('[data-triage-message]');
      if (select) select.value = status;
      if (note && typeof item.note === 'string') note.value = item.note;
      if (badge) {
        badge.textContent = triageStatusLabels[status] || status;
        badge.className = `tag ${triageStatusClasses[status] || 'info'}`;
      }
      if (message) {
        const date = item.updated_at ? new Date(item.updated_at) : null;
        const savedText = date && !Number.isNaN(date.getTime()) ? `已保存 ${date.toLocaleString()}` : '已保存';
        window.auditforgeSetStatus(message, savedText, 'ok');
      }
    }

    document.querySelectorAll('[data-triage-candidate]').forEach((box) => {
      const saveButton = box.querySelector('[data-triage-save]');
      if (!saveButton) return;
      saveButton.addEventListener('click', async () => {
        const runId = currentTriageRunId();
        const candidateId = box.dataset.triageCandidate;
        const status = box.querySelector('[data-triage-status]')?.value || 'needs_review';
        const note = box.querySelector('[data-triage-note]')?.value || '';
        const message = box.querySelector('[data-triage-message]');
        saveButton.disabled = true;
        if (message) {
          window.auditforgeSetStatus(message, '正在保存...');
        }
        try {
          const data = await window.auditforgeRequestJson(`/api/runs/${encodeURIComponent(runId)}/triage`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
            body: JSON.stringify({candidate_id: candidateId, status, note}),
          }, '保存失败');
          if (data.ok !== true || !data.item || typeof data.item !== 'object') {
            throw window.auditforgeCreateError({
              message: '服务返回了无法识别的响应。',
              code: 'RESPONSE_INVALID',
              action: '请刷新页面后重试；若问题持续，请查看运行日志。',
            });
          }
          applyTriageState(box, data.item || {status, note});
        } catch (error) {
          window.auditforgeShowError(message, error, '保存失败');
        } finally {
          saveButton.disabled = false;
        }
      });
    });
  </script>
"""


LOGS_SCRIPT = r"""
  <script>
    (() => {
      const stream = document.getElementById('logsStream');
      const empty = document.getElementById('logsEmpty');
      const status = document.getElementById('logsStatus');
      const count = document.getElementById('logsCount');
      const levelFilter = document.getElementById('logLevel');
      const search = document.getElementById('logSearch');
      const pauseButton = document.getElementById('logPause');
      const clearButton = document.getElementById('logClear');
      if (!stream || !empty || !status || !count || !levelFilter || !search || !pauseButton || !clearButton) return;

      const knownLevels = new Set(['debug', 'info', 'warning', 'error', 'critical']);
      const entries = [];
      let after = '0';
      let paused = false;
      let loading = false;
      let pollFailures = 0;
      let pollTimer = null;

      function text(value, fallback = 'n/a') {
        if (value === null || value === undefined || value === '') return fallback;
        return String(value);
      }

      function normalizedLevel(value) {
        const raw = text(value, 'info').toLowerCase();
        if (raw === 'warn') return 'warning';
        if (raw === 'fatal') return 'critical';
        return knownLevels.has(raw) ? raw : 'info';
      }

      function contextText(value) {
        if (value === null || value === undefined || value === '') return 'n/a';
        if (typeof value === 'string') return value;
        try {
          return JSON.stringify(value, null, 2);
        } catch (_error) {
          return String(value);
        }
      }

      function makeElement(tag, className, value) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        element.textContent = value;
        return element;
      }

      function createEntry(item) {
        const record = item && typeof item === 'object' ? item : {message: item};
        const timestamp = text(record.time ?? record.timestamp ?? record.created_at ?? record.createdAt);
        const level = normalizedLevel(record.level);
        const event = text(record.event);
        const message = text(record.message);
        const context = contextText(record.context);

        const row = document.createElement('article');
        row.className = 'log-entry';
        row.dataset.level = level;

        const head = document.createElement('div');
        head.className = 'log-entry-head';
        head.append(
          makeElement('time', 'log-time', timestamp),
          makeElement('span', 'log-level', level.toUpperCase()),
          makeElement('code', 'log-event', event),
        );
        row.append(
          head,
          makeElement('p', 'log-message', message),
          makeElement('pre', 'log-context', context),
        );
        return {
          element: row,
          level,
          searchable: [timestamp, level, event, message, context].join('\n').toLowerCase(),
        };
      }

      function applyFilters() {
        const selectedLevel = levelFilter.value;
        const keyword = search.value.trim().toLowerCase();
        let visible = 0;
        for (const entry of entries) {
          const levelMatches = selectedLevel === 'all' || entry.level === selectedLevel;
          const textMatches = !keyword || entry.searchable.includes(keyword);
          entry.element.hidden = !(levelMatches && textMatches);
          if (!entry.element.hidden) visible += 1;
        }
        empty.hidden = entries.length > 0;
        count.textContent = `显示 ${visible} / ${entries.length}`;
      }

      function payloadItems(payload) {
        if (Array.isArray(payload)) return payload;
        if (!payload || typeof payload !== 'object') return null;
        for (const key of ['items', 'logs', 'entries']) {
          if (Array.isArray(payload[key])) return payload[key];
        }
        return null;
      }

      function nextCursor(payload, batch) {
        if (payload && !Array.isArray(payload) && typeof payload === 'object') {
          for (const key of ['next_after', 'nextAfter', 'last_id', 'cursor', 'after']) {
            if (payload[key] !== null && payload[key] !== undefined && payload[key] !== '') return String(payload[key]);
          }
        }
        const last = batch[batch.length - 1];
        if (last && typeof last === 'object') {
          for (const key of ['sequence', 'id', 'offset', 'cursor']) {
            if (last[key] !== null && last[key] !== undefined && last[key] !== '') return String(last[key]);
          }
        }
        return after;
      }

      function appendBatch(batch) {
        if (!batch.length) return;
        const fragment = document.createDocumentFragment();
        for (const item of batch) {
          const entry = createEntry(item);
          entries.push(entry);
          fragment.append(entry.element);
        }
        while (entries.length > 1000) {
          const removed = entries.shift();
          if (removed) removed.element.remove();
        }
        stream.append(fragment);
        applyFilters();
        stream.scrollTop = stream.scrollHeight;
      }

      function schedulePoll(delay) {
        if (pollTimer) window.clearTimeout(pollTimer);
        if (!paused) pollTimer = window.setTimeout(poll, delay);
      }

      async function poll() {
        if (paused || loading) return;
        loading = true;
        try {
          const payload = await window.auditforgeRequestJson(`/api/logs?after=${encodeURIComponent(after)}`, {
            headers: {'Accept': 'application/json'},
          }, '读取日志失败');
          if (paused) return;
          const batch = payloadItems(payload);
          if (!batch) {
            throw window.auditforgeCreateError({
              message: '日志响应缺少列表数据。',
              code: 'RESPONSE_INVALID',
              action: '请刷新页面后重试；若问题持续，请查看运行日志。',
            });
          }
          after = nextCursor(payload, batch);
          appendBatch(batch);
          pollFailures = 0;
          window.auditforgeSetStatus(status, batch.length ? `已接收 ${batch.length} 条新日志` : '已连接，等待新日志', 'ok');
          schedulePoll(1500);
        } catch (error) {
          pollFailures += 1;
          const normalized = window.auditforgeShowError(status, error, '读取日志失败');
          const terminal = normalized.status === 401 || normalized.status === 403 || normalized.status === 421;
          if (!terminal) {
            const retryDelay = normalized.retryAfter > 0
              ? normalized.retryAfter * 1000
              : Math.min(30000, 1500 * (2 ** Math.min(pollFailures, 4)));
            schedulePoll(retryDelay);
          }
        } finally {
          loading = false;
        }
      }

      levelFilter.addEventListener('change', applyFilters);
      search.addEventListener('input', applyFilters);
      pauseButton.addEventListener('click', () => {
        paused = !paused;
        pauseButton.textContent = paused ? '继续' : '暂停';
        pauseButton.setAttribute('aria-pressed', String(paused));
        window.auditforgeSetStatus(status, paused ? '日志轮询已暂停' : '日志轮询已继续');
        if (paused && pollTimer) window.clearTimeout(pollTimer);
        if (!paused) schedulePoll(0);
      });
      clearButton.addEventListener('click', () => {
        entries.splice(0, entries.length);
        stream.replaceChildren(empty);
        empty.hidden = false;
        applyFilters();
        window.auditforgeSetStatus(status, '已清空当前浏览器中的日志；服务端日志未删除');
      });

      applyFilters();
      schedulePoll(0);
      window.addEventListener('beforeunload', () => {
        if (pollTimer) window.clearTimeout(pollTimer);
      }, {once: true});
    })();
  </script>
"""


def render_home_page(workspace: Path) -> str:
    return render_overview_page(workspace)


def render_i18n_script(language: str) -> str:
    payload = json.dumps(UI_TRANSLATIONS, ensure_ascii=False).replace("</", "<\\/")
    error_payload = json.dumps(ERROR_TRANSLATIONS, ensure_ascii=False).replace("</", "<\\/")
    safe_language = html.escape(language, quote=True)
    return f"""
  <script>
    window.auditforgeLanguage = "{safe_language}";
    window.auditforgeTranslations = {payload};
    window.auditforgeErrorTranslations = {error_payload};
    (function () {{
      const defaultLanguage = 'zh-CN';
      const skipTags = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'PRE', 'CODE', 'NOSCRIPT']);
      const attributeNames = ['title', 'aria-label', 'placeholder'];

      function dictionary(language) {{
        return (window.auditforgeTranslations && window.auditforgeTranslations[language]) || {{}};
      }}

      function translateCore(core, dict) {{
        if (!core) return core;
        if (dict[core]) return dict[core];
        let match = core.match(/^已保存：(.+)；留空不修改。$/);
        if (match) return `Saved: ${{match[1]}}; leave blank to keep it.`;
        match = core.match(/^已完成 · 候选 (\\d+)(?: · 依赖 (\\d+))?$/);
        if (match) return `Completed · Candidates ${{match[1]}}${{match[2] ? ` · Dependencies ${{match[2]}}` : ''}}`;
        match = core.match(/^扫描中 · 候选 (\\d+)(?: · 依赖 (\\d+))?$/);
        if (match) return `Running · Candidates ${{match[1]}}${{match[2] ? ` · Dependencies ${{match[2]}}` : ''}}`;
        match = core.match(/^失败 · 候选 (\\d+)(?: · 依赖 (\\d+))?$/);
        if (match) return `Failed · Candidates ${{match[1]}}${{match[2] ? ` · Dependencies ${{match[2]}}` : ''}}`;
        match = core.match(/^代码 ([\\d,]+) 行$/);
        if (match) return `Code ${{match[1]}} lines`;
        match = core.match(/^语言 (\\d+)$/);
        if (match) return `Languages ${{match[1]}}`;
        match = core.match(/^候选 (\\d+)$/);
        if (match) return `Candidates ${{match[1]}}`;
        match = core.match(/^LLM (\\d+)$/);
        if (match) return `LLM ${{match[1]}}`;
        match = core.match(/^依赖风险 (\\d+)$/);
        if (match) return `Dependency risks ${{match[1]}}`;
        match = core.match(/^已接收 (\\d+) 条新日志$/);
        if (match) return `Received ${{match[1]}} new log entries`;
        match = core.match(/^(\\d+) 秒后可重试。$/);
        if (match) return `Retry in ${{match[1]}} seconds.`;
        match = core.match(/^共 ([\\d,]+) 行代码 · (\\d+) 种语言$/);
        if (match) return `Total ${{match[1]}} lines of code · ${{match[2]}} languages`;
        match = core.match(/^代码总行数$/);
        if (match) return 'Total lines of code';
        match = core.match(/^语言数量$/);
        if (match) return 'Languages';
        match = core.match(/^统计文件$/);
        if (match) return 'Counted files';
        match = core.match(/^跳过文件$/);
        if (match) return 'Skipped files';
        match = core.match(/^([\\w#+. -]+)：([\\d,]+) 行 · ([\\d.]+)%$/);
        if (match) return `${{match[1]}}: ${{match[2]}} lines · ${{match[3]}}%`;
        match = core.match(/^限制 (\\d+)MB，解压后 (\\d+)MB$/);
        if (match) return `Limit ${{match[1]}}MB, ${{match[2]}}MB after extraction`;
        match = core.match(/^使用 LLM 候选补全（当前：(.+)）$/);
        if (match) return `Use LLM candidate completion (current: ${{translateCore(match[1], dict)}})`;
        match = core.match(/^使用 LLM 依赖风险扫描（(.+)，当前：(.+)）$/);
        if (match) return `Use LLM dependency risk scan (${{match[1]}}, current: ${{translateCore(match[2], dict)}})`;
        match = core.match(/^已解析 (\\d+) 个依赖清单、(\\d+) 个依赖，组件风险需通过 SCA\\/OSV\\/NVD 复核。$/);
        if (match) return `Parsed ${{match[1]}} dependency manifests and ${{match[2]}} dependencies. Component risks need SCA/OSV/NVD verification.`;
        match = core.match(/^生成 (\\d+) 条风险候选$/);
        if (match) return `Generated ${{match[1]}} risk candidates`;
        match = core.match(/^暂无(.+)。$/);
        if (match) return `No ${{match[1]}}.`;
        return core;
      }}

      function translateText(text, dict) {{
        const leading = text.match(/^\\s*/)[0];
        const trailing = text.match(/\\s*$/)[0];
        const core = text.trim();
        const translated = translateCore(core, dict);
        return translated === core ? text : `${{leading}}${{translated}}${{trailing}}`;
      }}

      function translateAttributes(element, dict) {{
        for (const name of attributeNames) {{
          const value = element.getAttribute && element.getAttribute(name);
          if (!value) continue;
          element.setAttribute(name, translateText(value, dict).trim());
        }}
      }}

      function walk(node, dict) {{
        if (!node) return;
        if (node.nodeType === 3) {{
          node.nodeValue = translateText(node.nodeValue || '', dict);
          return;
        }}
        if (node.nodeType !== 1 || skipTags.has(node.tagName)) return;
        translateAttributes(node, dict);
        for (const child of Array.from(node.childNodes)) walk(child, dict);
      }}

      window.auditforgeTranslate = function (text, language) {{
        const lang = language || window.auditforgeLanguage || defaultLanguage;
        if (lang === defaultLanguage) return String(text || '');
        return translateText(String(text || ''), dictionary(lang)).trim();
      }};

      window.auditforgeTranslateElement = function (element, language) {{
        const lang = language || window.auditforgeLanguage || defaultLanguage;
        if (!element || lang === defaultLanguage) return;
        walk(element, dictionary(lang));
      }};

      window.auditforgeApplyLanguage = function (language) {{
        window.auditforgeLanguage = language || defaultLanguage;
        document.documentElement.lang = window.auditforgeLanguage === 'en-US' ? 'en' : 'zh-CN';
        if (window.auditforgeLanguage === defaultLanguage) return;
        const dict = dictionary(window.auditforgeLanguage);
        document.title = translateText(document.title, dict).trim();
        walk(document.body, dict);
      }};

      window.auditforgeApplyLanguage(window.auditforgeLanguage);
    }})();
  </script>"""


def render_sidebar(workspace: Path, active: str, *, current_run_id: str | None = None) -> str:
    runs = _server_load_runs(workspace)
    run_links = "\n".join(render_sidebar_run_link(run, current_run_id=current_run_id) for run in runs[:8])
    if not run_links:
        run_links = '<div class="history-empty">暂无扫描任务</div>'
    overview_class = "active" if active == "overview" else ""
    scan_class = "active" if active == "scan" else ""
    history_class = "active" if active in {"history", "run"} else ""
    history_index_class = "history-index active" if active == "history" else "history-index"
    logs_class = "active" if active == "logs" else ""
    settings_class = "active" if active == "settings" else ""
    return f"""
    <aside class="sidebar">
      <div class="brand">
        <div class="mark">AF</div>
        <div>
          <h1>AuditForge</h1>
          <div class="subtle">AI 白盒审计平台</div>
        </div>
      </div>
      <nav class="side-nav" aria-label="平台导航">
        <a class="{overview_class}" href="/"><span class="side-icon">OV</span>概况总览</a>
        <a class="{scan_class}" href="/scan"><span class="side-icon">NS</span>新建扫描</a>
        <details class="history-nav {history_class}" open>
          <summary><span class="side-icon">HI</span><span>扫描历史</span><span class="nav-count">{len(runs)}</span></summary>
          <div class="history-subnav">
            <a class="{history_index_class}" href="/history"><span>全部扫描任务</span></a>
            {run_links}
          </div>
        </details>
        <a class="{logs_class}" href="/logs"><span class="side-icon">LG</span>运行日志</a>
        <a class="{settings_class}" href="/settings"><span class="side-icon">ST</span>设置</a>
      </nav>
      <div class="side-footer">{html.escape(str(workspace.resolve()))}</div>
    </aside>"""


def render_sidebar_run_link(run: dict, *, current_run_id: str | None = None) -> str:
    raw_run_id = str(run.get("id") or "")
    run_id = html.escape(raw_run_id)
    run_name = str(run.get("name") or raw_run_id)
    stats = run.get("stats") or {}
    candidates = int(stats.get("candidates") or 0) if isinstance(stats, dict) else 0
    dependency_findings = int(stats.get("dependency_findings") or 0) if isinstance(stats, dict) else 0
    status = str(run.get("status") or "unknown")
    status_text = {"completed": "已完成", "running": "扫描中", "failed": "失败"}.get(status, status)
    active_class = " active" if raw_run_id == current_run_id else ""
    dependency_meta = f" · 依赖 {dependency_findings}" if dependency_findings or run.get("dependency_scan") else ""
    return f"""
            <a class="history-task{active_class}" href="/runs/{run_id}" data-sidebar-run="{run_id}" title="{html.escape(run_name, quote=True)}">
              <span class="history-title">{html.escape(run_name)}</span>
              <span class="history-meta">{html.escape(status_text)} · 候选 {candidates}{html.escape(dependency_meta)}</span>
            </a>"""


def render_delete_run_button(run: dict) -> str:
    raw_run_id = str(run.get("id") or "")
    run_name = str(run.get("name") or raw_run_id)
    is_running = str(run.get("status") or "") == "running"
    is_legacy = raw_run_id == "legacy"
    disabled = ""
    label = "删除任务"
    if is_running:
        disabled = ' disabled title="扫描完成后可删除"'
        label = "运行中"
    elif is_legacy:
        disabled = ' disabled title="legacy 工作区不能从历史列表删除"'
        label = "系统任务"
    return (
        '<button class="danger-button delete-run-button" type="button" '
        f'data-delete-run data-run-id="{html.escape(raw_run_id, quote=True)}" '
        f'data-run-name="{html.escape(run_name, quote=True)}"{disabled}>{label}</button>'
    )


def render_cancel_run_button(run: dict) -> str:
    if str(run.get("status") or "") != "running":
        return ""
    run_id = html.escape(str(run.get("id") or ""), quote=True)
    return f'<button class="danger-button" type="button" data-cancel-run data-run-id="{run_id}">停止任务</button>'


def render_scan_diagnostics_panel(run: dict, artifacts: dict) -> str:
    llm_diagnostics = artifacts.get("llm_diagnostics") if isinstance(artifacts.get("llm_diagnostics"), dict) else {}
    dependency_diagnostics = artifacts.get("dependency_diagnostics") if isinstance(artifacts.get("dependency_diagnostics"), dict) else {}
    analysis_coverage = artifacts.get("analysis_coverage") if isinstance(artifacts.get("analysis_coverage"), dict) else {}
    scan_config = run.get("scan_config") if isinstance(run.get("scan_config"), dict) else {}
    profiles = scan_config.get("profiles") if isinstance(scan_config.get("profiles"), dict) else {}
    taint = diagnostics_stage_payload(
        "污点候选",
        "补充 source-to-sink 语义候选",
        profiles.get("taint") if isinstance(profiles.get("taint"), dict) else {},
        llm_diagnostics,
        enabled_hint=bool(run.get("llm_enabled")),
    )
    dependency = diagnostics_stage_payload(
        "依赖审计",
        "分析依赖清单中的 CVE/组件风险",
        profiles.get("dependency") if isinstance(profiles.get("dependency"), dict) else {},
        llm_diagnostics.get("dependency_scan") if isinstance(llm_diagnostics.get("dependency_scan"), dict) else dependency_diagnostics,
        enabled_hint=bool(run.get("dependency_scan")),
    )
    deep = diagnostics_stage_payload(
        "二次验证",
        "生成容器沙箱测试并复核候选",
        profiles.get("deep") if isinstance(profiles.get("deep"), dict) else {},
        llm_diagnostics.get("deep_verification") if isinstance(llm_diagnostics.get("deep_verification"), dict) else {},
        enabled_hint="deep" in str(run.get("verify") or "none"),
    )
    coverage_card = analysis_coverage_diagnostics_payload(analysis_coverage)
    cards = "\n".join(render_diagnostics_card(item) for item in (coverage_card, taint, dependency, deep))
    return f"""
            <div class="diagnostic-panel">
              <div class="diagnostic-head">
                <h2>分析覆盖与 AI 调用诊断</h2>
                <p>展示代码覆盖盲区、专项补扫、LLM 配置快照和错误摘要，不包含 API Key。</p>
              </div>
              <div class="diagnostic-grid">{cards}</div>
            </div>"""


def analysis_coverage_diagnostics_payload(coverage: dict) -> dict:
    if not coverage:
        return {
            "label": "分析覆盖与盲区",
            "description": "旧任务未生成覆盖地图。",
            "status": "无数据",
            "status_class": "info",
            "rows": [],
            "prompt_rows": [],
            "notes": ["重新扫描后将记录 parser、调用解析、source/sink 和 Agent 上下文盲区。"],
        }
    summary = coverage.get("summary") if isinstance(coverage.get("summary"), dict) else {}
    rescan = coverage.get("auto_rescan") if isinstance(coverage.get("auto_rescan"), dict) else {}
    dimensions = coverage.get("dimensions") if isinstance(coverage.get("dimensions"), dict) else {}
    rows: list[tuple[str, str]] = [
        ("分析置信分", f"{float(coverage.get('score') or 0):.1f}/100"),
        ("未解析调用", str(int(summary.get("unresolved_calls") or 0))),
        ("高优先级盲区", str(int(summary.get("high_priority_blindspots") or 0))),
        ("专项补扫", f"{int(rescan.get('succeeded') or 0)}/{int(rescan.get('executed') or 0)} 成功"),
    ]
    for name, item in dimensions.items():
        if not isinstance(item, dict):
            continue
        value = item.get("score")
        rows.append((str(name), "未启用" if value is None else f"{float(value):.1f}%"))
    blindspots = coverage.get("blindspots") if isinstance(coverage.get("blindspots"), list) else []
    notes = []
    for item in blindspots[:5]:
        if not isinstance(item, dict):
            continue
        item_rescan = item.get("auto_rescan") if isinstance(item.get("auto_rescan"), dict) else {}
        suffix = f"；补扫 {item_rescan.get('status')}" if item_rescan.get("scheduled") else ""
        notes.append(f"{str(item.get('severity') or 'info').upper()} · {item.get('id')} × {int(item.get('count') or 0)}{suffix}")
    high_priority = int(summary.get("high_priority_blindspots") or 0)
    return {
        "label": "分析覆盖与盲区",
        "description": "衡量可观察的分析覆盖，不代表漏洞检出率或漏报率。",
        "status": "存在高优先级盲区" if high_priority else "覆盖稳定",
        "status_class": "danger" if high_priority else "ok",
        "rows": rows,
        "prompt_rows": [],
        "notes": notes,
    }


def diagnostics_stage_payload(label: str, description: str, profile: dict, diagnostics: dict, *, enabled_hint: bool) -> dict:
    enabled = bool(profile.get("enabled")) if "enabled" in profile else bool(diagnostics.get("enabled", enabled_hint))
    provider = str(profile.get("provider") or diagnostics.get("provider") or "未记录")
    model = str(profile.get("model") or diagnostics.get("model") or "未记录")
    status_label_text, status_class = diagnostics_status(enabled, diagnostics)
    rows = [
        ("Provider", provider),
        ("模型", model),
    ]
    if profile.get("base_url"):
        rows.append(("Base URL", str(profile.get("base_url"))))
    if profile.get("max_candidates"):
        rows.append(("上限", str(profile.get("max_candidates"))))
    if profile.get("concurrency") or diagnostics.get("concurrency"):
        rows.append(("并发", str(profile.get("concurrency") or diagnostics.get("concurrency"))))
    rows.extend(diagnostics_metric_rows(diagnostics))
    prompt_rows = prompt_snapshot_rows(profile)
    notes = diagnostics_notes(diagnostics)
    return {
        "label": label,
        "description": description,
        "enabled": enabled,
        "status": status_label_text,
        "status_class": status_class,
        "rows": rows,
        "prompt_rows": prompt_rows,
        "notes": notes,
    }


def diagnostics_status(enabled: bool, diagnostics: dict) -> tuple[str, str]:
    if not enabled and not diagnostics.get("enabled"):
        return "未启用", "info"
    if diagnostics.get("error"):
        return "异常", "danger"
    if diagnostics.get("errors") or diagnostics.get("chunk_errors"):
        return "部分异常", "warn"
    if diagnostics.get("container_runtime_ready") is False:
        return "沙箱不可用", "warn"
    return "已完成" if diagnostics else "等待结果", "ok" if diagnostics else "info"


def diagnostics_metric_rows(diagnostics: dict) -> list[tuple[str, str]]:
    fields = [
        ("accepted", "接收"),
        ("agent_count", "专业 Agent"),
        ("tasks", "审计任务"),
        ("succeeded", "任务成功"),
        ("failed", "任务失败"),
        ("tested", "验证"),
        ("sandbox_tasks", "沙箱任务"),
        ("sandbox_concurrency", "验证并发"),
        ("sandbox_passed", "沙箱通过"),
        ("sandbox_failed", "沙箱失败"),
        ("sandbox_blocked", "沙箱受阻"),
        ("sandbox_max_concurrency_observed", "沙箱峰值并发"),
        ("rejected", "拒绝"),
        ("chunks", "分块"),
        ("dependencies", "依赖"),
        ("manifests", "清单"),
    ]
    rows: list[tuple[str, str]] = []
    for key, label in fields:
        if key not in diagnostics:
            continue
        value = diagnostics.get(key)
        if isinstance(value, list):
            rows.append((label, str(len(value))))
        elif value not in {None, ""}:
            rows.append((label, str(value)))
    selected = diagnostics.get("selected_candidate_ids")
    if isinstance(selected, list):
        rows.append(("选中候选", str(len(selected))))
    coverage = diagnostics.get("coverage")
    if isinstance(coverage, dict) and coverage.get("ratio") is not None:
        rows.append(("事实覆盖", f"{float(coverage.get('ratio') or 0) * 100:.1f}%"))
    return rows


def prompt_snapshot_rows(profile: dict) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for key, label in (("system_prompt", "System"), ("user_prompt", "Task")):
        item = profile.get(key)
        if not isinstance(item, dict):
            continue
        length = int(item.get("length") or 0)
        digest = str(item.get("sha256") or "")
        if not length and not digest:
            continue
        rows.append((label, f"{length} 字符 · {digest or '无 hash'}"))
    return rows


def diagnostics_notes(diagnostics: dict) -> list[str]:
    notes: list[str] = []
    if diagnostics.get("error"):
        notes.append(safe_stage_error("AI 审计", "LLM_PROVIDER_FAILED"))
    for key, label in (("chunk_errors", "分块异常"), ("errors", "执行异常")):
        value = diagnostics.get(key)
        if isinstance(value, list) and value:
            for item in value[:2]:
                if isinstance(item, dict):
                    detail = item.get("reason") if not item.get("error") else safe_stage_error(label, "LLM_PROVIDER_FAILED")
                else:
                    detail = safe_stage_error(label, "LLM_PROVIDER_FAILED")
                notes.append(f"{label}：{str(detail)[:220]}")
    rejected = diagnostics.get("rejected")
    if isinstance(rejected, list) and rejected:
        for item in rejected[:3]:
            if isinstance(item, dict):
                reason = item.get("reason") or item
            else:
                reason = item
            notes.append(f"拒绝样本：{safe_diagnostic_detail(reason)}")
    if diagnostics.get("container_runtime_error"):
        notes.append(safe_stage_error("容器沙箱", "SANDBOX_UNAVAILABLE"))
    if diagnostics.get("message"):
        notes.append(str(diagnostics.get("message"))[:260])
    return notes


def safe_stage_error(stage: str, code: str) -> str:
    messages = {
        "LLM_PROVIDER_FAILED": "上游模型服务未完成，详细原因已写入运行日志。",
        "SANDBOX_UNAVAILABLE": "隔离验证环境未完成，详细原因已写入运行日志。",
        "DEPENDENCY_SCAN_FAILED": "部分依赖数据源未完成，请查看运行日志确认覆盖范围。",
    }
    return f"{stage}：{messages.get(code, '该阶段未完成，请查看运行日志。')}"


def safe_diagnostic_detail(value: object) -> str:
    text = str(value or "").strip()[:220]
    lowered = text.lower()
    unsafe_markers = (
        "traceback",
        "valueerror",
        "runtimeerror",
        "oserror",
        "api_key",
        "authorization",
        "password",
        "secret=",
        "c:/",
        "c:\\",
        "/users/",
    )
    if not text or any(marker in lowered for marker in unsafe_markers):
        return "已拒绝一条不符合输出契约的结果"
    return text


def render_diagnostics_card(item: dict) -> str:
    rows = "\n".join(
        f"<div><span>{html.escape(label)}</span><strong>{html.escape(value)}</strong></div>" for label, value in item.get("rows", [])
    )
    prompt_rows = "\n".join(
        f"<div><span>{html.escape(label)}</span><code>{html.escape(value)}</code></div>" for label, value in item.get("prompt_rows", [])
    )
    prompt_block = f'<div class="diagnostic-prompts">{prompt_rows}</div>' if prompt_rows else ""
    notes = "\n".join(f"<li>{html.escape(str(note))}</li>" for note in item.get("notes", []))
    notes_block = f'<ul class="diagnostic-notes">{notes}</ul>' if notes else '<p class="diagnostic-empty">暂无异常或拒绝样本。</p>'
    return f"""
                <article class="diagnostic-card">
                  <div class="diagnostic-card-head">
                    <div>
                      <h3>{html.escape(str(item.get("label") or ""))}</h3>
                      <p>{html.escape(str(item.get("description") or ""))}</p>
                    </div>
                    <span class="tag {html.escape(str(item.get("status_class") or "info"))}">{html.escape(str(item.get("status") or ""))}</span>
                  </div>
                  <div class="diagnostic-kv">{rows}</div>
                  {prompt_block}
                  {notes_block}
                </article>"""


def partition_candidate_rows(candidates: list[dict], results: dict[str, dict]) -> dict[str, list[tuple[dict, dict | None]]]:
    partitions: dict[str, list[tuple[dict, dict | None]]] = {
        "confirmed": [],
        "secondary": [],
        "candidate": [],
        "archived": [],
    }
    for candidate in candidates:
        result = results.get(str(candidate.get("id") or ""))
        status = str(result.get("status") if result else "not_run")
        if status == "confirmed":
            partitions["confirmed"].append((candidate, result))
        elif status in {"sandbox_executed", "sandbox_confirmed"}:
            partitions["secondary"].append((candidate, result))
        elif status in {"false_positive", "not_reproducible"}:
            destination = "archived" if has_runtime_negative_evidence(result) else "candidate"
            partitions[destination].append((candidate, result))
        else:
            partitions["candidate"].append((candidate, result))
    return partitions


def default_result_partition(candidate_sections: dict[str, list[tuple[dict, dict | None]]], dependency_findings: list) -> str:
    """Choose the most useful non-empty evidence queue for first paint."""

    for tab_id in ("candidate", "secondary", "confirmed"):
        if candidate_sections.get(tab_id):
            return tab_id
    if dependency_findings:
        return "dependency"
    return "candidate"


def render_result_partition_tabs(
    candidate_sections: dict[str, list[tuple[dict, dict | None]]],
    dependency_findings: list,
    *,
    active_tab: str | None = None,
) -> str:
    active_tab = active_tab or default_result_partition(candidate_sections, dependency_findings)
    tabs = [
        ("dependency", "依赖漏洞", len(dependency_findings), "组件/CVE 风险候选"),
        ("candidate", "候选漏洞", len(candidate_sections.get("candidate", [])), "等待验证的代码路径"),
        ("secondary", "沙箱待复核", len(candidate_sections.get("secondary", [])), "沙箱脚本已执行，等待人工复核"),
        ("confirmed", "已确认漏洞", len(candidate_sections.get("confirmed", [])), "运行时复现定案"),
    ]
    return f"""
          <section class="panel result-tabs" role="tablist" aria-label="漏洞结果分区">
            {"".join(render_result_tab(tab_id, label, count, description, tab_id == active_tab) for tab_id, label, count, description in tabs)}
          </section>"""


def render_result_tab(tab_id: str, label: str, count: int, description: str, active: bool = False) -> str:
    safe_id = html.escape(tab_id, quote=True)
    selected = "true" if active else "false"
    active_class = " active" if active else ""
    return f"""
            <button type="button" class="result-tab{active_class}" data-result-tab="{safe_id}" role="tab" aria-selected="{selected}">
              <span>{html.escape(label)}</span>
              <strong>{count}</strong>
              <em>{html.escape(description)}</em>
            </button>"""


def render_project_inventory_panel(inventory: dict | None) -> str:
    if not isinstance(inventory, dict) or not inventory:
        return """
          <div class="inventory-panel">
            <div class="inventory-head">
              <div>
                <h2>项目盘点</h2>
                <p>暂无项目盘点数据。</p>
              </div>
              <span class="tag info">未生成</span>
            </div>
          </div>"""
    total_lines = int(inventory.get("total_lines") or 0)
    language_count = int(inventory.get("language_count") or 0)
    file_count = int(inventory.get("file_count") or 0)
    languages = inventory.get("languages") if isinstance(inventory.get("languages"), list) else []
    rows = "\n".join(render_inventory_language_row(item) for item in languages[:12] if isinstance(item, dict))
    if not rows:
        rows = '<div class="empty compact">未识别到可统计的文本/代码文件。</div>'
    return f"""
          <div class="inventory-panel">
            <div class="inventory-head">
              <div>
                <h2>项目盘点</h2>
                <p>{html.escape(inventory_summary(inventory))}</p>
              </div>
              <span class="tag ok">已完成</span>
            </div>
            <div class="inventory-metrics">
              <div class="inventory-metric"><span>代码总行数</span><strong>{total_lines:,}</strong></div>
              <div class="inventory-metric"><span>语言数量</span><strong>{language_count}</strong></div>
              <div class="inventory-metric"><span>统计文件</span><strong>{file_count:,}</strong></div>
              <div class="inventory-metric"><span>跳过文件</span><strong>{int(inventory.get("skipped_files") or 0):,}</strong></div>
            </div>
            <div class="language-list">{rows}</div>
          </div>"""


def render_inventory_language_row(item: dict) -> str:
    language = str(item.get("language") or item.get("id") or "Unknown")
    lines = int(item.get("lines") or 0)
    percent = float(item.get("percent") or 0.0)
    width = max(3, min(100, percent)) if lines else 0
    return f"""
              <div class="language-row">
                <div class="language-row-head">
                  <strong>{html.escape(language)}</strong>
                  <span>{lines:,} 行 · {percent:.1f}%</span>
                </div>
                <div class="language-track"><i style="width:{width:.1f}%"></i></div>
              </div>"""


def render_result_partitions(
    candidate_sections: dict[str, list[tuple[dict, dict | None]]],
    inventory: list,
    findings: list,
    diagnostics: dict,
    stats: dict,
    enabled: bool,
    repo_path: str,
    triage_items: dict[str, dict] | None = None,
    active_tab: str | None = None,
) -> str:
    triage_items = triage_items or {}
    active_tab = active_tab or default_result_partition(candidate_sections, findings)
    dependency_panel = render_result_tab_panel(
        "dependency",
        render_dependency_result_zone(inventory, findings, diagnostics, stats, enabled),
        active=active_tab == "dependency",
    )
    confirmed_panel = render_result_tab_panel(
        "confirmed",
        render_candidate_result_zone(
            "confirmed",
            "已确认漏洞",
            "已绑定运行时复现证据，可进入正式漏洞报告。",
            candidate_sections.get("confirmed", []),
            repo_path,
            triage_items,
        ),
        active=active_tab == "confirmed",
    )
    secondary_panel = render_result_tab_panel(
        "secondary",
        render_candidate_result_zone(
            "secondary",
            "沙箱执行待复核",
            "容器内测试脚本已执行，但这不是漏洞成立证明；仍需人工审阅断言与真实环境证据。",
            candidate_sections.get("secondary", []),
            repo_path,
            triage_items,
        ),
        active=active_tab == "secondary",
    )
    candidate_zones = [
        render_candidate_result_zone(
            "candidate",
            "候选漏洞",
            "静态规则或 LLM 生成的 source-to-sink 候选，等待 safe/deep/人工验证。",
            candidate_sections.get("candidate", []),
            repo_path,
            triage_items,
        )
    ]
    if candidate_sections.get("archived"):
        candidate_zones.append(
            render_candidate_result_zone(
                "archived",
                "验证归档",
                "误报、未复现或验证受阻的候选，单独归档避免污染候选区。",
                candidate_sections.get("archived", []),
                repo_path,
                triage_items,
            )
        )
    candidate_panel = render_result_tab_panel("candidate", "\n".join(candidate_zones), active=active_tab == "candidate")
    return "\n".join([dependency_panel, candidate_panel, secondary_panel, confirmed_panel])


def render_result_tab_panel(tab_id: str, content: str, active: bool = False) -> str:
    safe_id = html.escape(tab_id, quote=True)
    hidden = "" if active else " hidden"
    active_class = " active" if active else ""
    return f"""
          <div class="result-tab-panel{active_class}" data-result-panel="{safe_id}" role="tabpanel"{hidden}>
            {content}
          </div>"""


def render_dependency_result_zone(inventory: list, findings: list, diagnostics: dict, stats: dict, enabled: bool) -> str:
    manifest_count = len(inventory) or int(stats.get("dependency_manifests") or 0)
    dependency_count = sum(len(item.get("dependencies") or []) for item in inventory if isinstance(item, dict)) or int(
        stats.get("dependencies") or 0
    )
    finding_count = len(findings) or int(stats.get("dependency_findings") or 0)
    osv = diagnostics.get("osv") if isinstance(diagnostics.get("osv"), dict) else {}
    incomplete = enabled and diagnostics.get("complete") is False
    status_tag = "danger" if diagnostics.get("error") else ("info" if incomplete else "ok" if enabled else "info")
    status_text = (
        "部分完成"
        if incomplete
        else "已完成"
        if enabled and not diagnostics.get("error")
        else "扫描异常"
        if diagnostics.get("error")
        else "未启用"
    )
    error_html = (
        f'<p class="error">{html.escape(safe_stage_error("依赖审计", "DEPENDENCY_SCAN_FAILED"))}</p>' if diagnostics.get("error") else ""
    )
    osv_html = render_osv_diagnostics(osv) if osv else ""
    finding_html = "\n".join(render_dependency_item(item) for item in findings if isinstance(item, dict))
    if not finding_html:
        detail = (
            "暂无依赖风险候选；建议继续用 OSV/NVD 或企业 SCA 工具做权威复核。"
            if enabled or manifest_count
            else "本次扫描未启用依赖风险扫描。"
        )
        finding_html = f'<div class="dependency-item"><p>{html.escape(detail)}</p></div>'
    return f"""
          <section class="panel result-zone dependency" data-result-section="dependency">
            <div class="result-zone-head">
              <div>
                <h3>依赖漏洞</h3>
                <p>已解析 {manifest_count} 个依赖清单、{dependency_count} 个依赖；精确版本优先匹配 OSV 历史漏洞库。</p>
                {osv_html}
                {error_html}
              </div>
              <div class="tags">
                <span class="tag {status_tag}">{html.escape(status_text)}</span>
                <span class="result-zone-count">{finding_count}</span>
              </div>
            </div>
            <div class="dependency-list">{finding_html}</div>
          </section>"""


def render_candidate_result_zone(
    section: str,
    title: str,
    description: str,
    items: list[tuple[dict, dict | None]],
    repo_path: str,
    triage_items: dict[str, dict] | None = None,
) -> str:
    triage_items = triage_items or {}
    cards = "\n".join(
        render_card(candidate, result, repo_path, triage_items.get(str(candidate.get("id") or ""))) for candidate, result in items
    )
    if not cards:
        cards = f'<div class="empty compact">暂无{html.escape(title)}。</div>'
    return f"""
          <section class="panel result-zone {html.escape(section)}" data-result-section="{html.escape(section)}">
            <div class="result-zone-head">
              <div>
                <h3>{html.escape(title)}</h3>
                <p>{html.escape(description)}</p>
              </div>
              <span class="result-zone-count">{len(items)}</span>
            </div>
            <div class="candidate-list">{cards}</div>
          </section>"""


def render_dependency_detail_section(
    inventory: list,
    findings: list,
    diagnostics: dict,
    stats: dict,
    enabled: bool,
) -> str:
    has_dependency_data = enabled or bool(inventory) or bool(findings) or int(stats.get("dependency_manifests") or 0) > 0
    if not has_dependency_data:
        return ""
    manifest_count = len(inventory) or int(stats.get("dependency_manifests") or 0)
    dependency_count = sum(len(item.get("dependencies") or []) for item in inventory if isinstance(item, dict)) or int(
        stats.get("dependencies") or 0
    )
    finding_count = len(findings) or int(stats.get("dependency_findings") or 0)
    osv = diagnostics.get("osv") if isinstance(diagnostics.get("osv"), dict) else {}
    incomplete = enabled and diagnostics.get("complete") is False
    status_tag = "danger" if diagnostics.get("error") else ("info" if incomplete else "ok" if enabled else "info")
    status_text = (
        "部分完成"
        if incomplete
        else "已完成"
        if enabled and not diagnostics.get("error")
        else "扫描异常"
        if diagnostics.get("error")
        else "未启用"
    )
    error_html = (
        f'<p class="error">{html.escape(safe_stage_error("依赖审计", "DEPENDENCY_SCAN_FAILED"))}</p>' if diagnostics.get("error") else ""
    )
    osv_html = render_osv_diagnostics(osv) if osv else ""
    finding_html = "\n".join(render_dependency_item(item) for item in findings if isinstance(item, dict))
    if not finding_html:
        finding_html = '<div class="dependency-item"><p>暂无依赖风险候选；建议继续用 OSV/NVD 或企业 SCA 工具做权威复核。</p></div>'
    return f"""
          <section class="panel dependency-panel">
            <div class="dependency-head">
              <div>
                <h3>依赖风险分析</h3>
                <p>已解析 {manifest_count} 个依赖清单、{dependency_count} 个依赖，生成 {finding_count} 条组件风险候选。</p>
                {osv_html}
                {error_html}
              </div>
              <span class="tag {status_tag}">{html.escape(status_text)}</span>
            </div>
            <div class="dependency-list">{finding_html}</div>
          </section>"""


def render_dependency_item(item: dict) -> str:
    package = str(item.get("package") or "unknown")
    finding_id = str(item.get("id") or "DEP")
    severity = str(item.get("severity") or "unknown")
    confidence = str(item.get("confidence") or "low")
    manifest = str(item.get("manifest_file") or item.get("manifestFile") or "")
    line = item.get("line")
    location = f"{manifest}:{line}" if line else manifest
    version = str(item.get("installed_version") or item.get("installedVersion") or "未知")
    affected = str(item.get("affected_range") or item.get("affectedRange") or "未知")
    cve_ids = item.get("cve_ids") or item.get("cveIds") or []
    advisory_ids = item.get("advisory_ids") or item.get("advisoryIds") or cve_ids
    advisory_text = (
        ", ".join(str(advisory) for advisory in advisory_ids) if isinstance(advisory_ids, list) and advisory_ids else "未给出明确公告编号"
    )
    fixed_versions = item.get("fixed_versions") or item.get("fixedVersions") or []
    fixed_text = ", ".join(str(version) for version in fixed_versions) if isinstance(fixed_versions, list) else ""
    source = str(item.get("source") or "llm").upper()
    evidence = str(item.get("evidence") or "")
    recommendation = str(item.get("recommendation") or "")
    return f"""
              <article class="dependency-item">
                <h4>{html.escape(finding_id)} · {html.escape(package)}</h4>
                <div class="tags">
                  <span class="tag {dependency_severity_tag_class(severity)}">{html.escape(dependency_severity_label(severity))}</span>
                  <span class="tag">{html.escape(confidence_label(confidence))}</span>
                  <span class="tag">{html.escape(str(item.get("ecosystem") or ""))}</span>
                  <span class="tag">{html.escape(source)}</span>
                  <span class="tag">{html.escape(advisory_text)}</span>
                </div>
                <p><code>{html.escape(location)}</code> · 当前版本/约束：<code>{html.escape(version)}</code> · 影响范围：<code>{html.escape(affected)}</code></p>
                {f"<p>官方修复版本：<code>{html.escape(fixed_text)}</code></p>" if fixed_text else ""}
                {f"<p>{html.escape(evidence)}</p>" if evidence else ""}
                {f"<p>建议：{html.escape(recommendation)}</p>" if recommendation else ""}
              </article>"""


def render_osv_diagnostics(osv: dict) -> str:
    queried = int(osv.get("queried_components") or 0)
    resolved = int(osv.get("resolved_components") or 0)
    unresolved = int(osv.get("unresolved_components") or 0)
    failed = int(osv.get("failed_components") or 0)
    advisories = int(osv.get("advisories") or 0)
    state = "完整" if osv.get("complete") else "部分"
    return (
        '<p class="dependency-osv-status">'
        f"OSV 历史库匹配：{state} · 已查询 {queried}/{resolved} 个精确组件 · 命中 {advisories} 条公告"
        + (f" · 未解析版本 {unresolved}" if unresolved else "")
        + (f" · 查询失败 {failed}" if failed else "")
        + "</p>"
    )


def render_scan_progress_panel(run: dict) -> str:
    verify = str(run.get("verify") or "none")
    dependency_scan = bool(run.get("dependency_scan"))
    progress = _server_normalize_progress(run.get("progress"), verify, dependency_scan)
    run_id = html.escape(str(run.get("id") or ""), quote=True)
    status = html.escape(str(run.get("status") or "unknown"), quote=True)
    stages = progress.get("stages") if isinstance(progress.get("stages"), list) else []
    stage_html = "\n".join(render_progress_stage(stage, index + 1) for index, stage in enumerate(stages) if isinstance(stage, dict))
    percent = max(0, min(100, int(progress.get("percent") or 0)))
    detail = html.escape(str(progress.get("detail") or ""))
    return f"""
          <div class="scan-progress" id="runProgressPanel" data-run-id="{run_id}" data-status="{status}">
            <div class="progress-summary">
              <strong>扫描阶段进度</strong>
              <span><span data-progress-summary>{percent}%</span> · <span data-progress-summary-detail>{detail}</span></span>
            </div>
            {stage_html}
          </div>"""


def render_progress_stage(stage: dict, index: int) -> str:
    stage_id = html.escape(str(stage.get("id") or ""), quote=True)
    label = html.escape(str(stage.get("label") or "扫描阶段"))
    status = str(stage.get("status") or "pending")
    safe_status = html.escape(status if status in {"pending", "running", "completed", "skipped", "failed"} else "pending", quote=True)
    percent = max(0, min(100, int(stage.get("percent") or 0)))
    detail = html.escape(str(stage.get("detail") or ""))
    state = html.escape(progress_stage_status_label(status))
    return f"""
            <div class="progress-stage status-{safe_status}" data-progress-stage="{stage_id}">
              <div class="progress-index">{index:02d}</div>
              <div class="progress-body">
                <div class="progress-head">
                  <div class="progress-title">{label}</div>
                  <div class="progress-state" data-progress-state>{state}</div>
                </div>
                <div class="progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{percent}" aria-label="{label} {percent}%">
                  <span class="progress-fill" data-progress-fill style="width:{percent}%"></span>
                </div>
                <div class="progress-detail" data-progress-detail>{detail}</div>
              </div>
            </div>"""


def progress_stage_status_label(status: str) -> str:
    return {
        "pending": "等待中",
        "running": "进行中",
        "completed": "已完成",
        "skipped": "已跳过",
        "failed": "失败",
    }.get(status, status)


def format_time(value: str) -> str:
    if not value:
        return "未知时间"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def render_dashboard(workspace: Path, run: dict | None = None, platform_workspace: Path | None = None) -> str:
    data = read_dashboard_detail(workspace)
    scan = data.get("scan") or {}
    stats = json.loads(scan.get("stats_json") or "{}")
    candidates = data.get("candidates") or []
    results = {item["candidate_id"]: item for item in data.get("verification_results") or []}
    repo_path_raw = scan.get("repo_path", "")
    cards = "\n".join(render_card(candidate, results.get(candidate["id"]), repo_path_raw) for candidate in candidates)
    metrics = "\n".join(render_metric(key, value) for key, value in stats.items())
    repo_path = html.escape(scan.get("repo_path", "未知仓库"))
    target_url = html.escape(scan.get("target_url") or "未配置运行目标")
    total_candidates = html.escape(str(stats.get("candidates", 0)))
    if run:
        run_id = html.escape(str(run.get("id") or ""))
        nav_links = f"""
        <a href="/">概况总览</a>
        <a href="/history">扫描历史</a>
        <a href="/scan">新建扫描</a>
        <a href="/runs/{run_id}/report.html">HTML 报告</a>
        <a href="/runs/{run_id}/report.md">Markdown 报告</a>
        <a href="/runs/{run_id}/sbom.cdx.json">CycloneDX SBOM</a>
        <a href="/settings">设置</a>"""
        title_suffix = html.escape(str(run.get("name") or run_id))
    else:
        nav_links = """
        <a href="/">概况总览</a>
        <a href="/history">扫描历史</a>
        <a href="/scan">新建扫描</a>
        <a href="/report.html">HTML 报告</a>
        <a href="/report.md">Markdown 报告</a>
        <a href="/settings">设置</a>"""
        title_suffix = "当前工作区扫描"
    template = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AuditForge 审计工作台</title>
  <style>
    :root {
      --bg: #f4f5f2;
      --panel: #ffffff;
      --panel-soft: #f9faf8;
      --ink: #20231f;
      --muted: #6f766d;
      --line: #dfe3dc;
      --accent: #0d7f6e;
      --accent-strong: #07594d;
      --accent-soft: #e2f3ef;
      --danger: #b42318;
      --danger-soft: #fde7e4;
      --warn: #a15c07;
      --warn-soft: #fff3d6;
      --info: #2457a6;
      --info-soft: #e8eefb;
      --code: #111713;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      background:
        linear-gradient(180deg, #eef1ed 0, var(--bg) 420px),
        var(--bg);
      font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
      line-height: 1.5;
      text-wrap: pretty;
    }
    a { color: var(--accent-strong); text-decoration: none; }
    a:hover { text-decoration: underline; }
    header {
      border-bottom: 1px solid var(--line);
      background: rgba(255,255,255,.82);
      backdrop-filter: blur(14px);
      position: sticky;
      top: 0;
      z-index: 5;
    }
    .topbar {
      max-width: 1280px;
      margin: 0 auto;
      padding: 18px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
    .mark {
      width: 40px;
      height: 40px;
      display: grid;
      place-items: center;
      border-radius: 8px;
      background: var(--code);
      color: #dff8f1;
      font-weight: 800;
      letter-spacing: 0;
    }
    h1 { margin: 0; font-size: 22px; line-height: 1.2; letter-spacing: 0; }
    .repo { color: var(--muted); font-size: 13px; overflow-wrap: anywhere; margin-top: 4px; }
    .nav { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    .nav a, .filter-button {
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      color: var(--ink);
      padding: 8px 11px;
      font-size: 13px;
      cursor: pointer;
    }
    .nav a:hover, .filter-button:hover, .filter-button.active {
      background: var(--accent-soft);
      border-color: #a8d7cd;
      text-decoration: none;
    }
    main {
      max-width: 1280px;
      margin: 0 auto;
      padding: 24px;
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: 18px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 18px 48px rgba(22, 31, 24, .07);
    }
    .sidebar {
      align-self: start;
      position: sticky;
      top: 92px;
      overflow: hidden;
    }
    .side-section { padding: 18px; border-bottom: 1px solid var(--line); }
    .side-section:last-child { border-bottom: 0; }
    .label { color: var(--muted); font-size: 12px; margin-bottom: 8px; }
    .target {
      background: var(--panel-soft);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      color: var(--muted);
      overflow-wrap: anywhere;
      font-size: 13px;
    }
    .metrics { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
    .metric {
      min-height: 78px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 12px;
    }
    .metric span { display: block; color: var(--muted); font-size: 12px; }
    .metric strong { display: block; font-size: 24px; line-height: 1; margin-top: 8px; }
    .rule-list { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
    .rule-list li {
      display: flex;
      gap: 8px;
      align-items: flex-start;
      color: var(--muted);
      font-size: 13px;
    }
    .dot {
      width: 7px;
      height: 7px;
      border-radius: 999px;
      background: var(--accent);
      margin-top: 7px;
      flex: 0 0 auto;
    }
    .workspace { min-width: 0; }
    .hero {
      padding: 22px;
      margin-bottom: 14px;
    }
    .hero-kicker { color: var(--accent); font-size: 13px; font-weight: 800; margin-bottom: 10px; }
    .hero h2 { margin: 0; font-size: 30px; line-height: 1.18; letter-spacing: 0; }
    .hero p { margin: 12px 0 0; color: var(--muted); max-width: 860px; }
    .toolbar {
      padding: 14px;
      display: grid;
      grid-template-columns: minmax(180px, 1fr) auto;
      gap: 12px;
      align-items: center;
      margin-bottom: 14px;
    }
    .search {
      width: 100%;
      min-height: 40px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 9px 11px;
      font: inherit;
      background: var(--panel-soft);
      color: var(--ink);
    }
    .search:focus { outline: 2px solid #a8d7cd; outline-offset: 1px; }
    .filters { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    .candidate-list { display: grid; gap: 10px; }
    .candidate-row {
      padding: 16px;
      transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
    }
    .candidate-row:hover {
      transform: translateY(-1px);
      box-shadow: 0 20px 54px rgba(22, 31, 24, .09);
      border-color: #cbd5ce;
    }
    .candidate-row[hidden] { display: none; }
    .candidate-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: start;
    }
    .candidate-title {
      margin: 0;
      font-size: 17px;
      letter-spacing: 0;
      overflow-wrap: anywhere;
    }
    .tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 9px; }
    .tag {
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 12px;
      border: 1px solid var(--line);
      color: var(--muted);
      background: var(--panel-soft);
      white-space: nowrap;
    }
    .tag.danger { color: var(--danger); background: var(--danger-soft); border-color: #f5c5bf; }
    .tag.warn { color: var(--warn); background: var(--warn-soft); border-color: #efd8a4; }
    .tag.info { color: var(--info); background: var(--info-soft); border-color: #ccd9f3; }
    .tag.ok { color: var(--accent-strong); background: var(--accent-soft); border-color: #a8d7cd; }
    .path {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
      gap: 10px;
      align-items: center;
      margin-top: 14px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
    }
    code {
      background: #edf0ea;
      border: 1px solid #dce1d8;
      border-radius: 6px;
      padding: 2px 6px;
      font-family: Consolas, "SFMono-Regular", monospace;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .arrow { color: var(--accent); font-weight: 800; }
    .evidence { color: var(--muted); margin: 12px 0 0; }
    .flow-section {
      margin-top: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfa;
      overflow: hidden;
    }
    .flow-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-soft);
      font-weight: 800;
    }
    .flow-title span {
      color: var(--muted);
      font-weight: 500;
      font-size: 12px;
    }
    .flow-diagram {
      display: grid;
      gap: 0;
      padding: 12px;
    }
    .flow-node {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      overflow: hidden;
    }
    .flow-node.source { border-color: #a8d7cd; }
    .flow-node.sink { border-color: #f0b4ad; }
    .node-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-soft);
    }
    .node-role {
      font-weight: 800;
      font-size: 13px;
    }
    .node-symbol {
      color: var(--muted);
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .code-window {
      margin: 0;
      padding: 0;
      background: #111713;
      color: #edf4ee;
      overflow-x: auto;
      border-radius: 0;
      font-size: 12px;
      line-height: 1.5;
    }
    .code-window code {
      display: grid;
      background: transparent;
      border: 0;
      border-radius: 0;
      padding: 8px 0;
      color: inherit;
      font-size: inherit;
    }
    .code-line {
      display: grid;
      grid-template-columns: 54px minmax(0, 1fr);
      min-width: 0;
      padding: 0 12px 0 0;
    }
    .code-line.hit {
      background: rgba(13, 127, 110, .22);
      box-shadow: inset 3px 0 0 var(--accent);
    }
    .line-no {
      color: #8fa199;
      text-align: right;
      padding-right: 12px;
      user-select: none;
    }
    .line-text {
      white-space: pre;
      min-width: 0;
    }
    .flow-edge {
      display: grid;
      grid-template-columns: 26px minmax(0, 1fr);
      gap: 10px;
      padding: 10px 10px 10px 16px;
      color: var(--muted);
    }
    .edge-rail {
      display: grid;
      place-items: center;
      color: var(--accent);
      font-weight: 900;
    }
    .edge-copy {
      border: 1px dashed #c9d5ce;
      border-radius: 8px;
      padding: 8px 10px;
      background: #f6f8f5;
      font-size: 13px;
    }
    .edge-copy strong {
      color: var(--ink);
      margin-right: 8px;
    }
    .empty {
      padding: 22px;
      color: var(--muted);
      text-align: center;
    }
    @media (max-width: 980px) {
      main { grid-template-columns: 1fr; }
      .sidebar { position: static; }
      .toolbar { grid-template-columns: 1fr; }
      .filters { justify-content: flex-start; }
    }
    @media (max-width: 640px) {
      .topbar { align-items: flex-start; flex-direction: column; }
      main { padding: 16px; }
      .hero h2 { font-size: 24px; }
      .metrics { grid-template-columns: 1fr; }
      .candidate-head, .path { grid-template-columns: 1fr; }
      .node-head { grid-template-columns: 1fr; }
      .arrow { display: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation: none !important;
        transition: none !important;
        scroll-behavior: auto !important;
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div class="brand">
        <div class="mark">AF</div>
        <div>
          <h1>AuditForge 审计工作台</h1>
          <div class="repo">__RUN_TITLE__ · __REPO_PATH__</div>
        </div>
      </div>
      <nav class="nav" aria-label="报告入口">
        __NAV_LINKS__
      </nav>
    </div>
  </header>
  <main>
    <aside class="panel sidebar">
      <section class="side-section">
        <div class="label">运行目标</div>
        <div class="target">__TARGET_URL__</div>
      </section>
      <section class="side-section">
        <div class="label">扫描指标</div>
        <div class="metrics">__METRICS__</div>
      </section>
      <section class="side-section">
        <div class="label">报告规则</div>
        <ul class="rule-list">
          <li><span class="dot"></span><span>静态结果只进入候选队列。</span></li>
          <li><span class="dot"></span><span>正式漏洞必须绑定复现证据。</span></li>
          <li><span class="dot"></span><span>safe verifier 不执行破坏性 payload。</span></li>
        </ul>
      </section>
    </aside>
    <section class="workspace">
      <div class="panel hero">
        <div class="hero-kicker">自主审计流水线</div>
        <h2>已生成 __TOTAL_CANDIDATES__ 条 source-to-sink 候选路径。</h2>
        <p>每条候选都保留源码锚点、漏洞类型、置信度、验证状态和复现建议。筛选后可直接进入人工复核或自动安全验证。</p>
      </div>
      <div class="panel toolbar">
        <input class="search" id="candidateSearch" placeholder="搜索候选 ID、文件、证据或漏洞类型" aria-label="搜索候选">
        <div class="filters" aria-label="漏洞类型筛选">
          <button class="filter-button active" data-filter="all">全部</button>
          <button class="filter-button" data-filter="injection">注入</button>
          <button class="filter-button" data-filter="xss">XSS</button>
          <button class="filter-button" data-filter="ssrf">SSRF</button>
          <button class="filter-button" data-filter="authz">越权</button>
        </div>
      </div>
      <div class="candidate-list" id="candidateList">
        __CARDS__
      </div>
      <div class="panel empty" id="emptyState" hidden>没有匹配的候选路径。</div>
    </section>
  </main>
  <script>
    const filterButtons = Array.from(document.querySelectorAll('[data-filter]'));
    const searchInput = document.getElementById('candidateSearch');
    const rows = Array.from(document.querySelectorAll('.candidate-row'));
    const emptyState = document.getElementById('emptyState');
    let activeFilter = 'all';

    function applyFilters() {
      const keyword = searchInput.value.trim().toLowerCase();
      let visible = 0;
      rows.forEach((row) => {
        const byType = activeFilter === 'all' || row.dataset.vuln === activeFilter;
        const byText = !keyword || row.textContent.toLowerCase().includes(keyword);
        const show = byType && byText;
        row.hidden = !show;
        if (show) visible += 1;
      });
      emptyState.hidden = visible !== 0;
    }

    filterButtons.forEach((button) => {
      button.addEventListener('click', () => {
        activeFilter = button.dataset.filter;
        filterButtons.forEach((item) => item.classList.toggle('active', item === button));
        applyFilters();
      });
    });
    searchInput.addEventListener('input', applyFilters);
  </script>
</body>
</html>"""
    return (
        template.replace("__REPO_PATH__", repo_path)
        .replace("__RUN_TITLE__", title_suffix)
        .replace("__NAV_LINKS__", nav_links)
        .replace("__TARGET_URL__", target_url)
        .replace("__METRICS__", metrics)
        .replace("__TOTAL_CANDIDATES__", total_candidates)
        .replace("__CARDS__", cards or '<div class="panel empty">未生成候选路径。</div>')
    )


def render_metric(key: str, value: int) -> str:
    return f'<div class="metric"><span>{html.escape(metric_label(key))}</span><strong>{value}</strong></div>'


def render_card(candidate: dict, result: dict | None, repo_path: str, triage: dict | None = None) -> str:
    payload = json.loads(candidate["payload_json"])
    candidate_id = str(candidate["id"])
    vuln_class = str(candidate["vuln_class"])
    confidence = str(candidate["confidence"])
    status = result["status"] if result else "not_run"
    origin = str(payload.get("origin") or "deterministic")
    triage = triage if isinstance(triage, dict) else {}
    triage_status = str(triage.get("status") or "needs_review")
    triage_note = str(triage.get("note") or "")
    source = f"{candidate['source_file']}:{candidate['source_line']}"
    sink = f"{candidate['sink_file']}:{candidate['sink_line']}"
    searchable = " ".join(
        [
            candidate_id,
            vuln_class,
            confidence,
            status,
            origin,
            source,
            sink,
            payload.get("static_evidence", ""),
            payload.get("verification_hint", ""),
            triage_status_label(triage_status),
            triage_note,
            flow_search_text(repo_path, payload),
        ]
    )
    status_class = "ok" if status == "confirmed" else ""
    flow = render_flow_html(repo_path, payload)
    verification = render_verification_block(result)
    finding_title = f"{vuln_label(vuln_class)} · {candidate_id}"
    static_evidence = str(payload.get("static_evidence") or "暂无静态证据摘要。")
    verification_hint = str(payload.get("verification_hint") or "")
    return f"""
<article class="panel candidate-row" data-vuln="{html.escape(vuln_class)}" data-status="{html.escape(status)}" data-search="{html.escape(searchable)}">
  <button class="finding-summary" type="button" data-finding-open data-finding-title="{html.escape(finding_title, quote=True)}" aria-haspopup="dialog">
    <span class="finding-summary-main">
      <span class="finding-summary-heading">
        <code class="finding-summary-id">{html.escape(candidate_id)}</code>
        <strong class="finding-summary-title">{html.escape(vuln_label(vuln_class))}</strong>
      </span>
      <span class="finding-summary-copy">{html.escape(static_evidence)}</span>
      <span class="finding-summary-location">{html.escape(source)} <span aria-hidden="true">→</span> {html.escape(sink)}</span>
    </span>
    <span class="finding-summary-side">
      <span class="finding-summary-tags">
        <span class="tag {severity_tag_class(vuln_class)}">{html.escape(vuln_label(vuln_class))}</span>
        <span class="tag">{html.escape(confidence_label(confidence))}</span>
        <span class="tag {status_class}">{html.escape(status_label(status))}</span>
      </span>
      <span class="finding-summary-action">查看详情 <span aria-hidden="true">→</span></span>
    </span>
  </button>
  <section class="finding-detail-content" data-finding-detail hidden>
    <header class="finding-detail-header">
      <div>
        <p class="case-kicker">{html.escape(candidate_id)}</p>
        <h2>{html.escape(vuln_label(vuln_class))}</h2>
        <p>{html.escape(static_evidence)}</p>
      </div>
      <div class="tags">
        <span class="tag {severity_tag_class(vuln_class)}">{html.escape(vuln_label(vuln_class))}</span>
        <span class="tag">{html.escape(confidence_label(confidence))}</span>
        <span class="tag {status_class}">{html.escape(status_label(status))}</span>
        <span class="tag">{html.escape(origin_label(origin))}</span>
      </div>
    </header>
    <section class="finding-detail-section">
      <div class="finding-detail-section-head"><h3>代码路径</h3><span>source → sink</span></div>
      <div class="path">
        <code>{html.escape(source)}</code>
        <span class="arrow">&rarr;</span>
        <code>{html.escape(sink)}</code>
      </div>
      {flow}
    </section>
    {verification}
    {f'<section class="finding-detail-section"><h3>复核提示</h3><p class="evidence">{html.escape(verification_hint)}</p></section>' if verification_hint else ""}
    {render_triage_box(candidate_id, triage)}
  </section>
</article>"""


def render_triage_box(candidate_id: str, triage: dict | None) -> str:
    triage = triage if isinstance(triage, dict) else {}
    status = str(triage.get("status") or "needs_review")
    if status not in _backend().triage_status_options:
        status = "needs_review"
    note = str(triage.get("note") or "")
    updated_at = str(triage.get("updated_at") or "")
    options = "\n".join(
        f'<option value="{html.escape(value, quote=True)}"{" selected" if value == status else ""}>{html.escape(label)}</option>'
        for value, label in _backend().triage_status_options.items()
    )
    updated = f'<span class="triage-updated">更新：{html.escape(format_time(updated_at))}</span>' if updated_at else ""
    return f"""
  <details class="triage-box" data-triage-candidate="{html.escape(candidate_id, quote=True)}">
    <summary>
      <span>人工复核</span>
      <span class="tag {html.escape(triage_status_class(status))}" data-triage-badge>{html.escape(triage_status_label(status))}</span>
    </summary>
    <div class="triage-body">
      <label>处置状态
        <select data-triage-status>{options}</select>
      </label>
      <label>复核备注
        <textarea data-triage-note maxlength="1000" spellcheck="false" placeholder="记录人工判断、复现条件、误报原因或修复进展">{html.escape(note)}</textarea>
      </label>
      <div class="triage-actions">
        <button type="button" data-triage-save>保存复核</button>
        <span class="status" data-triage-message role="status" aria-live="polite" aria-atomic="true">{updated}</span>
      </div>
    </div>
  </details>"""


def triage_status_label(status: str) -> str:
    return _backend().triage_status_options.get(status, _backend().triage_status_options["needs_review"])


def triage_status_class(status: str) -> str:
    return {
        "accepted": "ok",
        "false_positive": "danger",
        "fixing": "warn",
        "fixed": "ok",
        "needs_review": "info",
    }.get(status, "info")


def render_verification_block(result: dict | None) -> str:
    if not result:
        return ""
    try:
        payload = json.loads(result.get("payload_json") or "{}")
    except json.JSONDecodeError:
        payload = {}
    status = str(payload.get("status") or result.get("status") or "not_run")
    evidence = payload.get("evidence") if isinstance(payload, dict) else []
    if not isinstance(evidence, list):
        evidence = []
    evidence_items = "\n".join(f"<li>{html.escape(str(item))}</li>" for item in evidence[:8])
    request_log = payload.get("request_log") if isinstance(payload, dict) else []
    sandbox_entries = (
        [item for item in request_log if isinstance(item, dict) and item.get("type") == "sandbox_python"]
        if isinstance(request_log, list)
        else []
    )
    sandbox_html = "\n".join(render_sandbox_entry(item) for item in sandbox_entries[:2])
    sandbox_details = (
        f"""
      <details class="sandbox-details">
        <summary>查看容器沙箱测试代码</summary>
        {sandbox_html}
      </details>"""
        if sandbox_html
        else ""
    )
    declarative_details = render_declarative_validation_html(request_log)
    status_class = "ok" if status == "confirmed" else ""
    return f"""
  <section class="verification-box">
    <div class="verification-head">
      <span>验证结果</span>
      <span class="tag {status_class}">{html.escape(status_label(status))}</span>
    </div>
    <ul class="verification-list">{evidence_items or "<li>暂无验证证据。</li>"}</ul>
    {declarative_details}
    {sandbox_details}
  </section>"""


def render_sandbox_entry(entry: dict) -> str:
    name = html.escape(str(entry.get("name") or "沙箱测试"))
    state = "通过" if entry.get("ok") else "未通过"
    code = html.escape(str(entry.get("code") or ""))
    runtime = entry.get("container_runtime") or "未识别"
    image = entry.get("container_image") or ""
    isolation = "容器隔离" if entry.get("isolation") == "container" else "进程隔离"
    meta = f"{isolation} · {runtime}" + (f" · {image}" if image else "")
    error = str(entry.get("error") or entry.get("policy_error") or entry.get("runtime_error") or "")
    error_html = f'<p class="evidence">原因：{html.escape(error)}</p>' if error else ""
    return f"""
        <div class="sandbox-case">
          <p class="evidence"><strong>{name}</strong>：{html.escape(state)}</p>
          <p class="evidence">隔离：{html.escape(meta)}；网络：{html.escape(str(entry.get("network") or "none"))}；只读根文件系统：{html.escape(str(entry.get("read_only_rootfs", True)))}</p>
          <pre class="sandbox-code"><code>{code}</code></pre>
          {error_html}
        </div>"""


def render_flow_html(repo_path: str, payload: dict) -> str:
    nodes = candidate_flow_nodes(payload)
    if not nodes:
        return ""
    parts = [
        '<section class="flow-section">',
        '<div class="flow-title">数据流向图 <span>命中行已高亮，显示上下文源码</span></div>',
        '<div class="flow-diagram">',
    ]
    for index, node in enumerate(nodes):
        if index > 0:
            parts.append(render_edge(node.get("edge")))
        parts.append(render_flow_node(repo_path, node, index + 1))
    parts.extend(["</div>", "</section>"])
    return "\n".join(parts)


def render_edge(step: dict | None) -> str:
    if not step:
        label = "传播"
        explanation = "继续沿候选路径传播。"
    else:
        label = step_kind_label(str(step.get("kind") or ""))
        explanation = str(step.get("explanation") or "候选路径传播步骤。")
    return f"""
<div class="flow-edge">
  <div class="edge-rail">&darr;</div>
  <div class="edge-copy"><strong>{html.escape(label)}</strong>{html.escape(explanation)}</div>
</div>"""


def render_flow_node(repo_path: str, node: dict, sequence: int) -> str:
    anchor = node["anchor"]
    snippet = code_window(repo_path, anchor)
    role = str(node.get("role") or "step")
    symbol = snippet.symbol or anchor.get("symbol") or ""
    symbol_text = f" · {symbol}" if symbol else ""
    return f"""
<div class="flow-node {html.escape(role)}">
  <div class="node-head">
    <div>
      <div class="node-role">{sequence}. {html.escape(str(node.get("title") or role_label(role)))}</div>
      <div class="node-symbol">{html.escape(format_anchor(anchor) + symbol_text)}</div>
    </div>
    <span class="tag {severity_tag_class_for_role(role)}">{html.escape(role_label(role))}</span>
  </div>
  {render_code_window(snippet)}
</div>"""


def render_code_window(snippet) -> str:
    if snippet.error:
        return f'<div class="target">{html.escape(snippet.error)}</div>'
    lines = []
    for item in snippet.lines:
        text = item.text if item.text else " "
        cls = "code-line hit" if item.highlighted else "code-line"
        lines.append(
            f'<span class="{cls}"><span class="line-no">{item.number}</span><span class="line-text">{html.escape(text)}</span></span>'
        )
    return f'<pre class="code-window"><code>{"".join(lines)}</code></pre>'


def flow_search_text(repo_path: str, payload: dict) -> str:
    chunks: list[str] = []
    for node in candidate_flow_nodes(payload):
        snippet = code_window(repo_path, node["anchor"], context=0)
        chunks.extend(line.text for line in snippet.lines)
    return " ".join(chunks)


def step_kind_label(kind: str) -> str:
    labels = {
        "assignment": "赋值传播",
        "call": "函数调用",
        "return": "返回值",
        "branch": "条件分支",
        "framework_binding": "框架绑定",
        "llm_inferred": "语义推断",
    }
    return labels.get(kind, kind or "传播")


def role_label(role: str) -> str:
    return {"source": "输入点", "sink": "危险操作", "step": "传播节点"}.get(role, role)


def severity_tag_class_for_role(role: str) -> str:
    if role == "source":
        return "ok"
    if role == "sink":
        return "danger"
    return "info"


def dependency_severity_label(severity: str) -> str:
    return {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "unknown": "未知等级",
    }.get(severity, severity)


def dependency_severity_tag_class(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "danger"
    if severity == "medium":
        return "warn"
    return "info"


# Greenfield page compositions keep the public renderer API stable.
def render_app_shell(
    workspace: Path,
    active: str,
    title: str,
    body: str,
    *,
    current_run_id: str | None = None,
    recent_runs: list[dict] | None = None,
    extra_script: str = "",
) -> str:
    language = ui_language(workspace)
    page_title = translate_title(title, language)
    return ui_shell.render_shell_document(
        page_title,
        body,
        active_page=active,
        recent_runs=recent_runs if recent_runs is not None else _server_load_runs(workspace),
        current_run_id=current_run_id,
        workspace_label=str(workspace.resolve()),
        language=language,
        extra_head_html=f"<style>{APP_CSS}</style>",
        extra_script_html=render_i18n_script(language) + ui_pages.API_FEEDBACK_SCRIPT + extra_script,
        include_page_header=False,
    )


def render_page_head(title: str, subtitle: str, actions: str = "") -> str:
    return f"""
      <header class="page-header">
        <div class="page-header-copy"><p class="page-kicker">AUDIT WORKSPACE</p><h1>{html.escape(title)}</h1><p>{html.escape(subtitle)}</p></div>
        {f'<nav class="page-header-actions" aria-label="页面快捷操作">{actions}</nav>' if actions else ""}
      </header>"""


def render_login_page(token_path: Path | None) -> str:
    return ui_pages.render_login_document(token_path, APP_CSS)


def render_overview_page(workspace: Path) -> str:
    runs = _server_load_runs(workspace)
    overview = build_home_overview(workspace, runs)
    body = ui_pages.render_overview_body(overview, runs, render_run_row)
    return render_app_shell(workspace, "overview", "概况总览", body, recent_runs=runs)


def render_scan_page(workspace: Path) -> str:
    settings = public_settings(load_workspace_settings(workspace))
    llm = settings.get("llm") if isinstance(settings.get("llm"), dict) else {}
    connection = llm.get("connection") if isinstance(llm.get("connection"), dict) else llm
    enabled = bool(connection.get("enabled"))
    llm_status = "已配置" if enabled else "未启用"
    body = ui_pages.render_scan_body(render_scan_form(workspace, llm_status), enabled)
    return render_app_shell(workspace, "scan", "新建扫描", body, extra_script=SCAN_SCRIPT)


def render_scan_form(workspace: Path, llm_status: str) -> str:
    roots = configured_repo_roots(workspace)
    root_hint = "; ".join(str(root) for root in roots) if roots else "未配置本地仓库白名单，请改用 ZIP 上传"
    upload_limit = _backend().max_upload_bytes // (1024 * 1024)
    extracted_limit = _backend().max_zip_uncompressed_bytes // (1024 * 1024)
    return f"""
      <form id="scanForm" class="scan-form" enctype="multipart/form-data">
        <section class="form-section">
          <div class="form-section-head"><span>01</span><div><h3>任务身份</h3><p>使用可辨认的名称区分仓库、分支或审计批次。</p></div></div>
          <label for="scanName">扫描名称</label>
          <input id="scanName" name="name" placeholder="例如：订单服务安全复核">
        </section>

        <section class="form-section">
          <div class="form-section-head"><span>02</span><div><h3>代码来源</h3><p>本地路径必须位于允许根目录内，上传包会在隔离工作区解压。</p></div></div>
          <div class="scan-source-switch" role="radiogroup" aria-label="代码来源">
            <input id="sourcePath" type="radio" name="sourceType" value="path" checked>
            <label for="sourcePath">本地仓库</label>
            <input id="sourceUpload" type="radio" name="sourceType" value="upload">
            <label for="sourceUpload">ZIP 代码包</label>
          </div>
          <div id="repoPathField" class="field-stack">
            <label for="repoPath">仓库路径</label>
            <input id="repoPath" name="repoPath" placeholder="C:\\path\\to\\repo">
            <small>{html.escape(root_hint)}</small>
          </div>
          <div id="repoZipField" class="field-stack hidden">
            <label for="repoZip">ZIP 代码包</label>
            <input id="repoZip" name="repoZip" type="file" accept=".zip,application/zip">
            <small>上传上限 {upload_limit} MB，解压上限 {extracted_limit} MB</small>
          </div>
        </section>

        <section class="form-section">
          <div class="form-section-head"><span>03</span><div><h3>验证策略</h3><p>动态验证只应针对自有或明确授权的隔离目标。</p></div></div>
          <div class="mode-grid" role="radiogroup" aria-label="验证模式">
            {verification_mode("none", "静态候选", "不连接运行目标", checked=True)}
            {verification_mode("safe", "Safe", "只读 GET/HEAD 探测")}
            {verification_mode("stateful", "Stateful", "允许受控写入测试数据")}
            {verification_mode("deep", "Deep", "固定镜像容器验证")}
            {verification_mode("safe+deep", "Hybrid", "目标探测 + 并行容器复核")}
          </div>
          <div class="field-stack">
            <label for="targetUrl">运行目标 URL</label>
            <input id="targetUrl" name="targetUrl" inputmode="url" placeholder="http://127.0.0.1:3000">
            <small>safe/stateful/hybrid 使用，必须是 HTTP(S) 同源目标；纯 Deep 可留空。</small>
          </div>
        </section>

        <section class="form-section">
          <div class="form-section-head"><span>04</span><div><h3>扩展分析</h3><p>语义候选与依赖风险使用独立模型配置。</p></div></div>
          <label class="checkline"><input name="useLlm" type="checkbox" value="true"><span><strong>LLM 语义候选</strong><small>当前状态：{html.escape(llm_status)}</small></span></label>
          <label class="checkline"><input name="scanDependencies" type="checkbox" value="true"><span><strong>依赖风险分析</strong><small>解析 requirements、pom、package.json 与 go.mod，当前状态：{html.escape(llm_status)}</small></span></label>
        </section>

        <div class="form-submit-row">
          <div><strong>准备创建任务</strong><p class="form-note">扫描制品、报告与日志会写入独立运行目录。</p></div>
          <button class="primary" type="submit">启动扫描</button>
        </div>
        <div class="status" id="scanStatus" role="status" aria-live="polite" aria-atomic="true"></div>
      </form>"""


def verification_mode(value: str, title: str, description: str, *, checked: bool = False) -> str:
    checked_attr = " checked" if checked else ""
    safe_value = html.escape(value, quote=True)
    return f'<label class="mode-option"><input type="radio" name="verify" value="{safe_value}"{checked_attr}><span><strong>{html.escape(title)}</strong><small>{html.escape(description)}</small></span></label>'


def render_history_page(workspace: Path) -> str:
    runs = _server_load_runs(workspace)
    language = ui_language(workspace)
    body = ui_pages.render_history_body(runs, lambda run: render_run_row(run, allow_delete=True, language=language))
    return render_app_shell(workspace, "history", "扫描历史", body, recent_runs=runs, extra_script=RUN_DELETE_SCRIPT)


def render_logs_page(workspace: Path) -> str:
    return render_app_shell(workspace, "logs", "运行日志", ui_pages.render_logs_body(), extra_script=LOGS_SCRIPT)


def format_run_error(run: dict, language: str = DEFAULT_LANGUAGE) -> str:
    message = str(run.get("error") or "").strip()
    failure = run.get("failure") if isinstance(run.get("failure"), dict) else {}
    code = str(failure.get("code") or "").strip()
    action = str(failure.get("action") or "").strip()
    reference = str(failure.get("diagnostic_id") or failure.get("reference") or "").strip()
    if not any((message, code, action, reference)):
        return ""
    translated = ERROR_TRANSLATIONS.get(language, {}).get(code, {})
    message = str(translated.get("message") or translate_title(message, language)).strip()
    action = str(translated.get("action") or translate_title(action, language)).strip()
    fallback = translate_title("任务执行失败。", language)
    code_label = translate_title("错误代码", language)
    action_label = translate_title("处理建议", language)
    reference_label = translate_title("诊断编号", language)
    colon = ": " if language == "en-US" else "："
    separator = "; " if language == "en-US" else "；"
    parts = [f"{message or fallback}" + (f" {code_label}{colon}{code}" if code else "")]
    if action:
        parts.append(f"{action_label}{colon}{action}")
    if reference:
        parts.append(f"{reference_label}{colon}{reference}")
    return separator.join(parts)


def render_run_row(run: dict, *, allow_delete: bool = False, language: str = DEFAULT_LANGUAGE) -> str:
    raw_run_id = str(run.get("id") or "")
    run_id = html.escape(raw_run_id, quote=True)
    status = str(run.get("status") or "unknown")
    stats = run.get("stats") if isinstance(run.get("stats"), dict) else {}
    inventory = run.get("project_inventory") if isinstance(run.get("project_inventory"), dict) else {}
    status_text = {"completed": "已完成", "running": "扫描中", "failed": "失败"}.get(status, status)
    status_class = {"completed": "ok", "running": "info", "failed": "danger"}.get(status, "warn")
    verify_label = {
        "none": "静态候选",
        "safe": "Safe 验证",
        "stateful": "Stateful 验证",
        "deep": "Deep 沙箱",
        "safe+deep": "Safe + Deep",
        "stateful+deep": "Stateful + Deep",
    }.get(str(run.get("verify") or "none"), "静态候选")
    source = str(run.get("source_label") or run.get("repo_path") or "未记录代码源")
    created = format_time(str(run.get("created_at") or ""))
    error = format_run_error(run, language)
    action_label = "查看证据" if status == "completed" else "查看进度"
    actions = f'<a href="/runs/{run_id}">{action_label}</a>'
    if status == "completed":
        actions += f'<a href="/runs/{run_id}/export.zip">导出证据</a>'
    if allow_delete:
        actions += render_delete_run_button(run)
    return f"""
      <article class="activity-row run-row" data-run-row="{run_id}">
        <div class="activity-main">
          <div class="run-heading"><span class="status-chip {status_class}">{html.escape(status_text)}</span><h3>{html.escape(str(run.get("name") or raw_run_id))}</h3></div>
          <p class="run-source">{html.escape(source)}</p>
          <div class="activity-meta">
            <span>{html.escape(created)}</span><span>{html.escape(verify_label)}</span>
            <span>{int(inventory.get("total_lines") or stats.get("code_lines") or 0):,} 行</span>
            <span>{int(stats.get("candidates") or 0)} 个候选</span>
            <span>{int(stats.get("dependency_findings") or 0)} 个依赖风险</span>
          </div>
          {f'<p class="status error" role="alert">{html.escape(error)}</p>' if error else ""}
        </div>
        <div class="actions">{actions}</div>
      </article>"""


def render_run_status_page(workspace: Path, run: dict) -> str:
    run_view = dict(run)
    run_view["error"] = format_run_error(run, ui_language(workspace))
    body = ui_run_pages.render_run_status_body(
        run_view,
        render_scan_progress_panel(run)
        + '<div class="progress-detail error" data-progress-error role="alert" aria-live="assertive" aria-atomic="true" hidden></div>',
        render_project_inventory_panel(run.get("project_inventory")),
        render_delete_run_button(run),
        render_cancel_run_button(run),
    )
    return render_app_shell(
        workspace,
        "run",
        str(run.get("name") or run.get("id") or "任务详情"),
        body,
        current_run_id=str(run.get("id") or ""),
        extra_script=RUN_PROGRESS_SCRIPT + RUN_CANCEL_SCRIPT + RUN_DELETE_SCRIPT,
    )


def render_run_detail_page(platform_workspace: Path, run_workspace: Path, run: dict) -> str:
    data = read_dashboard_detail(run_workspace)
    scan = data.get("scan") or {}
    stats = json.loads(scan.get("stats_json") or "{}")
    candidates = data.get("candidates") or []
    results = {item["candidate_id"]: item for item in data.get("verification_results") or []}
    artifacts = data.get("artifacts") or {}
    dependency_inventory = artifacts.get("dependency_inventory") or []
    dependency_findings = artifacts.get("dependency_findings") or []
    dependency_diagnostics = artifacts.get("dependency_diagnostics") or {}
    project_inventory = (
        artifacts.get("project_inventory")
        or run.get("project_inventory")
        or _server_read_json_file(run_workspace / "project_inventory.json", {})
    )
    triage_items = _server_load_triage_notes(run_workspace).get("items", {})
    candidate_sections = partition_candidate_rows(candidates, results)
    active_result_tab = default_result_partition(candidate_sections, dependency_findings)
    result_tabs = render_result_partition_tabs(candidate_sections, dependency_findings, active_tab=active_result_tab)
    toolbar_hidden = " hidden" if active_result_tab == "dependency" else ""
    filter_toolbar = f"""
      <div class="candidate-toolbar" data-candidate-toolbar{toolbar_hidden}>
        <input class="search" id="candidateSearch" placeholder="搜索候选 ID、文件、证据或漏洞类型" aria-label="搜索候选">
        <div class="filters" aria-label="漏洞类型筛选">
          <button class="filter-button active" type="button" data-filter="all">全部</button>
          <button class="filter-button" type="button" data-filter="injection">注入</button>
          <button class="filter-button" type="button" data-filter="xss">XSS</button>
          <button class="filter-button" type="button" data-filter="ssrf">SSRF</button>
          <button class="filter-button" type="button" data-filter="auth">认证</button>
          <button class="filter-button" type="button" data-filter="authz">越权</button>
        </div>
      </div>"""
    result_sections = render_result_partitions(
        candidate_sections,
        dependency_inventory,
        dependency_findings,
        dependency_diagnostics,
        stats,
        bool(run.get("dependency_scan")),
        str(scan.get("repo_path") or ""),
        triage_items if isinstance(triage_items, dict) else {},
        active_result_tab,
    )
    result_sections += '<div class="empty-command" id="emptyState" hidden>没有匹配当前筛选条件的候选路径。</div>'
    run_id = html.escape(str(run.get("id") or ""), quote=True)
    actions = (
        '<a href="/history">任务档案</a>'
        f'<a href="/runs/{run_id}/report.html">HTML 报告</a>'
        f'<a href="/runs/{run_id}/report.md">Markdown</a>'
        f'<a href="/runs/{run_id}/sbom.cdx.json">SBOM</a>'
        f'<a href="/runs/{run_id}/export.zip">导出证据</a>'
        f"{render_delete_run_button(run)}"
    )
    body = ui_run_pages.render_run_detail_body(
        run,
        scan,
        "".join(render_metric(key, value) for key, value in stats.items()),
        render_project_inventory_panel(project_inventory),
        render_scan_progress_panel(run) if run.get("progress") else '<p class="subtle">历史任务未保存进度明细。</p>',
        render_scan_diagnostics_panel(run, artifacts),
        result_tabs + filter_toolbar,
        result_sections,
        actions,
    )
    return render_app_shell(
        platform_workspace,
        "run",
        str(run.get("name") or run.get("id") or "任务详情"),
        body,
        current_run_id=str(run.get("id") or ""),
        extra_script=CANDIDATE_FILTER_SCRIPT + FINDING_DRAWER_SCRIPT + TRIAGE_SCRIPT + RUN_DELETE_SCRIPT,
    )


# Settings workbench adapters. The pure markup and interaction implementation
# lives in ui_settings; this module keeps the established public renderer API.
def render_settings_page(workspace: Path) -> str:
    settings = public_settings(load_workspace_settings(workspace))
    defaults = public_settings(default_settings())
    body = render_page_head(
        "设置",
        "统一维护 LLM 连接参数，并分别配置污点候选、依赖审计与二次审计的模型和提示词。",
        '<a class="primary-link" href="/scan">新建扫描</a>',
    )
    body += ui_settings.render_settings_body()
    script = ui_settings.render_settings_script(settings, defaults)
    return render_app_shell(workspace, "settings", "设置", body, extra_script=script)


def render_llm_connection_settings() -> str:
    return ui_settings.render_llm_connection_settings()


def render_llm_profile_settings(profile: str, title: str, description: str) -> str:
    return ui_settings.render_llm_profile_settings(profile, title, description)


def render_language_settings() -> str:
    return ui_settings.render_language_settings()


def render_cli_settings() -> str:
    return ui_settings.render_cli_settings()
