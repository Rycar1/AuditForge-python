from __future__ import annotations

import html
import json
from pathlib import Path

from ..analysis.project_inventory import inventory_summary
from ..core.models import DependencyFinding, ScanResult, TraceCandidate, VerificationResult
from ..core.snippets import candidate_flow_nodes, code_window, format_anchor
from ..core.utils import atomic_write_text
from .result_sections import collect_declarative_validation_runs, redact_validation_payload, section_id_for_verification


def write_reports(workspace: Path, result: ScanResult) -> None:
    markdown = render_markdown(result)
    html_report = render_html(result, markdown)
    atomic_write_text(workspace / "report.md", markdown)
    atomic_write_text(workspace / "report.html", html_report)


def render_markdown(result: ScanResult) -> str:
    results_by_id = {item.candidate_id: item for item in result.verification_results}
    lines = [
        "# AuditForge 白盒审计报告",
        "",
        f"- 代码仓库：`{result.repo_path}`",
        f"- 目标地址：`{result.target_url or '未提供'}`",
        "",
        "## 项目盘点",
        "",
    ]
    lines.extend(render_project_inventory_markdown(result.project_inventory))
    lines.extend(
        [
            "## 扫描概览",
            "",
        ]
    )
    for key, value in result.stats().items():
        lines.append(f"- {metric_label(key)}：{value}")
    lines.extend(render_analysis_completeness_markdown(result))
    lines.extend(
        [
            "",
            "## 审计结论",
            "",
            "静态分析阶段只生成候选路径；未通过动态复现的候选不会进入已确认漏洞区。",
            "",
        ]
    )
    lines.extend(render_dependency_markdown(result))
    lines.extend(
        [
            "## 已确认漏洞",
            "",
        ]
    )
    confirmed = [
        candidate
        for candidate in result.candidates
        if section_id_for_verification(results_by_id.get(candidate.id)) == "confirmed_vulnerabilities"
    ]
    if not confirmed:
        lines.append("暂无已确认漏洞。静态候选仍需运行时证据支撑。")
    for candidate in confirmed:
        lines.extend(render_candidate_markdown(candidate, results_by_id[candidate.id], result.repo_path))
    sandbox_executed = [
        candidate
        for candidate in result.candidates
        if section_id_for_verification(results_by_id.get(candidate.id)) == "sandbox_executed_reviews"
    ]
    lines.extend(["", "## 沙箱执行待复核", ""])
    if not sandbox_executed:
        lines.append("暂无完成容器沙箱执行的候选。")
    for candidate in sandbox_executed:
        lines.extend(render_candidate_markdown(candidate, results_by_id[candidate.id], result.repo_path))
    lines.extend(["", "## 静态候选路径", ""])
    pending = [
        candidate
        for candidate in result.candidates
        if section_id_for_verification(results_by_id.get(candidate.id)) == "candidate_vulnerabilities"
    ]
    if not pending:
        lines.append("暂无待复核静态候选。")
    for candidate in pending:
        verification = results_by_id.get(candidate.id)
        lines.extend(render_candidate_markdown(candidate, verification, result.repo_path))
    archived = [
        candidate for candidate in result.candidates if section_id_for_verification(results_by_id.get(candidate.id)) == "archived_results"
    ]
    lines.extend(["", "## 已归档验证结果", ""])
    if not archived:
        lines.append("暂无已归档结果。")
    for candidate in archived:
        lines.extend(render_candidate_markdown(candidate, results_by_id[candidate.id], result.repo_path))
    return "\n".join(lines) + "\n"


def render_analysis_completeness_markdown(result: ScanResult) -> list[str]:
    diagnostics = result.facts.analysis_diagnostics or {}
    inventory = result.project_inventory or {}
    truncated = bool(diagnostics.get("truncated")) or bool(inventory.get("truncated"))
    error_files = int(diagnostics.get("error_files") or 0)
    skipped_files = int(diagnostics.get("skipped_files") or 0)
    complete = not truncated and error_files == 0
    status = "完整" if complete else "不完整，请勿将本报告视为全量审计结论"
    lines = ["", "## 扫描完整性", "", f"- 状态：**{status}**"]
    if truncated:
        lines.append(f"- 截断：是；至少 {int(diagnostics.get('truncated_files') or 0):,} 个源码文件未进入分析")
    if error_files:
        lines.append(f"- 分析错误文件：{error_files:,}")
    if skipped_files:
        lines.append(f"- 跳过文件：{skipped_files:,}（原因详见压缩图证据包 `code_graph/manifest.json`）")
    coverage = getattr(result, "analysis_coverage", {}) or {}
    if coverage:
        lines.extend(
            [
                f"- 分析置信分：**{float(coverage.get('score') or 0):.1f}/100**（衡量可观察覆盖，不代表漏洞检出率）",
                f"- 覆盖状态：`{coverage.get('status') or 'unknown'}`",
            ]
        )
        dimensions = coverage.get("dimensions") if isinstance(coverage.get("dimensions"), dict) else {}
        for name, item in dimensions.items():
            if not isinstance(item, dict):
                continue
            score_value = item.get("score")
            score_text = "未启用" if score_value is None else f"{float(score_value):.1f}%"
            lines.append(f"  - `{name}`：{score_text}（{int(item.get('covered') or 0)}/{int(item.get('total') or 0)}）")
        blindspots = coverage.get("blindspots") if isinstance(coverage.get("blindspots"), list) else []
        if blindspots:
            lines.append("- 主要分析盲区：")
            for item in blindspots[:10]:
                if not isinstance(item, dict):
                    continue
                rescan = item.get("auto_rescan") if isinstance(item.get("auto_rescan"), dict) else {}
                rescan_text = f"；补扫：{rescan.get('status')}" if rescan.get("scheduled") else ""
                lines.append(
                    f"  - **{str(item.get('severity') or 'info').upper()}** `{item.get('id')}` × "
                    f"{int(item.get('count') or 0)}：{item.get('reason')}{rescan_text}"
                )
    frontends = diagnostics.get("language_frontends") if isinstance(diagnostics.get("language_frontends"), dict) else {}
    if frontends:
        details = "、".join(f"{name} × {int(count)}" for name, count in sorted(frontends.items()))
        lines.append(f"- 语言语义前端：{details}（轻量结构化分析，非完整编译器 AST）")
    lines.append("")
    return lines


def render_candidate_markdown(candidate: TraceCandidate, verification: VerificationResult | None, repo_path: str) -> list[str]:
    lines = [
        f"### {candidate.id}（{vuln_label(candidate.vuln_class)}，{confidence_label(candidate.confidence)}）",
        "",
        f"- Source：`{candidate.source.file}:{candidate.source.start_line}`",
        f"- Sink：`{candidate.sink.file}:{candidate.sink.start_line}`",
        f"- 静态证据：{candidate.static_evidence}",
        f"- 复现建议：{candidate.verification_hint}",
        f"- 运行时状态：`{status_label(verification.status if verification else 'not_run')}`",
        f"- 来源：`{origin_label(candidate.origin)}`",
    ]
    if candidate.reviewer_notes:
        lines.append(f"- LLM说明：{'；'.join(candidate.reviewer_notes)}")
    if candidate.blockers:
        lines.append(f"- 阻断条件：{'；'.join(candidate.blockers)}")
    if verification and verification.evidence:
        lines.append("- 证据：")
        lines.extend(f"  - {item}" for item in verification.evidence)
    if verification:
        lines.extend(render_declarative_validation_markdown(verification.request_log))
    lines.extend(render_flow_markdown(repo_path, candidate.to_dict()))
    lines.append("")
    return lines


def render_declarative_validation_markdown(request_log: object) -> list[str]:
    runs = collect_declarative_validation_runs(request_log)
    if not runs:
        return []
    lines = ["- 声明式验证证据："]
    for run in runs:
        plan = run.get("plan") if isinstance(run.get("plan"), dict) else {}
        result = run.get("result") if isinstance(run.get("result"), dict) else {}
        runner = run.get("runner") if isinstance(run.get("runner"), dict) else {}
        plan_id = str(plan.get("id") or run.get("plan_id") or result.get("plan_id") or "未标识计划")
        lines.append(f"  - 计划 `{plan_id}`")
        description = str(redact_validation_payload(plan.get("description") or ""))
        if description:
            lines.append(f"    - 说明：{description}")
        if runner:
            mode = str(runner.get("mode") or "unknown")
            ready = "已连接" if runner.get("configured") is True else "未配置"
            lines.append(f"    - Runner：`{mode}` · {ready}")
        cleanup = plan.get("cleanup") if isinstance(plan.get("cleanup"), dict) else {}
        if cleanup:
            lines.append(f"    - 清理策略：`{cleanup.get('strategy') or 'none'}`")
        steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
        if steps:
            lines.append("    - 计划步骤：")
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_id = str(step.get("id") or "step")
            action = validation_action_label(str(step.get("action") or step.get("type") or "unknown"))
            method = str(step.get("method") or "")
            url = str(redact_validation_payload(step.get("url") or "", key="url"))
            target = " ".join(part for part in (method, f"`{url}`" if url else "") if part)
            lines.append(f"      - `{step_id}` · {action}{f' · {target}' if target else ''}")
            expected = step.get("expected") if isinstance(step.get("expected"), dict) else {}
            if expected:
                lines.append(f"        - 断言：`{validation_value_text(expected)}`")
            blocked_reason = str(redact_validation_payload(step.get("blocked_reason") or ""))
            if blocked_reason:
                lines.append(f"        - 阻断原因：{blocked_reason}")
        if result:
            result_status = str(result.get("status") or "inconclusive")
            lines.append(f"    - Runner 结论：`{validation_result_label(result_status)}`")
            cleanup_status = str(result.get("cleanup_status") or "not_run")
            lines.append(f"    - 清理状态：`{cleanup_status}`")
            notes = str(redact_validation_payload(result.get("notes") or ""))
            if notes:
                lines.append(f"    - 备注：{notes}")
        evidence = result.get("evidence") if isinstance(result.get("evidence"), list) else []
        for item in evidence:
            if not isinstance(item, dict):
                continue
            step_id = str(item.get("step_id") or "step")
            status = validation_evidence_label(str(item.get("status") or "unknown"))
            summary = str(redact_validation_payload(item.get("summary") or ""))
            lines.append(f"    - 证据 `{step_id}` · {status}：{summary or '无摘要'}")
            observed = redact_validation_payload(item.get("observed") or {})
            if not isinstance(observed, dict) or not observed:
                continue
            method = str(observed.get("method") or "")
            url = str(observed.get("url") or "")
            response_status = observed.get("status")
            if method or url or isinstance(response_status, int):
                lines.append(
                    f"      - 脱敏响应：{method or '-'} `{url or '-'}` · HTTP {response_status if isinstance(response_status, int) else '-'}"
                )
            assertions = observed.get("assertions")
            if isinstance(assertions, dict) and assertions:
                lines.append(f"      - 断言结果：`{validation_value_text(assertions)}`")
            headers = observed.get("headers")
            if isinstance(headers, dict) and headers:
                lines.append(f"      - 响应头：`{validation_value_text(headers)}`")
            body = str(observed.get("body_sample") or "")
            if body:
                lines.append("      - 响应正文（已脱敏/限长）：")
                lines.extend(f"        {body_line}" for body_line in body.splitlines() or [body])
            error = str(observed.get("error") or "")
            if error:
                lines.append(f"      - 失败原因：{error}")
    return lines


def render_project_inventory_markdown(inventory: dict | None) -> list[str]:
    if not isinstance(inventory, dict) or not inventory:
        return ["暂无项目盘点数据。", ""]
    lines = [
        inventory_summary(inventory),
        "",
        f"- 代码总行数：{int(inventory.get('total_lines') or 0):,}",
        f"- 语言数量：{int(inventory.get('language_count') or 0)}",
        f"- 统计文件：{int(inventory.get('file_count') or 0):,}",
        f"- 跳过文件：{int(inventory.get('skipped_files') or 0):,}",
        "",
    ]
    languages = inventory.get("languages") if isinstance(inventory.get("languages"), list) else []
    for item in languages:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"- {item.get('language') or item.get('id') or 'Unknown'}："
            f"{int(item.get('lines') or 0):,} 行 · {float(item.get('percent') or 0.0):.1f}%"
        )
    lines.append("")
    return lines


def render_dependency_markdown(result: ScanResult) -> list[str]:
    lines = ["## 依赖风险扫描", ""]
    diagnostics = result.dependency_diagnostics or {}
    if not diagnostics.get("enabled") and not result.dependency_inventory:
        lines.append("未启用 LLM 依赖风险扫描。")
        lines.append("")
        return lines
    package_count = sum(len(manifest.dependencies) for manifest in result.dependency_inventory)
    lines.append(f"- 依赖清单：{len(result.dependency_inventory)}")
    lines.append(f"- 依赖数量：{package_count}")
    lines.append(f"- 风险候选：{len(result.dependency_findings)}")
    if diagnostics.get("error"):
        lines.append(f"- LLM 诊断：{diagnostics['error']}")
    if not result.dependency_findings:
        lines.append("")
        lines.append("暂无 LLM 依赖风险候选；仍建议使用 OSV/NVD 或企业 SCA 工具做权威复核。")
        lines.append("")
        return lines
    lines.append("")
    for finding in result.dependency_findings:
        lines.extend(render_dependency_finding_markdown(finding))
    return lines


def render_dependency_finding_markdown(finding: DependencyFinding) -> list[str]:
    advisories = finding.advisory_ids or finding.cve_ids
    advisory_text = ", ".join(advisories) if advisories else "未给出明确公告编号"
    location = f"{finding.manifest_file}:{finding.line}" if finding.line else finding.manifest_file
    lines = [
        f"### {finding.id}（{finding.package}，{dependency_severity_label(finding.severity)}）",
        "",
        f"- 清单位置：`{location}`",
        f"- 生态：`{finding.ecosystem}`",
        f"- 当前版本/约束：`{finding.installed_version or '未知'}`",
        f"- 影响范围：`{finding.affected_range or '未知'}`",
        f"- 漏洞公告：{advisory_text}",
        f"- 数据来源：{finding.source.upper()}",
        f"- 置信度：{confidence_label(finding.confidence)}",
        f"- 证据：{finding.evidence}",
        f"- 建议：{finding.recommendation}",
    ]
    if finding.fixed_versions:
        lines.insert(9, f"- 官方修复版本：{', '.join(finding.fixed_versions)}")
    if finding.references:
        lines.append(f"- 引用：{'；'.join(finding.references)}")
    lines.append("")
    return lines


def render_flow_markdown(repo_path: str, payload: dict) -> list[str]:
    lines = ["", "#### 数据流向与源码", ""]
    nodes = candidate_flow_nodes(payload)
    for index, node in enumerate(nodes, start=1):
        anchor = node["anchor"]
        snippet = code_window(repo_path, anchor, context=1)
        role = role_label(str(node.get("role") or "step"))
        title = str(node.get("title") or role)
        lines.append(f"{index}. {title}（{role}）：`{format_anchor(anchor)}`")
        edge = node.get("edge")
        if edge and edge.get("explanation"):
            lines.append(f"   - 传播说明：{edge['explanation']}")
        if snippet.error:
            lines.append(f"   - 源码：{snippet.error}")
            continue
        lines.append("")
        lines.append("```")
        for item in snippet.lines:
            marker = ">" if item.highlighted else " "
            lines.append(f"{marker} {item.number:>4} | {item.text}")
        lines.append("```")
        lines.append("")
    return lines


def render_html(result: ScanResult, markdown: str) -> str:
    cards = "\n".join(render_candidate_card(candidate, result) for candidate in result.candidates)
    coverage_section = render_analysis_coverage_html(result.analysis_coverage)
    dependency_section = render_dependency_section_html(result)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AuditForge 白盒审计报告</title>
  <style>
    :root {{
      --bg: #f4f5f2;
      --panel: #ffffff;
      --panel-soft: #f9faf8;
      --ink: #20231f;
      --muted: #6f766d;
      --line: #dfe3dc;
      --accent: #0d7f6e;
      --accent-soft: #e2f3ef;
      --danger: #b42318;
      --danger-soft: #fde7e4;
      --warn: #a15c07;
      --warn-soft: #fff3d6;
      --info: #2457a6;
      --info-soft: #e8eefb;
      --code: #111713;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background:
        linear-gradient(180deg, #eef1ed 0, var(--bg) 340px),
        var(--bg);
      font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
      line-height: 1.55;
      text-wrap: pretty;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: rgba(255,255,255,.78);
      backdrop-filter: blur(14px);
      position: sticky;
      top: 0;
      z-index: 2;
    }}
    .topbar {{
      max-width: 1240px;
      margin: 0 auto;
      padding: 18px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
    }}
    .brand {{ display: flex; align-items: center; gap: 12px; min-width: 0; }}
    .mark {{
      width: 38px;
      height: 38px;
      border-radius: 8px;
      display: grid;
      place-items: center;
      background: var(--code);
      color: #dff8f1;
      font-weight: 800;
      font-size: 15px;
      letter-spacing: 0;
    }}
    h1 {{ margin: 0; font-size: 22px; line-height: 1.2; letter-spacing: 0; }}
    .repo {{ color: var(--muted); font-size: 13px; overflow-wrap: anywhere; margin-top: 4px; }}
    .pill {{
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 7px 11px;
      background: var(--panel);
      color: var(--muted);
      font-size: 13px;
      white-space: nowrap;
    }}
    main {{ max-width: 1240px; margin: 0 auto; padding: 24px; }}
    .hero {{
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(280px, .75fr);
      gap: 16px;
      align-items: stretch;
      margin-bottom: 18px;
    }}
    .statement, .summary-card, .candidate-card, .markdown-box {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 16px 40px rgba(21, 30, 24, .06);
    }}
    .statement {{ padding: 24px; }}
    .eyebrow {{ color: var(--accent); font-weight: 700; font-size: 13px; margin-bottom: 10px; }}
    .statement h2 {{ margin: 0; font-size: 30px; line-height: 1.16; letter-spacing: 0; max-width: 760px; }}
    .statement p {{ color: var(--muted); max-width: 780px; margin: 14px 0 0; }}
    .summary-card {{ padding: 18px; }}
    .summary-card h2, .section-title {{ margin: 0 0 12px; font-size: 16px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
    .metric {{
      min-height: 78px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 12px;
    }}
    .metric span {{ color: var(--muted); font-size: 12px; }}
    .metric strong {{ display: block; font-size: 24px; line-height: 1.1; margin-top: 6px; }}
    .inventory-card {{
      display: grid;
      gap: 12px;
      margin-bottom: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 13px;
    }}
    .inventory-card p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}
    .language-list {{ display: grid; gap: 9px; }}
    .language-row {{ display: grid; gap: 6px; }}
    .language-row-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: baseline; font-size: 13px; }}
    .language-row-head span {{ color: var(--muted); font-size: 12px; white-space: nowrap; }}
    .language-track {{ height: 8px; border-radius: 999px; background: #e7ebe5; overflow: hidden; border: 1px solid #dfe3dc; }}
    .language-track i {{ display: block; height: 100%; min-width: 3px; border-radius: inherit; background: var(--accent); }}
    .section-head {{
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 16px;
      margin: 26px 0 12px;
    }}
    .section-head p {{ margin: 0; color: var(--muted); font-size: 14px; }}
    .candidate-card {{ padding: 16px; margin: 12px 0; }}
    .dependency-grid {{ display: grid; gap: 10px; margin: 12px 0 22px; }}
    .dependency-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 15px;
      box-shadow: 0 14px 32px rgba(21, 30, 24, .05);
    }}
    .dependency-card p {{ margin: 10px 0 0; color: var(--muted); }}
    .dependency-meta {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }}
    .candidate-top {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }}
    .candidate-card h3 {{ margin: 0; font-size: 17px; letter-spacing: 0; }}
    .tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }}
    .tag {{ border-radius: 999px; padding: 4px 8px; font-size: 12px; border: 1px solid var(--line); color: var(--muted); background: var(--panel-soft); }}
    .tag.danger {{ color: var(--danger); background: var(--danger-soft); border-color: #f5c5bf; }}
    .tag.warn {{ color: var(--warn); background: var(--warn-soft); border-color: #efd8a4; }}
    .tag.info {{ color: var(--info); background: var(--info-soft); border-color: #ccd9f3; }}
    .tag.ok {{ color: var(--accent); background: var(--accent-soft); border-color: #a8d7cd; }}
    .evidence {{ margin: 12px 0 0; color: var(--muted); }}
    .path {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
      align-items: center;
      gap: 10px;
      margin-top: 14px;
      padding: 12px;
      background: var(--panel-soft);
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    .path code, code {{
      background: #edf0ea;
      border: 1px solid #dce1d8;
      border-radius: 6px;
      padding: 2px 6px;
      font-family: Consolas, "SFMono-Regular", monospace;
      font-size: 12px;
    }}
    .arrow {{ color: var(--accent); font-weight: 800; }}
    .verification-box {{
      margin-top: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfa;
      overflow: hidden;
    }}
    .verification-head {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      padding: 11px 13px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-soft);
      font-weight: 800;
    }}
    .verification-list {{ margin: 0; padding: 12px 16px 12px 30px; color: var(--muted); font-size: 13px; }}
    .verification-list li + li {{ margin-top: 6px; }}
    .sandbox-details {{ border-top: 1px solid var(--line); padding: 10px 13px; }}
    .sandbox-details summary {{ cursor: pointer; font-weight: 800; color: var(--accent); }}
    .validation-details {{ border-top: 1px solid var(--line); padding: 10px 13px; }}
    .validation-details > summary {{ cursor: pointer; font-weight: 800; color: var(--accent); }}
    .validation-runs, .validation-step-list, .validation-evidence-list {{ display: grid; gap: 10px; margin-top: 10px; }}
    .validation-run, .validation-step, .validation-evidence-item {{ border: 1px solid var(--line); border-radius: 8px; background: var(--panel); padding: 11px; min-width: 0; }}
    .validation-run-head, .validation-step-head {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }}
    .validation-description, .validation-summary, .validation-note, .validation-target, .validation-artifacts {{ margin: 6px 0 0; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }}
    .validation-meta {{ display: flex; flex-wrap: wrap; gap: 6px 14px; margin-top: 9px; color: var(--muted); font-size: 12px; }}
    .validation-section {{ margin-top: 12px; }}
    .validation-section h4 {{ margin: 0; font-size: 12px; }}
    .validation-assertions {{ display: grid; gap: 6px; margin: 8px 0 0; padding: 0; list-style: none; }}
    .validation-assertions li {{ display: flex; justify-content: space-between; gap: 12px; padding: 7px 8px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel-soft); font-size: 12px; overflow-wrap: anywhere; }}
    .validation-assertion-true {{ color: var(--accent); font-weight: 800; }}
    .validation-assertion-false, .validation-error {{ color: var(--danger); font-weight: 800; }}
    .validation-observed {{ margin-top: 9px; padding-top: 9px; border-top: 1px dashed var(--line); }}
    .validation-response-line {{ margin: 0; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }}
    .validation-response {{ margin-top: 8px; }}
    .validation-response summary {{ cursor: pointer; color: var(--accent); font-size: 12px; }}
    .validation-response pre, .validation-generic {{ margin-top: 7px; padding: 10px; max-height: 260px; }}
    .sandbox-code {{
      margin: 10px 0 0;
      padding: 10px;
      border-radius: 8px;
      background: #111713;
      color: #edf4ee;
      overflow-x: auto;
      font-size: 12px;
      line-height: 1.5;
    }}
    .flow-section {{
      margin-top: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfa;
      overflow: hidden;
    }}
    .flow-title {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-soft);
      font-weight: 800;
    }}
    .flow-title span {{ color: var(--muted); font-weight: 500; font-size: 12px; }}
    .flow-diagram {{ display: grid; padding: 12px; }}
    .flow-node {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      overflow: hidden;
    }}
    .flow-node.source {{ border-color: #a8d7cd; }}
    .flow-node.sink {{ border-color: #f0b4ad; }}
    .node-head {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-soft);
    }}
    .node-role {{ font-weight: 800; font-size: 13px; }}
    .node-symbol {{ color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }}
    .code-window {{
      margin: 0;
      padding: 0;
      background: #111713;
      color: #edf4ee;
      overflow-x: auto;
      border-radius: 0;
      font-size: 12px;
      line-height: 1.5;
    }}
    .code-window code {{
      display: grid;
      background: transparent;
      border: 0;
      border-radius: 0;
      padding: 8px 0;
      color: inherit;
      font-size: inherit;
    }}
    .code-line {{
      display: grid;
      grid-template-columns: 54px minmax(0, 1fr);
      min-width: 0;
      padding: 0 12px 0 0;
    }}
    .code-line.hit {{
      background: rgba(13, 127, 110, .22);
      box-shadow: inset 3px 0 0 var(--accent);
    }}
    .line-no {{
      color: #8fa199;
      text-align: right;
      padding-right: 12px;
      user-select: none;
    }}
    .line-text {{ white-space: pre; min-width: 0; }}
    .flow-edge {{
      display: grid;
      grid-template-columns: 26px minmax(0, 1fr);
      gap: 10px;
      padding: 10px 10px 10px 16px;
      color: var(--muted);
    }}
    .edge-rail {{
      display: grid;
      place-items: center;
      color: var(--accent);
      font-weight: 900;
    }}
    .edge-copy {{
      border: 1px dashed #c9d5ce;
      border-radius: 8px;
      padding: 8px 10px;
      background: #f6f8f5;
      font-size: 13px;
    }}
    .edge-copy strong {{ color: var(--ink); margin-right: 8px; }}
    .markdown-box {{ margin-top: 20px; padding: 16px; }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      background: var(--code);
      color: #e7ede8;
      padding: 16px;
      border-radius: 8px;
      overflow: auto;
      font-size: 13px;
      line-height: 1.55;
    }}
    @media (max-width: 860px) {{
      .topbar {{ align-items: flex-start; flex-direction: column; }}
      .hero {{ grid-template-columns: 1fr; }}
      .statement h2 {{ font-size: 24px; }}
      .path {{ grid-template-columns: 1fr; }}
      .node-head {{ grid-template-columns: 1fr; }}
      .arrow {{ display: none; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div class="brand">
        <div class="mark">AF</div>
        <div>
          <h1>AuditForge 白盒审计报告</h1>
          <div class="repo">{html.escape(result.repo_path)}</div>
        </div>
      </div>
      <div class="pill">目标：{html.escape(result.target_url or "未提供运行目标")}</div>
    </div>
  </header>
  <main>
    <section class="hero">
      <div class="statement">
        <div class="eyebrow">候选优先，复现定案</div>
        <h2>本报告只把动态复现成功的结果视为已确认漏洞。</h2>
        <p>静态分析用于生成带源码锚点的 source-to-sink 候选路径；每条候选都保留 Source、Sink、置信度、验证建议和运行时状态。</p>
      </div>
      <aside class="summary-card">
        {render_project_inventory_html(result.project_inventory)}
        <h2>扫描指标</h2>
        <div class="metrics">{render_metrics(result)}</div>
      </aside>
    </section>
    {coverage_section}
    <div class="section-head">
      <div>
        <h2 class="section-title">依赖风险扫描</h2>
        <p>LLM 依赖分析只生成组件风险候选，CVE 结论需通过 OSV/NVD 或企业 SCA 工具复核。</p>
      </div>
    </div>
    {dependency_section}
    <div class="section-head">
      <div>
        <h2 class="section-title">候选路径</h2>
        <p>按静态置信度排序；未复现前不会进入正式漏洞结论。</p>
      </div>
    </div>
    {cards or "<p>未生成候选路径。</p>"}
    <section class="markdown-box">
      <h2 class="section-title">Markdown 原文</h2>
      <pre>{html.escape(markdown)}</pre>
    </section>
  </main>
</body>
</html>
"""


def render_analysis_coverage_html(coverage: dict | None) -> str:
    coverage = coverage or {}
    if not coverage:
        return ""
    dimensions = coverage.get("dimensions") if isinstance(coverage.get("dimensions"), dict) else {}
    dimension_rows = []
    for name, item in dimensions.items():
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        score_text = "未启用" if score is None else f"{float(score):.1f}%"
        dimension_rows.append(f'<div class="metric"><span>{html.escape(str(name))}</span><strong>{html.escape(score_text)}</strong></div>')
    blindspots = coverage.get("blindspots") if isinstance(coverage.get("blindspots"), list) else []
    blindspot_cards = []
    for item in blindspots[:8]:
        if not isinstance(item, dict):
            continue
        rescan = item.get("auto_rescan") if isinstance(item.get("auto_rescan"), dict) else {}
        rescan_text = f" · 补扫 {rescan.get('status')}" if rescan.get("scheduled") else ""
        blindspot_cards.append(
            '<div class="dependency-card">'
            f"<strong>{html.escape(str(item.get('severity') or 'info').upper())} · "
            f"{html.escape(str(item.get('id') or 'unknown'))} × {int(item.get('count') or 0)}</strong>"
            f"<p>{html.escape(str(item.get('reason') or ''))}{html.escape(rescan_text)}</p>"
            f'<p class="evidence">{html.escape(str(item.get("recommended_action") or ""))}</p>'
            "</div>"
        )
    score = float(coverage.get("score") or 0)
    rescan = coverage.get("auto_rescan") if isinstance(coverage.get("auto_rescan"), dict) else {}
    return f"""
    <div class="section-head">
      <div>
        <h2 class="section-title">分析覆盖与盲区</h2>
        <p>置信分只衡量可观察的分析覆盖，不代表漏洞检出率或已测得的漏报率。</p>
      </div>
    </div>
    <div class="dependency-grid">
      <div class="dependency-card">
        <strong>{score:.1f}/100 · {html.escape(str(coverage.get("status") or "unknown"))}</strong>
        <div class="metrics">{"".join(dimension_rows)}</div>
        <p class="evidence">专项补扫：执行 {int(rescan.get("executed") or 0)}，成功 {int(rescan.get("succeeded") or 0)}，失败 {int(rescan.get("failed") or 0)}</p>
      </div>
      {"".join(blindspot_cards) or '<div class="dependency-card"><p>未发现高价值分析盲区。</p></div>'}
    </div>
    """


def render_dependency_section_html(result: ScanResult) -> str:
    diagnostics = result.dependency_diagnostics or {}
    if not diagnostics.get("enabled") and not result.dependency_inventory:
        return '<p class="evidence">未启用 LLM 依赖风险扫描。</p>'
    summary = (
        f"识别 {len(result.dependency_inventory)} 个依赖清单、"
        f"{sum(len(manifest.dependencies) for manifest in result.dependency_inventory)} 个依赖，"
        f"生成 {len(result.dependency_findings)} 条风险候选。"
    )
    error = f'<p class="evidence">LLM 诊断：{html.escape(str(diagnostics.get("error")))}</p>' if diagnostics.get("error") else ""
    cards = "\n".join(render_dependency_finding_html(finding) for finding in result.dependency_findings)
    if not cards:
        cards = '<div class="dependency-card"><p>暂无依赖风险候选；仍建议使用 OSV/NVD 或企业 SCA 工具做权威复核。</p></div>'
    return f"""
    <div class="dependency-grid">
      <div class="dependency-card"><strong>{html.escape(summary)}</strong>{error}</div>
      {cards}
    </div>"""


def render_project_inventory_html(inventory: dict | None) -> str:
    if not isinstance(inventory, dict) or not inventory:
        return """
        <section class="inventory-card">
          <h2 class="section-title">项目盘点</h2>
          <p>暂无项目盘点数据。</p>
        </section>"""
    languages = inventory.get("languages") if isinstance(inventory.get("languages"), list) else []
    rows = "\n".join(render_project_inventory_language_html(item) for item in languages[:8] if isinstance(item, dict))
    return f"""
        <section class="inventory-card">
          <h2 class="section-title">项目盘点</h2>
          <p>{html.escape(inventory_summary(inventory))}</p>
          <div class="metrics">
            <div class="metric"><span>代码总行数</span><strong>{int(inventory.get("total_lines") or 0):,}</strong></div>
            <div class="metric"><span>语言数量</span><strong>{int(inventory.get("language_count") or 0)}</strong></div>
          </div>
          <div class="language-list">{rows}</div>
        </section>"""


def render_project_inventory_language_html(item: dict) -> str:
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


def render_dependency_finding_html(finding: DependencyFinding) -> str:
    severity_class = dependency_severity_tag_class(finding.severity)
    advisories = finding.advisory_ids or finding.cve_ids
    advisory_text = ", ".join(advisories) if advisories else "未给出明确公告编号"
    location = f"{finding.manifest_file}:{finding.line}" if finding.line else finding.manifest_file
    fixed = f" · 修复版本：<code>{html.escape(', '.join(finding.fixed_versions))}</code>" if finding.fixed_versions else ""
    references = ""
    if finding.references:
        references = "<p>引用：" + html.escape("；".join(finding.references)) + "</p>"
    return f"""
      <article class="dependency-card">
        <div class="candidate-top">
          <div>
            <h3>{html.escape(finding.id)} · {html.escape(finding.package)}</h3>
            <div class="dependency-meta">
              <span class="tag {severity_class}">{html.escape(dependency_severity_label(finding.severity))}</span>
              <span class="tag">{html.escape(confidence_label(finding.confidence))}</span>
              <span class="tag">{html.escape(finding.ecosystem)}</span>
              <span class="tag">{html.escape(finding.source.upper())}</span>
              <span class="tag">{html.escape(advisory_text)}</span>
            </div>
          </div>
        </div>
        <p><code>{html.escape(location)}</code> · 当前版本/约束：<code>{html.escape(finding.installed_version or "未知")}</code> · 影响范围：<code>{html.escape(finding.affected_range or "未知")}</code>{fixed}</p>
        <p>{html.escape(finding.evidence)}</p>
        <p>建议：{html.escape(finding.recommendation)}</p>
        {references}
      </article>"""


def render_metrics(result: ScanResult) -> str:
    return "\n".join(
        f'<div class="metric"><span>{html.escape(metric_label(key))}</span><strong>{value}</strong></div>'
        for key, value in result.stats().items()
    )


def render_candidate_card(candidate: TraceCandidate, result: ScanResult) -> str:
    verification = next((item for item in result.verification_results if item.candidate_id == candidate.id), None)
    status = verification.status if verification else "not_run"
    severity_class = severity_tag_class(candidate.vuln_class)
    status_class = "ok" if status == "confirmed" else ""
    flow = render_flow_html(result.repo_path, candidate.to_dict())
    verification_block = render_verification_result_html(verification)
    return f"""
<article class="candidate-card">
  <div class="candidate-top">
    <div>
      <h3>{html.escape(candidate.id)}</h3>
      <div class="tags">
        <span class="tag {severity_class}">{html.escape(vuln_label(candidate.vuln_class))}</span>
        <span class="tag">{html.escape(confidence_label(candidate.confidence))}</span>
        <span class="tag {status_class}">{html.escape(status_label(status))}</span>
        <span class="tag">{html.escape(origin_label(candidate.origin))}</span>
      </div>
    </div>
  </div>
  <p class="evidence">{html.escape(candidate.static_evidence)}</p>
  <div class="path">
    <code>{html.escape(candidate.source.file)}:{candidate.source.start_line}</code>
    <span class="arrow">&rarr;</span>
    <code>{html.escape(candidate.sink.file)}:{candidate.sink.start_line}</code>
  </div>
  {flow}
  {verification_block}
  <p class="evidence">{html.escape(candidate.verification_hint)}</p>
</article>
"""


def render_verification_result_html(verification: VerificationResult | None) -> str:
    if not verification:
        return ""
    evidence_items = "\n".join(f"<li>{html.escape(str(item))}</li>" for item in verification.evidence[:8])
    sandbox_entries = [item for item in verification.request_log if isinstance(item, dict) and item.get("type") == "sandbox_python"]
    sandbox_html = "\n".join(render_sandbox_entry_html(item) for item in sandbox_entries[:2])
    sandbox_details = (
        f"""
    <details class="sandbox-details">
      <summary>查看容器沙箱测试代码</summary>
      {sandbox_html}
    </details>"""
        if sandbox_html
        else ""
    )
    declarative_details = render_declarative_validation_html(verification.request_log)
    status_class = "ok" if verification.status == "confirmed" else ""
    return f"""
  <section class="verification-box">
    <div class="verification-head">
      <span>验证结果</span>
      <span class="tag {status_class}">{html.escape(status_label(verification.status))}</span>
    </div>
    <ul class="verification-list">{evidence_items or "<li>暂无验证证据。</li>"}</ul>
    {declarative_details}
    {sandbox_details}
  </section>"""


def render_declarative_validation_html(request_log: object) -> str:
    runs = collect_declarative_validation_runs(request_log)
    if not runs:
        return ""
    rendered = "\n".join(render_declarative_validation_run_html(run) for run in runs[:8])
    return f"""
    <details class="validation-details">
      <summary>查看声明式验证计划与运行证据</summary>
      <div class="validation-runs">{rendered}</div>
    </details>"""


def render_declarative_validation_run_html(run: dict[str, object]) -> str:
    plan = run.get("plan") if isinstance(run.get("plan"), dict) else {}
    result = run.get("result") if isinstance(run.get("result"), dict) else {}
    runner = run.get("runner") if isinstance(run.get("runner"), dict) else {}
    plan_id = str(plan.get("id") or run.get("plan_id") or result.get("plan_id") or "未标识计划")
    result_status = str(result.get("status") or "inconclusive") if result else "not_run"
    description = str(redact_validation_payload(plan.get("description") or ""))
    runner_mode = str(runner.get("mode") or "未记录")
    runner_state = "已连接" if runner.get("configured") is True else "未配置/未记录"
    cleanup = plan.get("cleanup") if isinstance(plan.get("cleanup"), dict) else {}
    cleanup_strategy = str(cleanup.get("strategy") or "none")
    cleanup_status = str(result.get("cleanup_status") or "not_run") if result else "not_run"
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    step_html = "\n".join(render_declarative_validation_step_html(item) for item in steps if isinstance(item, dict))
    if not step_html:
        step_html = '<p class="evidence">未记录可展示的计划步骤。</p>'
    evidence = result.get("evidence") if isinstance(result.get("evidence"), list) else []
    evidence_html = "\n".join(render_declarative_evidence_html(item) for item in evidence if isinstance(item, dict))
    if not evidence_html:
        evidence_html = '<p class="evidence">Runner 尚未返回结构化运行证据。</p>'
    notes = str(redact_validation_payload(result.get("notes") or "")) if result else ""
    notes_html = f'<p class="validation-note">{html.escape(notes)}</p>' if notes else ""
    description_html = f'<p class="validation-description">{html.escape(description)}</p>' if description else ""
    return f"""
      <article class="validation-run">
        <div class="validation-run-head">
          <div><strong>{html.escape(plan_id)}</strong>{description_html}</div>
          <span class="tag {validation_status_class(result_status)}">{html.escape(validation_result_label(result_status))}</span>
        </div>
        <div class="validation-meta">
          <span>Runner：{html.escape(runner_mode)} · {html.escape(runner_state)}</span>
          <span>清理：{html.escape(cleanup_strategy)} · {html.escape(cleanup_status)}</span>
        </div>
        <section class="validation-section">
          <h4>计划步骤与断言</h4>
          <div class="validation-step-list">{step_html}</div>
        </section>
        <section class="validation-section">
          <h4>运行证据</h4>
          <div class="validation-evidence-list">{evidence_html}</div>
        </section>
        {notes_html}
      </article>"""


def render_declarative_validation_step_html(step: dict[str, object]) -> str:
    step_id = str(step.get("id") or "step")
    action = validation_action_label(str(step.get("action") or step.get("type") or "unknown"))
    method = str(step.get("method") or "")
    url = str(redact_validation_payload(step.get("url") or "", key="url"))
    request_id = str(step.get("request_id") or "")
    execution_status = str(step.get("execution_status") or "ready")
    expected = step.get("expected") if isinstance(step.get("expected"), dict) else {}
    assertion_html = "\n".join(
        f"<li><code>{html.escape(str(key))}</code><span>{html.escape(validation_value_text(value))}</span></li>"
        for key, value in expected.items()
    )
    if not assertion_html:
        assertion_html = "<li><span>未记录断言。</span></li>"
    request_target = " · ".join(part for part in (method, url) if part)
    if request_id:
        request_target = f"引用响应 {request_id}"
    target_html = f'<p class="validation-target">{html.escape(request_target)}</p>' if request_target else ""
    blocked_reason = str(redact_validation_payload(step.get("blocked_reason") or ""))
    blocked_html = f'<p class="validation-error">阻断原因：{html.escape(blocked_reason)}</p>' if blocked_reason else ""
    return f"""
            <article class="validation-step">
              <div class="validation-step-head">
                <strong>{html.escape(step_id)}</strong>
                <span>{html.escape(action)} · {html.escape(execution_status)}</span>
              </div>
              {target_html}
              <ul class="validation-assertions">{assertion_html}</ul>
              {blocked_html}
            </article>"""


def render_declarative_evidence_html(item: dict[str, object]) -> str:
    step_id = str(item.get("step_id") or "step")
    status = str(item.get("status") or "unknown")
    action = validation_action_label(str(item.get("action") or "unknown"))
    summary = str(redact_validation_payload(item.get("summary") or ""))
    elapsed = item.get("elapsed_ms")
    elapsed_text = f" · {elapsed} ms" if isinstance(elapsed, int) else ""
    observed = redact_validation_payload(item.get("observed") or {})
    response_html = render_declarative_observed_html(observed) if isinstance(observed, dict) and observed else ""
    artifacts = item.get("artifacts") if isinstance(item.get("artifacts"), list) else []
    artifacts_html = ""
    if artifacts:
        artifact_text = "、".join(str(value) for value in redact_validation_payload(artifacts))
        artifacts_html = f'<p class="validation-artifacts">制品：{html.escape(artifact_text)}</p>'
    return f"""
            <article class="validation-evidence-item">
              <div class="validation-step-head">
                <strong>{html.escape(step_id)}</strong>
                <span class="tag {validation_status_class(status)}">{html.escape(validation_evidence_label(status))}</span>
              </div>
              <p class="validation-description">{html.escape(action + elapsed_text)}</p>
              <p class="validation-summary">{html.escape(summary or "无摘要")}</p>
              {response_html}
              {artifacts_html}
            </article>"""


def render_declarative_observed_html(observed: dict[str, object]) -> str:
    method = str(observed.get("method") or "")
    url = str(observed.get("url") or "")
    response_status = observed.get("status")
    response_bits = [method] if method else []
    if url:
        response_bits.append(url)
    if isinstance(response_status, int):
        response_bits.append(f"HTTP {response_status}")
    response_line = " · ".join(response_bits)
    assertions = observed.get("assertions") if isinstance(observed.get("assertions"), dict) else {}
    assertion_html = "\n".join(
        f'<li><code>{html.escape(str(key))}</code><span class="validation-assertion-{str(value).lower()}">{"通过" if value is True else "失败" if value is False else html.escape(str(value))}</span></li>'
        for key, value in assertions.items()
    )
    assertion_block = f'<ul class="validation-assertions">{assertion_html}</ul>' if assertion_html else ""
    headers = observed.get("headers") if isinstance(observed.get("headers"), dict) else {}
    body = str(observed.get("body_sample") or "")
    response_details = []
    if headers:
        response_details.append(
            f'<details class="validation-response"><summary>响应头（已脱敏）</summary><pre><code>{html.escape(validation_value_text(headers))}</code></pre></details>'
        )
    if body:
        response_details.append(
            f'<details class="validation-response"><summary>响应正文（已脱敏/限长）</summary><pre><code>{html.escape(body)}</code></pre></details>'
        )
    error = str(observed.get("error") or "")
    error_html = f'<p class="validation-error">失败原因：{html.escape(error)}</p>' if error else ""
    generic = ""
    if not response_line and not assertion_block and not response_details and not error_html:
        generic = f'<pre class="validation-generic"><code>{html.escape(validation_value_text(observed))}</code></pre>'
    return f"""
              <div class="validation-observed">
                {f'<p class="validation-response-line">脱敏响应：{html.escape(response_line)}</p>' if response_line else ""}
                {assertion_block}
                {"".join(response_details)}
                {error_html}
                {generic}
              </div>"""


def validation_value_text(value: object) -> str:
    safe = redact_validation_payload(value)
    if isinstance(safe, str):
        return safe
    return json.dumps(safe, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def validation_result_label(status: str) -> str:
    return {
        "runtime_confirmed": "运行时已确认",
        "not_reproduced": "未复现",
        "inconclusive": "证据不足",
        "blocked": "执行受阻",
        "error": "执行错误",
        "not_run": "尚未执行",
    }.get(status, status)


def validation_evidence_label(status: str) -> str:
    return {
        "passed": "通过",
        "failed": "未通过",
        "blocked": "受阻",
        "unsupported": "暂不支持",
        "error": "错误",
    }.get(status, status)


def validation_action_label(action: str) -> str:
    return {
        "http_request": "受控 HTTP 请求",
        "runtime_assert": "响应断言",
        "browser_assert": "浏览器断言",
        "oast_probe": "OAST 探测",
        "assert_response": "响应断言",
    }.get(action, action)


def validation_status_class(status: str) -> str:
    if status in {"passed", "runtime_confirmed"}:
        return "ok"
    if status in {"failed", "not_reproduced", "blocked", "unsupported", "inconclusive"}:
        return "warn"
    if status == "error":
        return "danger"
    return ""


def render_sandbox_entry_html(entry: dict) -> str:
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


def metric_label(key: str) -> str:
    labels = {
        "code_lines": "代码行数",
        "languages": "语言数量",
        "inventory_files": "盘点文件",
        "files": "文件",
        "functions": "函数",
        "classes": "类",
        "routes": "路由",
        "call_sites": "调用点",
        "data_flows": "数据流",
        "control_flows": "控制流",
        "sources": "Source",
        "sinks": "Sink",
        "sanitizers": "Sanitizer",
        "analysis_analyzed_files": "已分析源码文件",
        "analysis_ast_files": "AST 分析文件",
        "analysis_heuristic_files": "启发式分析文件",
        "analysis_language_frontend_files": "语言语义前端文件",
        "analysis_skipped_files": "跳过源码文件",
        "analysis_error_files": "分析错误文件",
        "analysis_truncated_files": "因上限截断文件",
        "analysis_truncated": "扫描是否截断",
        "analysis_confidence_score": "分析置信分",
        "analysis_blindspots": "分析盲区",
        "analysis_high_priority_blindspots": "高优先级分析盲区",
        "analysis_unresolved_calls": "未解析调用",
        "analysis_rescan_tasks": "专项补扫任务",
        "candidates": "候选路径",
        "llm_candidates": "LLM补全",
        "verification_results": "验证结果",
        "sandbox_confirmed": "旧版沙箱结果",
        "sandbox_executed": "沙箱已执行",
        "dependency_manifests": "依赖清单",
        "dependencies": "依赖数量",
        "dependency_findings": "依赖风险",
        "dependency_critical": "严重依赖",
        "dependency_high": "高危依赖",
    }
    return labels.get(key, key)


def vuln_label(vuln_class: str) -> str:
    labels = {
        "injection": "注入",
        "xss": "XSS",
        "ssrf": "SSRF",
        "auth": "认证",
        "authz": "越权",
        "dependency": "依赖漏洞",
    }
    return labels.get(vuln_class, vuln_class)


def confidence_label(confidence: str) -> str:
    return {"high": "高置信", "medium": "中置信", "low": "低置信"}.get(confidence, confidence)


def status_label(status: str) -> str:
    labels = {
        "confirmed": "已确认",
        "sandbox_confirmed": "旧版沙箱结果（待人工复核）",
        "sandbox_executed": "容器沙箱已执行（待人工复核）",
        "blocked": "验证受阻",
        "false_positive": "误报",
        "not_reproducible": "未复现",
        "needs_manual_review": "需人工验证",
        "not_run": "未运行",
    }
    return labels.get(status, status)


def origin_label(origin: str) -> str:
    return {"deterministic": "确定性规则", "llm": "LLM补全"}.get(origin, origin)


def severity_tag_class(vuln_class: str) -> str:
    if vuln_class in {"injection", "ssrf"}:
        return "danger"
    if vuln_class in {"auth", "authz"}:
        return "warn"
    return "info"


def dependency_severity_label(severity: str) -> str:
    labels = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "unknown": "未知等级",
    }
    return labels.get(severity, severity)


def dependency_severity_tag_class(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "danger"
    if severity == "medium":
        return "warn"
    return "info"
