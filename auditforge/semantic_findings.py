from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace
from pathlib import Path

from .models import CodeAnchor, CodeFacts, CodeGraph, SourceFact, TraceCandidate, TraceStep
from .utils import normalize_path, sha256_text


@dataclass(frozen=True)
class SemanticMatch:
    taxonomy_id: str
    cwe_ids: tuple[str, ...]
    vuln_class: str
    line: int
    symbol: str
    confidence: str
    evidence: str
    verification_hint: str


SECRET_NAME = re.compile(
    r"(?:secret(?:_?key)?|api_?key|access_?token|jwt_?secret|private_?key|client_?secret|database_?password|db_?password)$",
    re.I,
)
PLACEHOLDER_SECRET = re.compile(r"^(?:changeme|change-me|example|placeholder|replace-me|todo|test|dummy|secret|password)$", re.I)
CRYPTO_CONTEXT = re.compile(r"password|passwd|token|secret|signature|session|credential|auth", re.I)


def generate_semantic_candidates(repo_path: Path, facts: CodeFacts, existing: list[TraceCandidate]) -> list[TraceCandidate]:
    repo_path = repo_path.resolve()
    existing_keys = {
        (item.taxonomy_id, normalize_path(item.source.file), item.source.start_line, item.source.symbol or "") for item in existing
    }
    matches: list[tuple[str, SemanticMatch]] = []
    for indexed in facts.files:
        if indexed.language != "python" or indexed.skipped_reason:
            continue
        path = (repo_path / indexed.path).resolve()
        try:
            path.relative_to(repo_path)
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=indexed.path)
        except (OSError, SyntaxError, ValueError):
            continue
        visitor = _SemanticVisitor(source)
        visitor.visit(tree)
        for match in visitor.matches:
            key = (match.taxonomy_id, normalize_path(indexed.path), match.line, match.symbol)
            if key not in existing_keys:
                matches.append((normalize_path(indexed.path), match))
                existing_keys.add(key)
    for file, match in configuration_matches(repo_path):
        key = (match.taxonomy_id, file, match.line, match.symbol)
        if key not in existing_keys:
            matches.append((file, match))
            existing_keys.add(key)

    matches.sort(key=lambda item: (item[0], item[1].line, item[1].taxonomy_id, item[1].symbol))
    candidates: list[TraceCandidate] = []
    for index, (file, match) in enumerate(matches, start=1):
        anchor = semantic_anchor(repo_path, file, match.line, match.symbol)
        candidates.append(
            TraceCandidate(
                id=f"DIRECT-{match.vuln_class.upper()}-{index:03d}",
                vuln_class=match.vuln_class,  # type: ignore[arg-type]
                source=anchor,
                sink=anchor,
                steps=[],
                sanitizers=[],
                blockers=[],
                confidence=match.confidence,  # type: ignore[arg-type]
                static_evidence=match.evidence,
                verification_hint=match.verification_hint,
                origin="deterministic",
                taxonomy_id=match.taxonomy_id,
                cwe_ids=list(match.cwe_ids),
            )
        )
    candidates.extend(
        generate_php_include_candidates(
            repo_path,
            facts,
            [*existing, *candidates],
            start_index=len(candidates) + 1,
        )
    )
    candidates.extend(
        generate_php_persistent_xss_candidates(
            repo_path,
            facts,
            [*existing, *candidates],
            start_index=len(candidates) + 1,
        )
    )
    candidates.extend(generate_object_authz_candidates(facts, [*existing, *candidates], start_index=len(candidates) + 1))
    candidates.extend(
        generate_resource_access_authz_candidates(
            repo_path,
            facts,
            [*existing, *candidates],
            start_index=len(candidates) + 1,
        )
    )
    return candidates


def generate_php_include_candidates(
    repo_path: Path,
    facts: CodeFacts,
    existing: list[TraceCandidate],
    *,
    start_index: int,
) -> list[TraceCandidate]:
    """Connect module-scope PHP facts across bounded include relationships.

    PHP applications commonly select a vulnerability/controller implementation
    and ``include`` it into an entry page. Per-file taint scopes cannot see the
    resulting global variables, so this pass links only explicit same-variable
    flows from an included PHP file to an HTML or file-path sink in its loader.
    It intentionally does not invent function-level or arbitrary repository-wide
    edges.
    """

    repo_path = repo_path.resolve()
    php_paths = {
        normalize_path(item.path)
        for item in facts.files
        if item.language == "php" and not item.skipped_reason
    }
    included = _php_include_targets(repo_path, php_paths)
    if not included:
        return []
    sources = [
        item
        for item in facts.sources
        if item.anchor.file in php_paths
        and not item.enclosing_function_id
        and item.kind in {"http_query", "http_body", "http_path", "cookie", "session_data", "file_upload"}
    ]
    sinks = [
        item
        for item in facts.sinks
        if item.anchor.file in included
        and not item.enclosing_function_id
        and item.kind in {"html_output", "file_path"}
        and item.variables
    ]
    candidates: list[TraceCandidate] = []
    existing_keys = {
        (item.taxonomy_id, item.source.file, item.source.start_line, item.sink.file, item.sink.start_line)
        for item in existing
    }
    seen: set[tuple[str, int, str, int, str]] = set()
    for sink in sinks:
        for source in sources:
            if source.anchor.file not in included.get(sink.anchor.file, set()):
                continue
            if not any(_php_paths_intersect(left, right) for left in source.variables for right in sink.variables):
                continue
            strict_allowlist = sink.kind == "file_path" and _php_has_strict_allowlist(
                repo_path,
                source.anchor.file,
                source.variables,
            )
            if strict_allowlist:
                continue
            classifications = (
                [("cross_site_scripting", "xss", "CWE-79")]
                if sink.kind == "html_output"
                else [("path_traversal", "injection", "CWE-22")]
            )
            if sink.kind == "file_path" and _php_include_can_fetch_remote(
                repo_path,
                source.anchor.file,
                source.variables,
                sink.expression,
            ):
                classifications.append(("server_side_request_forgery", "ssrf", "CWE-918"))
            for taxonomy, vuln_class, cwe in classifications:
                key = (source.anchor.file, source.anchor.start_line, sink.anchor.file, sink.anchor.start_line, taxonomy)
                existing_key = (taxonomy, source.anchor.file, source.anchor.start_line, sink.anchor.file, sink.anchor.start_line)
                if key in seen or existing_key in existing_keys:
                    continue
                seen.add(key)
                is_ssrf = taxonomy == "server_side_request_forgery"
                candidates.append(
                    TraceCandidate(
                        id=f"DIRECT-{'XSS' if sink.kind == 'html_output' else 'INJECTION'}-{start_index + len(candidates):03d}",
                        vuln_class=vuln_class,
                        source=source.anchor,
                        sink=sink.anchor,
                        steps=[
                            TraceStep(
                                kind="call",
                                from_anchor=source.anchor,
                                to_anchor=sink.anchor,
                                explanation=(
                                    f"Included PHP module exports tainted {source.variables[0]} into the loader's global scope."
                                ),
                                confidence="medium",
                            )
                        ],
                        sanitizers=[],
                        blockers=(
                            ["Remote inclusion requires the PHP URL-wrapper configuration to permit network-backed includes."]
                            if is_ssrf
                            else []
                        ),
                        confidence="medium",
                        static_evidence=(
                            f"PHP module-scope value {source.variables[0]} from included file "
                            f"{source.anchor.file}:{source.anchor.start_line} reaches {sink.expression} at "
                            f"{sink.anchor.file}:{sink.anchor.start_line}; the include target is not restricted to local files."
                            if is_ssrf
                            else f"PHP module-scope value {source.variables[0]} from included file "
                            f"{source.anchor.file}:{source.anchor.start_line} reaches {sink.kind} at "
                            f"{sink.anchor.file}:{sink.anchor.start_line}."
                        ),
                        verification_hint=(
                            "Confirm URL-wrapper configuration against a loopback-only test service; do not request cloud metadata or internal networks."
                            if is_ssrf
                            else "Verify the selected include variant and output encoding in an isolated target; "
                            "do not execute arbitrary payloads."
                        ),
                        origin="deterministic",
                        taxonomy_id=taxonomy,
                        cwe_ids=[cwe],
                    )
                )
                existing_keys.add(existing_key)
    return candidates


def _php_include_targets(repo_path: Path, php_paths: set[str]) -> dict[str, set[str]]:
    targets: dict[str, set[str]] = {}
    include_re = re.compile(r"\b(?:include|include_once|require|require_once)\b(?P<expr>[^;]+)", re.IGNORECASE)
    for loader in sorted(php_paths):
        path = repo_path / loader
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in include_re.finditer(text):
            expression = match.group("expr")
            literals = re.findall(r"['\"]([^'\"]+)['\"]", expression)
            if not literals:
                continue
            candidate_set: set[str] = set()
            for literal in literals:
                normalized_literal = literal.replace("\\", "/").strip()
                prefix = normalized_literal.split("{", 1)[0].lstrip("./")
                if not prefix:
                    continue
                for target in php_paths:
                    target_norm = target.replace("\\", "/")
                    if prefix.endswith("/") and target_norm.startswith(prefix):
                        candidate_set.add(target)
                    elif prefix and target_norm == prefix:
                        candidate_set.add(target)
                # Resolve ordinary relative includes as a fallback.
                if "{" not in normalized_literal:
                    resolved = (path.parent / normalized_literal).resolve()
                    try:
                        relative = normalize_path(resolved.relative_to(repo_path))
                    except ValueError:
                        relative = ""
                    if relative in php_paths:
                        candidate_set.add(relative)
            if candidate_set:
                targets.setdefault(loader, set()).update(candidate_set)
    return targets


def _php_has_strict_allowlist(repo_path: Path, source_file: str, variables: list[str]) -> bool:
    try:
        text = (repo_path / source_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for variable in variables:
        token = re.escape(variable)
        if re.search(
            rf"if\s*\(\s*!\s*in_array\s*\(\s*{token}\b.*?\)\s*\)\s*\{{.*?\b(?:exit|return|throw)\b",
            text,
            re.IGNORECASE | re.DOTALL,
        ):
            return True
    return False


def _php_include_can_fetch_remote(
    repo_path: Path,
    source_file: str,
    variables: list[str],
    expression: str,
) -> bool:
    if expression.strip().lower() not in {"include", "include_once", "require", "require_once"}:
        return False
    try:
        text = (repo_path / source_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    for variable in variables:
        token = re.escape(variable)
        for guard in re.finditer(
            r"if\s*\((?P<condition>.*?)\)\s*\{(?P<body>.*?)\}",
            text,
            re.IGNORECASE | re.DOTALL,
        ):
            condition = guard.group("condition")
            if not re.search(rf"!\s*fnmatch\s*\(\s*['\"]file\*['\"]\s*,\s*{token}\b", condition, re.IGNORECASE):
                continue
            if re.search(r"\b(?:exit|return|throw)\b", guard.group("body"), re.IGNORECASE):
                return False
    return True


def _php_paths_intersect(left: str, right: str) -> bool:
    left_root = left.split("->", 1)[0].split("[", 1)[0]
    right_root = right.split("->", 1)[0].split("[", 1)[0]
    return left_root == right_root or left.startswith(f"{right_root}[") or right.startswith(f"{left_root}[")


def generate_php_persistent_xss_candidates(
    repo_path: Path,
    facts: CodeFacts,
    existing: list[TraceCandidate],
    *,
    start_index: int,
) -> list[TraceCandidate]:
    """Join unencoded PHP database writes to a proven raw database output.

    Database reads are treated as a persistent trust boundary by the PHP
    frontend. When a table has a database-result-to-HTML path, this pass
    re-evaluates writes to that table using HTML sanitizer semantics and links
    the original request source to the proven output sink. SQL escaping remains
    irrelevant to XSS, while ``htmlspecialchars`` and equivalent encoders stop
    the path.
    """

    from .candidates import build_trace_candidates

    database_sources = {
        (item.anchor.file, item.anchor.start_line): item
        for item in facts.sources
        if item.kind == "database_result"
    }
    output_by_table: dict[str, CodeAnchor] = {}
    for candidate in existing:
        if candidate.taxonomy_id != "cross_site_scripting":
            continue
        if (candidate.source.file, candidate.source.start_line) not in database_sources:
            continue
        table = _php_sql_table_near(repo_path, candidate.source.file, candidate.source.start_line, read=True)
        if table:
            output_by_table.setdefault(table, candidate.sink)
    if not output_by_table:
        return []

    source_by_anchor = {
        (item.anchor.file, item.anchor.start_line, item.anchor.symbol): item
        for item in facts.sources
    }
    existing_keys = {
        (item.taxonomy_id, item.source.file, item.source.start_line, item.sink.file, item.sink.start_line)
        for item in existing
    }
    output: list[TraceCandidate] = []
    for raw_sink in facts.sinks:
        if raw_sink.kind != "raw_sql" or not raw_sink.variables:
            continue
        table = _php_sql_table_near(repo_path, raw_sink.anchor.file, raw_sink.anchor.start_line, read=False)
        rendered_sink = output_by_table.get(table or "")
        if rendered_sink is None:
            continue
        synthetic_sink = replace(
            raw_sink,
            kind="html_output",
            vuln_class="xss",
            taxonomy_id="cross_site_scripting",
            cwe_ids=["CWE-79"],
        )
        synthetic_facts = replace(facts, sinks=[synthetic_sink])
        write_paths = build_trace_candidates(synthetic_facts, CodeGraph())
        for path in write_paths:
            source_fact = source_by_anchor.get((path.source.file, path.source.start_line, path.source.symbol))
            if source_fact is None or all(variable.startswith("$_") for variable in source_fact.variables):
                continue
            key = (
                "cross_site_scripting",
                path.source.file,
                path.source.start_line,
                rendered_sink.file,
                rendered_sink.start_line,
            )
            if key in existing_keys:
                continue
            output.append(
                TraceCandidate(
                    id=f"DIRECT-XSS-{start_index + len(output):03d}",
                    vuln_class="xss",
                    source=path.source,
                    sink=rendered_sink,
                    steps=[
                        *path.steps,
                        TraceStep(
                            kind="return",
                            from_anchor=raw_sink.anchor,
                            to_anchor=rendered_sink,
                            explanation=f"Unencoded value persists in table {table} and reaches a raw HTML response.",
                            confidence="medium",
                        ),
                    ],
                    sanitizers=path.sanitizers,
                    blockers=path.blockers,
                    confidence="medium",
                    static_evidence=(
                        f"Request-controlled content is stored in {table} at {raw_sink.anchor.file}:{raw_sink.anchor.start_line} "
                        f"without HTML encoding and later rendered at {rendered_sink.file}:{rendered_sink.start_line}."
                    ),
                    verification_hint=(
                        "In an isolated disposable target, store a harmless marker containing a minimal HTML event and confirm "
                        "whether it is rendered; stop after proving execution."
                    ),
                    origin="deterministic",
                    taxonomy_id="cross_site_scripting",
                    cwe_ids=["CWE-79"],
                )
            )
            existing_keys.add(key)
    return output


def _php_sql_table_near(repo_path: Path, file: str, line: int, *, read: bool) -> str | None:
    try:
        lines = (repo_path / file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = max(0, line - 24)
    window = "\n".join(lines[start:line])
    pattern = r"\bFROM\s+([A-Za-z_]\w*)" if read else r"\b(?:INSERT\s+INTO|UPDATE)\s+([A-Za-z_]\w*)"
    matches = list(re.finditer(pattern, window, re.IGNORECASE))
    return matches[-1].group(1).lower() if matches else None


def generate_object_authz_candidates(
    facts: CodeFacts,
    existing: list[TraceCandidate],
    *,
    start_index: int,
) -> list[TraceCandidate]:
    route_by_function = {route.handler_function_id: route for route in facts.routes if route.handler_function_id}
    guarded_scopes = {
        sanitizer.enclosing_function_id
        for sanitizer in facts.sanitizers
        if sanitizer.kind == "authorization_guard"
        and sanitizer.enclosing_function_id
        and sanitizer.confidence == "high"
        and sanitizer.expression in {"class permission policy", "decorator/dependency permission guard"}
    }

    existing_authz = {
        (candidate.source.file, candidate.source.start_line, candidate.sink.file, candidate.sink.start_line)
        for candidate in existing
        if candidate.vuln_class == "authz"
    }
    output: list[TraceCandidate] = []
    for source in facts.sources:
        scope = source.enclosing_function_id
        route = route_by_function.get(scope)
        if not scope or not route or scope in guarded_scopes or source.kind not in {"http_query", "http_path", "http_body"}:
            continue
        identifier = next((name for name in source.variables if object_identifier_name(name)), None)
        if not identifier or not re.search(r"profile|account|user|tenant|order|invoice|project|document|record", route.path, re.I):
            continue
        flows = [
            candidate
            for candidate in existing
            if candidate.source.file == source.anchor.file
            and candidate.source.start_line == source.anchor.start_line
            and candidate.sink.file == source.anchor.file
            and candidate.taxonomy_id in {"sql_injection", "path_traversal"}
        ]
        if not flows:
            continue
        sink = min(flows, key=lambda candidate: candidate.sink.start_line).sink
        key = (source.anchor.file, source.anchor.start_line, sink.file, sink.start_line)
        if key in existing_authz:
            continue
        output.append(
            TraceCandidate(
                id=f"DIRECT-AUTHZ-{start_index + len(output):03d}",
                vuln_class="authz",
                source=source.anchor,
                sink=sink,
                steps=[
                    TraceStep(
                        kind="branch",
                        from_anchor=source.anchor,
                        to_anchor=sink,
                        explanation=f"对象标识符 {identifier} 控制资源查询，但当前处理函数未发现 ownership/tenant/role guard。",
                        confidence="medium",
                    )
                ],
                sanitizers=[],
                blockers=["需结合路由中间件、全局 policy 和 ORM 默认作用域复核"],
                confidence="medium",
                static_evidence=(
                    f"路由 {route.path} 从外部输入读取对象标识符 {identifier}，并在 {sink.file}:{sink.start_line} 查询资源；"
                    "当前函数内未发现对象归属、租户或角色检查。"
                ),
                verification_hint="使用两个隔离测试账户创建不同归属对象，比较同一请求仅替换对象 ID 后的响应，不修改生产数据。",
                route_id=route.id,
                origin="deterministic",
                taxonomy_id="authorization_failure",
                cwe_ids=["CWE-639", "CWE-862"],
            )
        )
        existing_authz.add(key)
    return output


def object_identifier_name(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9_]+", ".", value.lower())
    return bool(re.search(r"(?:^|\.)(?:user|account|tenant|owner|profile|order|invoice|project|document|record)_?id$", normalized))


def configuration_matches(repo_path: Path) -> list[tuple[str, SemanticMatch]]:
    """Identify high-impact local deployment/configuration anti-patterns."""

    output: list[tuple[str, SemanticMatch]] = []
    names = {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "application.properties",
        "application.yml",
        "application.yaml",
        ".env",
    }
    for path in repo_path.rglob("*"):
        is_github_workflow = _is_github_workflow(path, repo_path)
        if (
            not path.is_file()
            or (path.name.lower() not in names and not is_github_workflow)
            or any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts)
        ):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        file = normalize_path(path.relative_to(repo_path))
        name = path.name.lower()
        if is_github_workflow:
            output.extend(_github_actions_matches(file, lines))
        for line_no, raw in enumerate(lines, 1):
            lowered = raw.strip().lower()
            if name == "dockerfile" and re.match(r"user\s+root\b", lowered):
                output.append((file, insecure_config_match(line_no, "USER root", "Docker 镜像以 root 用户运行。")))
            if name.startswith("docker-compose") and re.search(r"\bprivileged\s*:\s*true\b", lowered):
                output.append((file, insecure_config_match(line_no, "privileged: true", "Compose 服务启用了 privileged 容器权限。")))
            if (
                name.startswith("application")
                and "management.endpoints.web.exposure.include" in lowered
                and ("*" in lowered or "gateway" in lowered)
            ):
                output.append(
                    (
                        file,
                        SemanticMatch(
                            "insecure_configuration",
                            ("CWE-16", "CWE-94"),
                            "auth",
                            line_no,
                            "Spring management endpoint exposure",
                            "medium",
                            "Spring 管理端点暴露了全部或 Gateway 端点；需结合认证、网络边界和已知框架版本复核。",
                            "确认 Actuator/Gateway 管理端点仅对受控网络和管理员角色开放，并升级受影响组件。",
                        ),
                    )
                )
            if name == ".env":
                match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)\s*$", raw)
                if match and is_hardcoded_secret(match.group(1).lower(), match.group(2).strip().strip("'\"")):
                    output.append(
                        (
                            file,
                            SemanticMatch(
                                "hardcoded_secret",
                                ("CWE-798",),
                                "auth",
                                line_no,
                                match.group(1),
                                "high",
                                f"{match.group(1)} 在部署环境文件中包含疑似硬编码凭据；报告已隐藏实际值。",
                                "从版本库移除该凭据，迁移到密钥管理系统并轮换已暴露值。",
                            ),
                        )
                    )
    return output


def _is_github_workflow(path: Path, repo_path: Path) -> bool:
    """Return whether ``path`` is a GitHub Actions workflow below this repository."""

    if not path.is_file() or path.suffix.lower() not in {".yml", ".yaml"}:
        return False
    try:
        relative = path.relative_to(repo_path)
    except ValueError:
        return False
    return tuple(part.lower() for part in relative.parts[:2]) == (".github", "workflows")


def _github_actions_matches(file: str, lines: list[str]) -> list[tuple[str, SemanticMatch]]:
    """Model high-signal CI supply-chain and pull-request execution risks.

    Workflow YAML is intentionally inspected as text.  This keeps the scanner
    dependency-free and lets comments/templates survive, while the rules remain
    narrow enough to avoid treating every CI style preference as a vulnerability.
    """

    output: list[tuple[str, SemanticMatch]] = []
    pull_request_target_line = next(
        (line_no for line_no, raw in enumerate(lines, 1) if re.match(r"^\s*pull_request_target\s*:", raw)),
        None,
    )
    untrusted_checkout_line: int | None = None
    run_line: int | None = None

    for line_no, raw in enumerate(lines, 1):
        stripped = raw.strip()
        uses = re.match(r"^(?:-\s*)?uses:\s*([^\s#]+)", stripped)
        if uses:
            reference = uses.group(1).strip("'\"")
            action, separator, revision = reference.partition("@")
            if action.endswith("/checkout") and re.search(r"github\.(?:event\.pull_request\.head\.(?:ref|sha)|head_ref)", raw, re.I):
                untrusted_checkout_line = line_no
            if (
                separator
                and not re.fullmatch(r"[0-9a-fA-F]{40}", revision)
                and "/" in action
                and not action.lower().startswith(("actions/", "github/"))
            ):
                output.append(
                    (
                        file,
                        SemanticMatch(
                            "insecure_configuration",
                            ("CWE-829",),
                            "auth",
                            line_no,
                            f"GitHub Action {action}",
                            "medium",
                            f"第三方 GitHub Action {action} 使用可变引用 {revision}，无法保证后续运行的代码版本不可被替换。",
                            "将第三方 Action 固定到完整的 40 位提交 SHA，并结合发布者、提交来源和权限范围复核。",
                        ),
                    )
                )
        if re.match(r"^(?:-\s*)?run:\s*", stripped):
            run_line = line_no
        if re.search(r"^ref:\s*.*github\.(?:event\.pull_request\.head\.(?:ref|sha)|head_ref)", stripped, re.I):
            untrusted_checkout_line = line_no
        if re.match(r"^permissions:\s*write-all\s*$", stripped, re.I):
            output.append(
                (
                    file,
                    SemanticMatch(
                        "insecure_configuration",
                        ("CWE-250",),
                        "auth",
                        line_no,
                        "GitHub Actions write-all permission",
                        "medium",
                        "GitHub Actions workflow grants write-all token permissions, exceeding least privilege for typical CI jobs.",
                        "Set explicit, minimal job-level permissions and grant write scopes only to the step that needs them.",
                    ),
                )
            )

    if pull_request_target_line and untrusted_checkout_line and run_line:
        output.append(
            (
                file,
                SemanticMatch(
                    "insecure_configuration",
                    ("CWE-94", "CWE-829"),
                    "auth",
                    untrusted_checkout_line,
                    "pull_request_target checks out pull request code",
                    "high",
                    "pull_request_target workflow checks out pull-request-controlled code and runs commands; the base-repository token/context can be exposed to untrusted code.",
                    "Use pull_request for untrusted code, avoid checking out the PR head in privileged workflows, and split trusted write operations into a separate workflow.",
                ),
            )
        )
    return output


def generate_resource_access_authz_candidates(
    repo_path: Path,
    facts: CodeFacts,
    existing: list[TraceCandidate],
    *,
    start_index: int,
) -> list[TraceCandidate]:
    """Find object lookup by an external identifier without an ownership scope.

    This is intentionally separate from SQL/path candidates: parameterized ORM
    queries are usually safe from injection yet can still expose another user's
    record.  The model only emits medium-confidence candidates for a route
    handler, an explicit request-derived identifier, and a recognised resource
    lookup lacking owner/tenant/account scoping in that lookup.
    """

    routes = {route.handler_function_id: route for route in facts.routes if route.handler_function_id}
    functions = {(function.anchor.file, function.id): function for function in facts.functions}
    sources_by_scope: dict[tuple[str, str], list[SourceFact]] = {}
    for source in facts.sources:
        if source.enclosing_function_id and source.kind in {"http_query", "http_path", "http_body"}:
            sources_by_scope.setdefault((source.anchor.file, source.enclosing_function_id), []).append(source)
    guarded = {
        sanitizer.enclosing_function_id
        for sanitizer in facts.sanitizers
        if sanitizer.kind == "authorization_guard"
        and sanitizer.confidence == "high"
        and sanitizer.expression in {"class permission policy", "decorator/dependency permission guard"}
    }
    emitted = {
        (item.source.file, item.source.start_line, item.sink.file, item.sink.start_line) for item in existing if item.vuln_class == "authz"
    }
    output: list[TraceCandidate] = []
    for indexed in facts.files:
        if indexed.language != "python" or indexed.skipped_reason:
            continue
        path = repo_path / indexed.path
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=indexed.path)
        except (OSError, SyntaxError):
            continue
        for function_node in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            function = next(
                (
                    item
                    for item in functions.values()
                    if item.anchor.file == indexed.path and item.anchor.start_line == function_node.lineno
                ),
                None,
            )
            if not function or function.id in guarded or function.id not in routes:
                continue
            sources = sources_by_scope.get((indexed.path, function.id), [])
            for call in (node for node in ast.walk(function_node) if isinstance(node, ast.Call)):
                call_name = qualified_name(call.func).lower()
                if not _resource_lookup_call(call_name):
                    continue
                selector_names = _resource_selector_names(call)
                source = next(
                    (item for item in sources if any(_selector_references_source(name, item.variables) for name in selector_names)),
                    None,
                )
                if source is None or _resource_lookup_has_scope(call):
                    continue
                sink = semantic_anchor(repo_path, indexed.path, call.lineno, "resource_access")
                key = (source.anchor.file, source.anchor.start_line, sink.file, sink.start_line)
                if key in emitted:
                    continue
                route = routes[function.id]
                identifier = next((name for name in source.variables if object_identifier_name(name)), source.variables[0])
                output.append(
                    TraceCandidate(
                        id=f"DIRECT-AUTHZ-{start_index + len(output):03d}",
                        vuln_class="authz",
                        source=source.anchor,
                        sink=sink,
                        steps=[
                            TraceStep(
                                kind="call",
                                from_anchor=source.anchor,
                                to_anchor=sink,
                                explanation=f"外部对象标识符 {identifier} 直接作为资源查询选择器。",
                                confidence="medium",
                            )
                        ],
                        sanitizers=[],
                        blockers=["需核对全局 ORM 默认作用域、路由中间件和对象级 policy"],
                        confidence="medium",
                        static_evidence=(
                            f"路由 {route.path} 使用外部输入 {identifier} 调用 {call_name}，调用参数中未见 owner/tenant/account/user 范围。"
                        ),
                        verification_hint="在隔离环境使用两个账户的不同资源，仅替换对象 ID；确认访问是否被拒绝且不修改数据。",
                        route_id=route.id,
                        origin="deterministic",
                        taxonomy_id="authorization_failure",
                        cwe_ids=["CWE-639", "CWE-862"],
                    )
                )
                emitted.add(key)
    return output


def _resource_lookup_call(name: str) -> bool:
    return name.endswith((".objects.get", ".objects.filter", ".query.get", ".query.filter", ".get_or_404", ".find_by_id"))


def _resource_selector_names(call: ast.Call) -> list[str]:
    names: list[str] = []
    for keyword in call.keywords:
        if keyword.arg and re.search(r"(?:^|_)(?:id|pk|uuid|slug)$", keyword.arg, re.I):
            names.extend(_ast_names(keyword.value))
    return names


def _selector_references_source(selector: str, variables: list[str]) -> bool:
    return any(selector == variable or selector.startswith(f"{variable}.") for variable in variables)


def _resource_lookup_has_scope(call: ast.Call) -> bool:
    return any(keyword.arg and re.search(r"owner|tenant|account|organization|org|user", keyword.arg, re.I) for keyword in call.keywords)


def _ast_names(node: ast.AST) -> list[str]:
    return [item.id for item in ast.walk(node) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)]


class _SemanticVisitor(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self.source = source
        self.matches: list[SemanticMatch] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                name = assignment_name(target)
                if name and is_hardcoded_secret(name, node.value.value):
                    self.matches.append(
                        SemanticMatch(
                            "hardcoded_secret",
                            ("CWE-798",),
                            "auth",
                            node.lineno,
                            name,
                            "high",
                            f"{name} 在源码中被赋予硬编码凭据值；报告已隐藏实际值。",
                            "确认该值是否仍在生产环境使用；迁移到密钥管理系统并轮换已暴露凭据。",
                        )
                    )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            name = assignment_name(node.target)
            if name and is_hardcoded_secret(name, node.value.value):
                self.matches.append(
                    SemanticMatch(
                        "hardcoded_secret",
                        ("CWE-798",),
                        "auth",
                        node.lineno,
                        name,
                        "high",
                        f"{name} 在源码中被赋予硬编码凭据值；报告已隐藏实际值。",
                        "确认该值是否仍在生产环境使用；迁移到密钥管理系统并轮换已暴露凭据。",
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = qualified_name(node.func).lower()
        call_text = ast.get_source_segment(self.source, node) or name
        lowered = call_text.lower()
        if name in {"hashlib.md5", "hashlib.sha1"} and CRYPTO_CONTEXT.search(parent_statement_text(self.source, node)):
            self.matches.append(
                SemanticMatch(
                    "weak_cryptography",
                    ("CWE-327", "CWE-328"),
                    "auth",
                    node.lineno,
                    name,
                    "high",
                    f"安全敏感上下文使用 {name}，该摘要算法不适合密码、令牌或签名保护。",
                    "确认用途；密码改用 Argon2id/bcrypt/scrypt，签名或完整性校验改用受支持的 HMAC/现代算法。",
                )
            )
        if name in {"random.random", "random.randint", "random.randrange", "random.choice"} and CRYPTO_CONTEXT.search(
            parent_statement_text(self.source, node)
        ):
            self.matches.append(
                SemanticMatch(
                    "insecure_randomness",
                    ("CWE-330", "CWE-338"),
                    "auth",
                    node.lineno,
                    name,
                    "high",
                    "安全敏感令牌或凭据使用非密码学随机数生成器。",
                    "改用 secrets 模块或系统 CSPRNG，并验证令牌长度、过期和重放保护。",
                )
            )
        if keyword_constant(node, "debug") is True and name.endswith((".run", ".serve")):
            self.matches.append(insecure_config_match(node.lineno, f"{name}(debug=True)", "服务启动时显式启用了调试模式。"))
        if keyword_constant(node, "verify") is False and name.startswith(("requests.", "httpx.")):
            self.matches.append(
                SemanticMatch(
                    "tls_verification_disabled",
                    ("CWE-295",),
                    "auth",
                    node.lineno,
                    f"{name}(verify=False)",
                    "high",
                    "外部 HTTPS 请求显式关闭了证书校验。",
                    "恢复证书和主机名校验；如使用私有 CA，请配置受控 CA bundle，而不是关闭验证。",
                )
            )
        if name.endswith(("cors", "corsmiddleware")) and ("'*'" in lowered or '"*"' in lowered):
            self.matches.append(insecure_config_match(node.lineno, name, "CORS 配置允许任意来源，需要结合凭据设置复核。"))
        self.generic_visit(node)


def insecure_config_match(line: int, symbol: str, evidence: str) -> SemanticMatch:
    return SemanticMatch(
        "insecure_configuration",
        ("CWE-16",),
        "auth",
        line,
        symbol,
        "high",
        evidence,
        "在隔离环境核对实际部署配置，关闭调试/宽松跨域选项并增加配置回归测试。",
    )


def is_hardcoded_secret(name: str, value: str) -> bool:
    cleaned = value.strip()
    return bool(SECRET_NAME.search(name)) and len(cleaned) >= 8 and not PLACEHOLDER_SECRET.fullmatch(cleaned)


def assignment_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = assignment_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def keyword_constant(node: ast.Call, name: str) -> object:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant):
            return keyword.value.value
    return None


def parent_statement_text(source: str, node: ast.AST) -> str:
    lines = source.splitlines()
    start = max(0, int(getattr(node, "lineno", 1)) - 1)
    end = min(len(lines), int(getattr(node, "end_lineno", start + 1)))
    return "\n".join(lines[start:end])[:1000]


def semantic_anchor(repo_path: Path, file: str, line_no: int, symbol: str) -> CodeAnchor:
    path = repo_path / file
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        snippet = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    except OSError:
        snippet = ""
    return CodeAnchor(
        file=file,
        start_line=line_no,
        end_line=line_no,
        snippet_hash=sha256_text(snippet)[:16],
        symbol=symbol,
    )
