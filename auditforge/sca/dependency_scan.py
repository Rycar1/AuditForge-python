from __future__ import annotations

import json
import math
import os
import re
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ..analysis.llm_candidates import LLMConfig, load_llm_json_response, parse_json_object, with_output_contract
from ..core.models import Confidence, DependencyFinding, DependencyManifest, DependencyPackage, DependencySeverity
from ..core.utils import normalize_path

DEFAULT_DEPENDENCY_SYSTEM_PROMPT = (
    "你是资深软件成分分析（SCA）审计员，负责基于依赖清单生成需要复核的依赖漏洞候选。"
    "你的输出只进入依赖风险候选区，不能作为已确认漏洞；没有联网事实源时必须保守，禁止编造 CVE、公告、修复版本或引用链接。"
    "你必须只分析输入 inventory 中真实存在的组件、生态、scope 和版本约束，严格区分 PyPI/npm/Maven/Go 生态与同名包。"
    "判断时先核对包名与生态，再判断版本约束是否可能落入受影响范围，最后给 severity/confidence。"
    "你要显式区分已知公告匹配、版本过旧风险、供应链配置风险和无法判断；无法可靠核实时不要把模型记忆当成事实。"
    "输出必须是严格 JSON object，中文解释，并完全遵守输出契约。"
)
DEFAULT_DEPENDENCY_USER_PROMPT = (
    "分析 requirements.txt、pom.xml、package.json、go.mod 等依赖清单，识别公开 CVE/GHSA/OSV、受影响版本范围、"
    "明显过旧或高风险组件，并生成需要 OSV/NVD/GHSA/供应商公告/包生态 advisory 复核的依赖风险候选。"
    "优先输出包名、生态、当前版本和公告范围高度匹配的结果；版本为范围、变量、继承、未固定或不确定时必须降置信。"
    "对每条结果说明它属于明确公告匹配、疑似受影响范围、过旧风险还是仅建议复核；不要把 dev/test 依赖默认当成生产风险。"
    "不要臆造 CVE、引用链接、修复版本或确定性结论；证据不足时写清复核原因、降低 confidence，或返回空 findings。"
)
DEPENDENCY_OUTPUT_CONTRACT = """必须返回一个 JSON object，根对象必须包含 findings 字段。
findings 必须是数组；没有结果时返回 {"findings": []}。
每个 findings[] 元素必须包含：
- package: string，必须来自 inventory
- ecosystem: "pypi" | "maven" | "npm" | "go" | "crates.io" | "rubygems" | "packagist" | "nuget"
- installedVersion: string，可为版本约束
- affectedRange: string，可为空但字段必须存在
- cveIds: string array，可为空；禁止编造 CVE
- severity: "critical" | "high" | "medium" | "low" | "unknown"
- confidence: "low" | "medium" | "high"
- title: non-empty Chinese string
- evidence: non-empty Chinese string
- recommendation: non-empty Chinese string
- manifestFile: string，必须是对应依赖清单路径
- references: string array，可为空
硬性禁止：
- 禁止输出 Markdown、自然语言前后缀、inventory 外依赖、已确认漏洞结论或无法追溯到清单的组件。
- 禁止编造 CVE、GHSA、公告链接、修复版本或影响范围；不确定时 cveIds 为空且 confidence 降低。
- 禁止把 dev/test-only 依赖、未固定版本约束、父 BOM 管理版本误判为高置信，除非 evidence 说明原因。"""

MANIFEST_FILENAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "pyproject.toml",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "pom.xml",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "packages.lock.json",
}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "target",
    "build",
    "dist",
    "workspace",
    "workspace-smoke",
    "validation-labs",
}
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_DEPENDENCY_FINDINGS = 5000
DEPENDENCY_LLM_CHUNK_SIZE = 5
OSV_QUERY_BATCH_SIZE = 1000
OSV_RETRY_DELAYS_SECONDS = (0.2, 0.8)
OSV_ENDPOINT_ENV = "AUDITFORGE_OSV_ENDPOINT"
OSV_DISABLED_ENV = "AUDITFORGE_OSV_DISABLED"
DEFAULT_OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
OSV_DETAIL_CACHE: dict[tuple[str, str], dict[str, Any]] = {}
OSV_DETAIL_CACHE_LOCK = threading.Lock()
ALLOWED_SEVERITIES: set[str] = {"critical", "high", "medium", "low", "unknown"}
ALLOWED_CONFIDENCE: set[str] = {"low", "medium", "high"}


def scan_dependency_manifests(repo_path: Path) -> list[DependencyManifest]:
    repo_path = repo_path.resolve()
    manifests: list[DependencyManifest] = []
    for manifest_path in find_manifest_files(repo_path):
        relative = normalize_path(manifest_path.relative_to(repo_path))
        try:
            if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
                manifests.append(
                    DependencyManifest(
                        file=relative,
                        ecosystem=ecosystem_for_manifest(manifest_path.name),
                        package_manager=package_manager_for_manifest(manifest_path.name),
                        dependencies=[],
                        skipped_reason="依赖清单文件过大，已跳过解析。",
                    )
                )
                continue
            manifests.append(parse_manifest(repo_path, manifest_path))
        except Exception as exc:  # noqa: BLE001 - keep dependency parsing best-effort
            manifests.append(
                DependencyManifest(
                    file=relative,
                    ecosystem=ecosystem_for_manifest(manifest_path.name),
                    package_manager=package_manager_for_manifest(manifest_path.name),
                    dependencies=[],
                    skipped_reason=f"解析失败：{exc}",
                )
            )
    return manifests


def find_manifest_files(repo_path: Path) -> list[Path]:
    files: list[Path] = []
    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(repo_path).parts[:-1]):
            continue
        name = path.name
        if name in MANIFEST_FILENAMES or name.startswith("requirements-") and name.endswith(".txt"):
            files.append(path)
    return sorted(files, key=lambda item: normalize_path(item.relative_to(repo_path)))


def parse_manifest(repo_path: Path, manifest_path: Path) -> DependencyManifest:
    name = manifest_path.name
    relative = normalize_path(manifest_path.relative_to(repo_path))
    if name.startswith("requirements") and name.endswith(".txt"):
        return DependencyManifest(relative, "pypi", "pip", parse_requirements(manifest_path, relative))
    if name == "pyproject.toml":
        return DependencyManifest(relative, "pypi", "pyproject", parse_pyproject(manifest_path, relative))
    if name in {"uv.lock", "poetry.lock"}:
        manager = "uv" if name == "uv.lock" else "poetry"
        return DependencyManifest(relative, "pypi", manager, parse_python_toml_lock(manifest_path, relative, manager))
    if name == "Pipfile.lock":
        return DependencyManifest(relative, "pypi", "pipenv", parse_pipfile_lock(manifest_path, relative))
    if name == "pom.xml":
        return DependencyManifest(relative, "maven", "maven", parse_pom(manifest_path, relative))
    if name == "package.json":
        return DependencyManifest(relative, "npm", "npm", parse_package_json(manifest_path, relative))
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return DependencyManifest(relative, "npm", "npm", parse_package_lock(manifest_path, relative))
    if name == "yarn.lock":
        return DependencyManifest(relative, "npm", "yarn", parse_yarn_lock(manifest_path, relative))
    if name == "pnpm-lock.yaml":
        return DependencyManifest(relative, "npm", "pnpm", parse_pnpm_lock(manifest_path, relative))
    if name == "go.mod":
        return DependencyManifest(relative, "go", "go", parse_go_mod(manifest_path, relative))
    if name == "go.sum":
        return DependencyManifest(relative, "go", "go", parse_go_sum(manifest_path, relative))
    if name == "Cargo.lock":
        return DependencyManifest(relative, "crates.io", "cargo", parse_cargo_lock(manifest_path, relative))
    if name == "Gemfile.lock":
        return DependencyManifest(relative, "rubygems", "bundler", parse_gemfile_lock(manifest_path, relative))
    if name == "composer.lock":
        return DependencyManifest(relative, "packagist", "composer", parse_composer_lock(manifest_path, relative))
    if name == "packages.lock.json":
        return DependencyManifest(relative, "nuget", "nuget", parse_nuget_lock(manifest_path, relative))
    return DependencyManifest(relative, ecosystem_for_manifest(name), package_manager_for_manifest(name), [])


def parse_requirements(path: Path, relative: str, seen: set[Path] | None = None) -> list[DependencyPackage]:
    seen = seen if seen is not None else set()
    resolved_path = path.resolve()
    if resolved_path in seen:
        return []
    seen.add(resolved_path)
    dependencies: list[DependencyPackage] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = strip_inline_comment(raw).strip()
        if not line:
            continue
        include = re.match(r"^(?:-r|--requirement|-c|--constraint)\s+(.+)$", line)
        if include:
            include_name = include.group(1).strip()
            include_path = (path.parent / include_name).resolve()
            if include_path.is_file():
                include_relative = normalize_path(Path(relative).parent / include_name)
                dependencies.extend(parse_requirements(include_path, include_relative, seen))
            continue
        editable = re.match(r"^-e\s+(.+)$", line)
        if editable:
            line = editable.group(1).strip()
        if line.startswith(("-r", "--requirement", "-c", "--constraint", "git+", "http://", "https://")):
            continue
        match = re.match(r"^(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?(?P<spec>.*)$", line)
        if not match:
            continue
        package = match.group("name")
        specifier = normalize_specifier(match.group("spec"))
        dependencies.append(
            DependencyPackage(
                name=package,
                ecosystem="pypi",
                package_manager="pip",
                manifest_file=relative,
                line=line_no,
                version=exact_version(specifier),
                specifier=specifier or None,
                direct=True,
                resolved=exact_version(specifier) is not None,
                purl=make_purl("pypi", package, exact_version(specifier)),
            )
        )
    return dedupe_dependencies(dependencies)


def parse_pyproject(path: Path, relative: str) -> list[DependencyPackage]:
    payload = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    dependencies: list[DependencyPackage] = []
    project = payload.get("project") if isinstance(payload.get("project"), dict) else {}
    for raw in project.get("dependencies") or []:
        if not isinstance(raw, str):
            continue
        dependencies.extend(parse_pep508_requirement(raw, relative, "pyproject"))
    optional = project.get("optional-dependencies") if isinstance(project.get("optional-dependencies"), dict) else {}
    for group, values in optional.items():
        for raw in values if isinstance(values, list) else []:
            if not isinstance(raw, str):
                continue
            dependencies.extend(parse_pep508_requirement(raw, relative, f"optional:{group}"))

    tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    poetry_dependencies = poetry.get("dependencies") if isinstance(poetry.get("dependencies"), dict) else {}
    for name, raw in poetry_dependencies.items():
        if str(name).lower() == "python":
            continue
        specifier = raw if isinstance(raw, str) else raw.get("version") if isinstance(raw, dict) else ""
        version = exact_version(str(specifier or ""))
        dependencies.append(
            DependencyPackage(
                name=str(name),
                ecosystem="pypi",
                package_manager="poetry",
                manifest_file=relative,
                version=version,
                specifier=str(specifier or "") or None,
                scope="runtime",
                direct=True,
                resolved=version is not None,
                purl=make_purl("pypi", str(name), version),
            )
        )
    return dedupe_dependencies(dependencies)


def parse_pep508_requirement(raw: str, relative: str, scope: str) -> list[DependencyPackage]:
    requirement = raw.split(";", 1)[0].strip()
    match = re.match(r"^(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?P<spec>.*)$", requirement)
    if not match:
        return []
    name = match.group("name")
    specifier = normalize_specifier(match.group("spec"))
    version = exact_version(specifier)
    return [
        DependencyPackage(
            name=name,
            ecosystem="pypi",
            package_manager="pyproject",
            manifest_file=relative,
            version=version,
            specifier=specifier or None,
            scope=scope,
            direct=True,
            resolved=version is not None,
            purl=make_purl("pypi", name, version),
        )
    ]


def parse_python_toml_lock(path: Path, relative: str, manager: str) -> list[DependencyPackage]:
    payload = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    raw_packages = payload.get("package") or []
    dependencies: list[DependencyPackage] = []
    for item in raw_packages if isinstance(raw_packages, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        if not name or not version:
            continue
        dependencies.append(
            DependencyPackage(
                name=name,
                ecosystem="pypi",
                package_manager=manager,
                manifest_file=relative,
                version=version,
                specifier=f"=={version}",
                scope=str(item.get("category") or "resolved"),
                direct=None,
                resolved=True,
                purl=make_purl("pypi", name, version),
            )
        )
    return dedupe_dependencies(dependencies)


def parse_pipfile_lock(path: Path, relative: str) -> list[DependencyPackage]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    dependencies: list[DependencyPackage] = []
    for section, scope in (("default", "runtime"), ("develop", "development")):
        items = payload.get(section) if isinstance(payload.get(section), dict) else {}
        for name, metadata in items.items():
            raw = metadata.get("version") if isinstance(metadata, dict) else metadata
            specifier = str(raw or "")
            version = exact_version(specifier)
            dependencies.append(
                DependencyPackage(
                    name=str(name),
                    ecosystem="pypi",
                    package_manager="pipenv",
                    manifest_file=relative,
                    version=version,
                    specifier=specifier or None,
                    scope=scope,
                    direct=True,
                    resolved=version is not None,
                    purl=make_purl("pypi", str(name), version),
                )
            )
    return dedupe_dependencies(dependencies)


@dataclass(frozen=True)
class MavenPomContext:
    properties: dict[str, str]
    managed_versions: dict[str, str]
    group_id: str
    version: str


def parse_pom(path: Path, relative: str) -> list[DependencyPackage]:
    root, context = load_maven_pom(path, set())
    dependencies: list[DependencyPackage] = []
    dependency_root = root.find("{*}dependencies")
    for dependency in list(dependency_root) if dependency_root is not None else []:
        group_id = substitute_property(child_text(dependency, "groupId"), context.properties)
        artifact_id = substitute_property(child_text(dependency, "artifactId"), context.properties)
        version = substitute_property(child_text(dependency, "version"), context.properties)
        scope = substitute_property(child_text(dependency, "scope"), context.properties)
        if not artifact_id:
            continue
        package = f"{group_id}:{artifact_id}" if group_id else artifact_id
        if not version:
            version = context.managed_versions.get(package, "")
        dependencies.append(
            DependencyPackage(
                name=package,
                ecosystem="maven",
                package_manager="maven",
                manifest_file=relative,
                line=None,
                version=version or None,
                specifier=version or None,
                scope=scope or None,
                group_id=group_id or None,
                direct=True,
                resolved=bool(version and "${" not in version),
                purl=make_purl("maven", package, version or None),
            )
        )
    return dedupe_dependencies(dependencies)


def load_maven_pom(path: Path, seen: set[Path]) -> tuple[ET.Element, MavenPomContext]:
    """Resolve local parent properties and dependencyManagement conservatively."""

    resolved = path.resolve()
    if resolved in seen:
        raise ValueError(f"Maven parent cycle detected at {path}")
    seen.add(resolved)
    root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
    parent = root.find("{*}parent")
    parent_context: MavenPomContext | None = None
    parent_properties: dict[str, str] = {}
    parent_group = ""
    parent_version = ""
    if parent is not None:
        parent_group = child_text(parent, "groupId")
        parent_version = child_text(parent, "version")
        parent_path = local_maven_parent_path(path, parent)
        if parent_path is not None:
            try:
                _, parent_context = load_maven_pom(parent_path, seen)
            except (OSError, ET.ParseError, ValueError):
                parent_context = None
        if parent_context is not None:
            parent_properties.update(parent_context.properties)
            parent_group = parent_context.group_id or parent_group
            parent_version = parent_context.version or parent_version

    group_id = substitute_property(child_text(root, "groupId") or parent_group, parent_properties)
    version = substitute_property(child_text(root, "version") or parent_version, parent_properties)
    properties = dict(parent_properties)
    properties.update(
        {
            "project.groupId": group_id,
            "pom.groupId": group_id,
            "groupId": group_id,
            "project.version": version,
            "pom.version": version,
            "version": version,
            "project.parent.groupId": parent_group,
            "pom.parent.groupId": parent_group,
            "project.parent.version": parent_version,
            "pom.parent.version": parent_version,
        }
    )
    properties.update(pom_properties(root))
    properties = resolve_maven_properties(properties)
    group_id = substitute_property(group_id, properties)
    version = substitute_property(version, properties)
    properties.update(
        {
            "project.groupId": group_id,
            "pom.groupId": group_id,
            "groupId": group_id,
            "project.version": version,
            "pom.version": version,
            "version": version,
        }
    )

    managed_versions = dict(parent_context.managed_versions) if parent_context is not None else {}
    management = root.find("{*}dependencyManagement/{*}dependencies")
    for dependency in list(management) if management is not None else []:
        managed_group = substitute_property(child_text(dependency, "groupId"), properties)
        managed_artifact = substitute_property(child_text(dependency, "artifactId"), properties)
        managed_version = substitute_property(child_text(dependency, "version"), properties)
        if not managed_group or not managed_artifact or not managed_version or "${" in managed_version:
            continue
        managed_versions[f"{managed_group}:{managed_artifact}"] = managed_version
    return root, MavenPomContext(properties, managed_versions, group_id, version)


def local_maven_parent_path(path: Path, parent: ET.Element) -> Path | None:
    relative_node = parent.find("{*}relativePath")
    if relative_node is not None and not (relative_node.text or "").strip():
        return None
    relative = (relative_node.text or "").strip() if relative_node is not None else "../pom.xml"
    candidate = (path.parent / relative).resolve()
    return candidate if candidate.is_file() else None


def resolve_maven_properties(properties: dict[str, str]) -> dict[str, str]:
    resolved = dict(properties)
    for _ in range(12):
        updated = {key: substitute_property(value, resolved) for key, value in resolved.items()}
        if updated == resolved:
            break
        resolved = updated
    return resolved


def parse_package_json(path: Path, relative: str) -> list[DependencyPackage]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    dependencies: list[DependencyPackage] = []
    sections = [
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    ]
    for section, scope in sections:
        items = payload.get(section)
        if not isinstance(items, dict):
            continue
        for package, specifier in sorted(items.items()):
            dependencies.append(
                DependencyPackage(
                    name=str(package),
                    ecosystem="npm",
                    package_manager="npm",
                    manifest_file=relative,
                    version=exact_version(str(specifier)),
                    specifier=str(specifier),
                    scope=scope,
                    direct=True,
                    resolved=exact_version(str(specifier)) is not None,
                    purl=make_purl("npm", str(package), exact_version(str(specifier))),
                )
            )
    return dependencies


def parse_package_lock(path: Path, relative: str) -> list[DependencyPackage]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    dependencies: list[DependencyPackage] = []
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for location, metadata in packages.items():
            if not location or not isinstance(metadata, dict):
                continue
            name = str(metadata.get("name") or package_name_from_node_modules(str(location))).strip()
            version = str(metadata.get("version") or "").strip()
            if not name or not version:
                continue
            dependencies.append(
                DependencyPackage(
                    name=name,
                    ecosystem="npm",
                    package_manager="npm",
                    manifest_file=relative,
                    version=version,
                    specifier=version,
                    scope="development" if metadata.get("dev") else "optional" if metadata.get("optional") else "runtime",
                    direct=location.count("node_modules") == 1,
                    resolved=True,
                    purl=make_purl("npm", name, version),
                )
            )
    else:
        collect_package_lock_dependencies(payload.get("dependencies"), relative, dependencies, direct=True)
    return dedupe_dependencies(dependencies)


def collect_package_lock_dependencies(
    raw: object,
    relative: str,
    output: list[DependencyPackage],
    *,
    direct: bool,
) -> None:
    if not isinstance(raw, dict):
        return
    for name, metadata in raw.items():
        if not isinstance(metadata, dict):
            continue
        version = str(metadata.get("version") or "").strip()
        if version:
            output.append(
                DependencyPackage(
                    name=str(name),
                    ecosystem="npm",
                    package_manager="npm",
                    manifest_file=relative,
                    version=version,
                    specifier=version,
                    scope="development" if metadata.get("dev") else "optional" if metadata.get("optional") else "runtime",
                    direct=direct,
                    resolved=True,
                    purl=make_purl("npm", str(name), version),
                )
            )
        collect_package_lock_dependencies(metadata.get("dependencies"), relative, output, direct=False)


def package_name_from_node_modules(location: str) -> str:
    marker = "node_modules/"
    if marker not in location:
        return ""
    tail = location.rsplit(marker, 1)[-1]
    parts = tail.split("/")
    if tail.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


def parse_yarn_lock(path: Path, relative: str) -> list[DependencyPackage]:
    dependencies: list[DependencyPackage] = []
    current_names: list[str] = []
    current_line: int | None = None
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            current_names = []
            current_line = line_no
            for selector in split_yarn_selectors(raw.rstrip()[:-1]):
                name = npm_name_from_selector(selector)
                if name and name not in current_names:
                    current_names.append(name)
            continue
        version_match = re.match(r'^\s+version\s+["\']?([^"\'\s]+)', raw)
        if not current_names or not version_match:
            continue
        version = version_match.group(1)
        dependencies.extend(
            DependencyPackage(
                name=name,
                ecosystem="npm",
                package_manager="yarn",
                manifest_file=relative,
                line=current_line,
                version=version,
                specifier=version,
                scope="resolved",
                direct=None,
                resolved=True,
                purl=make_purl("npm", name, version),
            )
            for name in current_names
        )
        current_names = []
    return dedupe_dependencies(dependencies)


def split_yarn_selectors(header: str) -> list[str]:
    return [item.strip().strip("\"'") for item in re.split(r",\s*(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", header)]


def npm_name_from_selector(selector: str) -> str:
    value = selector.strip().strip("\"'")
    if value.startswith("npm:"):
        value = value[4:]
    separator = value.rfind("@")
    if separator <= 0:
        return ""
    return value[:separator]


def parse_pnpm_lock(path: Path, relative: str) -> list[DependencyPackage]:
    dependencies: list[DependencyPackage] = []
    section = ""
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            section = raw.strip()[:-1]
            continue
        if section not in {"packages", "snapshots"}:
            continue
        match = re.match(r"^\s{2}([^#][^:]*):\s*$", raw)
        if not match:
            continue
        key = match.group(1).strip().strip("\"'").lstrip("/")
        parsed = parse_pnpm_package_key(key)
        if not parsed:
            continue
        name, version = parsed
        dependencies.append(
            DependencyPackage(
                name=name,
                ecosystem="npm",
                package_manager="pnpm",
                manifest_file=relative,
                line=line_no,
                version=version,
                specifier=version,
                scope="resolved",
                direct=None,
                resolved=True,
                purl=make_purl("npm", name, version),
            )
        )
    return dedupe_dependencies(dependencies)


def parse_pnpm_package_key(value: str) -> tuple[str, str] | None:
    key = re.sub(r"\([^)]*\)$", "", value)
    if key.startswith("@"):
        separator = key.rfind("@")
        if separator > key.find("/"):
            return key[:separator], key[separator + 1 :]
        if "/" in key:
            name, version = key.rsplit("/", 1)
            return name, version
        return None
    if "@" in key:
        name, version = key.rsplit("@", 1)
        return (name, version) if name and version else None
    if "/" in key:
        name, version = key.rsplit("/", 1)
        return (name, version) if name and version else None
    return None


def parse_cargo_lock(path: Path, relative: str) -> list[DependencyPackage]:
    payload = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    dependencies: list[DependencyPackage] = []
    for item in payload.get("package") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        source = str(item.get("source") or "")
        if not name or not version or source and "crates.io" not in source:
            continue
        dependencies.append(
            DependencyPackage(
                name=name,
                ecosystem="crates.io",
                package_manager="cargo",
                manifest_file=relative,
                version=version,
                specifier=version,
                scope="resolved",
                direct=None,
                resolved=True,
                purl=make_purl("crates.io", name, version),
            )
        )
    return dedupe_dependencies(dependencies)


def parse_gemfile_lock(path: Path, relative: str) -> list[DependencyPackage]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    direct_names: set[str] = set()
    in_dependencies = False
    for raw in lines:
        if raw == "DEPENDENCIES":
            in_dependencies = True
            continue
        if in_dependencies and raw and not raw[0].isspace():
            in_dependencies = False
        if in_dependencies:
            match = re.match(r"^\s{2}([^\s(!]+)", raw)
            if match:
                direct_names.add(match.group(1))
    dependencies: list[DependencyPackage] = []
    in_specs = False
    for line_no, raw in enumerate(lines, start=1):
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and raw and not raw[0].isspace():
            in_specs = False
        if not in_specs:
            continue
        match = re.match(r"^\s{4}([^\s(]+)\s+\(([^),\s]+)", raw)
        if not match:
            continue
        name, version = match.groups()
        dependencies.append(
            DependencyPackage(
                name=name,
                ecosystem="rubygems",
                package_manager="bundler",
                manifest_file=relative,
                line=line_no,
                version=version,
                specifier=version,
                scope="resolved",
                direct=name in direct_names,
                resolved=True,
                purl=make_purl("rubygems", name, version),
            )
        )
    return dedupe_dependencies(dependencies)


def parse_composer_lock(path: Path, relative: str) -> list[DependencyPackage]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    dependencies: list[DependencyPackage] = []
    for section, scope in (("packages", "runtime"), ("packages-dev", "development")):
        for item in payload.get(section) or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            version = str(item.get("version") or "").strip().lstrip("v")
            if not name or not version:
                continue
            dependencies.append(
                DependencyPackage(
                    name=name,
                    ecosystem="packagist",
                    package_manager="composer",
                    manifest_file=relative,
                    version=version,
                    specifier=version,
                    scope=scope,
                    direct=None,
                    resolved=True,
                    purl=make_purl("packagist", name, version),
                )
            )
    return dedupe_dependencies(dependencies)


def parse_nuget_lock(path: Path, relative: str) -> list[DependencyPackage]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    dependencies: list[DependencyPackage] = []
    frameworks = payload.get("dependencies") if isinstance(payload.get("dependencies"), dict) else {}
    for framework, packages in frameworks.items():
        if not isinstance(packages, dict):
            continue
        for name, item in packages.items():
            if not isinstance(item, dict):
                continue
            version = str(item.get("resolved") or "").strip()
            if not version:
                continue
            dependency_type = str(item.get("type") or "").lower()
            dependencies.append(
                DependencyPackage(
                    name=str(name),
                    ecosystem="nuget",
                    package_manager="nuget",
                    manifest_file=relative,
                    version=version,
                    specifier=str(item.get("requested") or version),
                    scope=str(framework),
                    direct=True if dependency_type == "direct" else False if dependency_type == "transitive" else None,
                    resolved=True,
                    purl=make_purl("nuget", str(name), version),
                )
            )
    return dedupe_dependencies(dependencies)


def parse_go_mod(path: Path, relative: str) -> list[DependencyPackage]:
    dependencies: list[DependencyPackage] = []
    in_require_block = False
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_require_block:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        dependencies.append(
            DependencyPackage(
                name=parts[0],
                ecosystem="go",
                package_manager="go",
                manifest_file=relative,
                line=line_no,
                version=parts[1],
                specifier=parts[1],
                direct=True,
                resolved=True,
                purl=make_purl("go", parts[0], parts[1]),
            )
        )
    return dependencies


def parse_go_sum(path: Path, relative: str) -> list[DependencyPackage]:
    dependencies: list[DependencyPackage] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        parts = raw.split()
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        if version.endswith("/go.mod"):
            continue
        dependencies.append(
            DependencyPackage(
                name=name,
                ecosystem="go",
                package_manager="go",
                manifest_file=relative,
                line=line_no,
                version=version,
                specifier=version,
                scope="resolved",
                direct=None,
                resolved=True,
                purl=make_purl("go", name, version),
            )
        )
    return dedupe_dependencies(dependencies)


def analyze_dependencies_with_osv(
    manifests: list[DependencyManifest],
    *,
    endpoint: str | None = None,
    transport: Any | None = None,
    detail_transport: Any | None = None,
) -> tuple[list[DependencyFinding], dict[str, Any]]:
    all_components = [dependency for manifest in manifests for dependency in manifest.dependencies if osv_ecosystem(dependency.ecosystem)]
    components = dedupe_dependencies([dependency for dependency in all_components if dependency.version and dependency.resolved])
    resolved_keys = {dependency_resolution_key(item) for item in components}
    unresolved = dedupe_dependencies(
        [
            dependency
            for dependency in all_components
            if (not dependency.version or not dependency.resolved) and dependency_resolution_key(dependency) not in resolved_keys
        ]
    )
    total_dependencies = sum(len(manifest.dependencies) for manifest in manifests)
    diagnostics: dict[str, Any] = {
        "enabled": not env_truthy(OSV_DISABLED_ENV),
        "endpoint": endpoint or os.getenv(OSV_ENDPOINT_ENV, DEFAULT_OSV_ENDPOINT),
        "dependencies": total_dependencies,
        "resolved_components": len(components),
        "unresolved_components": len(unresolved),
        "queried_components": 0,
        "failed_components": 0,
        "advisories": 0,
        "detail_queries": 0,
        "detail_failures": 0,
        "query_retries": 0,
        "detail_retries": 0,
        "complete": False,
        "errors": [],
    }
    if not diagnostics["enabled"]:
        diagnostics["message"] = "OSV scanning disabled by environment."
        return [], diagnostics
    if not components:
        diagnostics["complete"] = total_dependencies == 0
        diagnostics["message"] = "No resolved dependency versions were available for deterministic OSV matching."
        return [], diagnostics

    sender = transport or post_osv_query_batch
    component_results: list[tuple[DependencyPackage, object]] = []
    for offset in range(0, len(components), OSV_QUERY_BATCH_SIZE):
        batch = components[offset : offset + OSV_QUERY_BATCH_SIZE]
        queries = [
            {
                "package": {"name": item.name, "ecosystem": osv_ecosystem(item.ecosystem)},
                "version": item.version,
            }
            for item in batch
        ]
        try:
            response, retries = call_osv_with_retry(sender, diagnostics["endpoint"], {"queries": queries})
            diagnostics["query_retries"] += retries
            raw_results = response.get("results") if isinstance(response, dict) else None
            if not isinstance(raw_results, list) or len(raw_results) != len(batch):
                raise ValueError("OSV querybatch returned a result count that does not match the request")
            diagnostics["queried_components"] += len(batch)
            for dependency, raw_result in zip(batch, raw_results, strict=True):
                component_results.append((dependency, raw_result))
        except Exception as exc:  # noqa: BLE001 - partial SCA results remain useful when completeness is explicit
            diagnostics["failed_components"] += len(batch)
            diagnostics["errors"].append(str(exc)[:800])
    detail_ids = sorted(
        {
            str(vulnerability.get("id") or "")
            for _, raw_result in component_results
            if isinstance(raw_result, dict)
            for vulnerability in raw_result.get("vulns") or []
            if isinstance(vulnerability, dict) and vulnerability.get("id") and not osv_vulnerability_has_details(vulnerability)
        }
    )
    details: dict[str, dict[str, Any]] = {}
    detail_sender = detail_transport or (post_osv_vulnerability if transport is None else None)
    if detail_ids and detail_sender:
        diagnostics["detail_queries"] = len(detail_ids)
        with ThreadPoolExecutor(max_workers=min(8, len(detail_ids)), thread_name_prefix="auditforge-osv-detail") as executor:
            futures = {
                executor.submit(call_osv_with_retry, detail_sender, diagnostics["endpoint"], advisory_id): advisory_id
                for advisory_id in detail_ids
            }
            for future in as_completed(futures):
                advisory_id = futures[future]
                try:
                    detail, retries = future.result()
                    diagnostics["detail_retries"] += retries
                    if isinstance(detail, dict):
                        details[advisory_id] = detail
                except Exception as exc:  # noqa: BLE001 - retain the advisory ID even if enrichment fails
                    diagnostics["detail_failures"] += 1
                    diagnostics["errors"].append(f"{advisory_id}: {exc}"[:800])

    findings: list[DependencyFinding] = []
    for dependency, raw_result in component_results:
        findings.extend(osv_findings_for_component(dependency, hydrate_osv_result(raw_result, details)))
    findings = merge_dependency_finding_list(findings)
    diagnostics["advisories"] = len(findings)
    diagnostics["complete"] = (
        diagnostics["failed_components"] == 0
        and diagnostics["queried_components"] == len(components)
        and diagnostics["detail_failures"] == 0
        and diagnostics["unresolved_components"] == 0
    )
    return findings, diagnostics


def call_osv_with_retry(operation: Any, *args: Any) -> tuple[Any, int]:
    """Retry only transient OSV transport failures with bounded backoff."""

    retries = 0
    for attempt in range(len(OSV_RETRY_DELAYS_SECONDS) + 1):
        try:
            return operation(*args), retries
        except Exception as exc:  # noqa: BLE001 - classification below is deliberately conservative
            if attempt >= len(OSV_RETRY_DELAYS_SECONDS) or not is_transient_osv_error(exc):
                raise
            retries += 1
            time.sleep(OSV_RETRY_DELAYS_SECONDS[attempt])
    raise AssertionError("unreachable OSV retry state")


def is_transient_osv_error(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or 500 <= exc.code <= 599
    if isinstance(exc, (TimeoutError, ConnectionError, urllib.error.URLError, json.JSONDecodeError)):
        return True
    # The built-in transport wraps URLError with a stable OSV-specific message.
    return isinstance(exc, RuntimeError) and "osv" in str(exc).lower()


def post_osv_query_batch(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "AuditForge/0.2 dependency-scanner"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(8 * 1024 * 1024)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OSV query failed: {exc}") from exc
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("OSV querybatch response must be a JSON object")
    return parsed


def post_osv_vulnerability(query_endpoint: str, advisory_id: str) -> dict[str, Any]:
    cache_key = (query_endpoint, advisory_id)
    with OSV_DETAIL_CACHE_LOCK:
        cached = OSV_DETAIL_CACHE.get(cache_key)
    if cached is not None:
        return cached
    endpoint = osv_detail_endpoint(query_endpoint, advisory_id)
    request = urllib.request.Request(endpoint, method="GET", headers={"User-Agent": "AuditForge/0.2 dependency-scanner"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(8 * 1024 * 1024)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OSV advisory lookup failed: {exc}") from exc
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("OSV advisory response must be a JSON object")
    with OSV_DETAIL_CACHE_LOCK:
        if len(OSV_DETAIL_CACHE) >= 5000:
            OSV_DETAIL_CACHE.pop(next(iter(OSV_DETAIL_CACHE)))
        OSV_DETAIL_CACHE[cache_key] = parsed
    return parsed


def osv_detail_endpoint(query_endpoint: str, advisory_id: str) -> str:
    parsed = urllib.parse.urlsplit(query_endpoint)
    path = parsed.path
    if path.endswith("/querybatch"):
        path = path[: -len("/querybatch")] + "/vulns/" + urllib.parse.quote(advisory_id, safe="-")
    else:
        path = path.rstrip("/") + "/vulns/" + urllib.parse.quote(advisory_id, safe="-")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def osv_vulnerability_has_details(vulnerability: dict[str, Any]) -> bool:
    return any(key in vulnerability for key in ("aliases", "affected", "summary", "details", "references", "severity"))


def hydrate_osv_result(raw_result: object, details: dict[str, dict[str, Any]]) -> object:
    if not isinstance(raw_result, dict) or not isinstance(raw_result.get("vulns"), list):
        return raw_result
    hydrated = dict(raw_result)
    hydrated["vulns"] = [details.get(str(item.get("id") or ""), item) if isinstance(item, dict) else item for item in raw_result["vulns"]]
    return hydrated


def osv_findings_for_component(dependency: DependencyPackage, raw_result: object) -> list[DependencyFinding]:
    if not isinstance(raw_result, dict):
        return []
    vulns = raw_result.get("vulns")
    if not isinstance(vulns, list):
        return []
    findings: list[DependencyFinding] = []
    for vulnerability in vulns:
        if not isinstance(vulnerability, dict):
            continue
        advisory_id = str(vulnerability.get("id") or "").strip()
        if not advisory_id:
            continue
        aliases = [str(item).strip() for item in vulnerability.get("aliases") or [] if str(item).strip()]
        advisory_ids = list(dict.fromkeys([advisory_id, *aliases]))
        cve_ids = normalize_cve_ids(advisory_ids)
        affected_entries, has_scoped_entries = osv_affected_entries_for_dependency(vulnerability, dependency)
        if has_scoped_entries and not affected_entries:
            # Some advisories describe several packages.  Never attach another
            # package's fixed version merely because the advisory ID matched.
            continue
        affected_range, fixed_versions = osv_affected_summary(vulnerability, affected_entries=affected_entries)
        severity = osv_severity(vulnerability)
        summary = clean_text(vulnerability.get("summary") or vulnerability.get("details") or advisory_id, 500)
        references = [
            str(item.get("url") or "").strip()
            for item in vulnerability.get("references") or []
            if isinstance(item, dict) and str(item.get("url") or "").strip()
        ][:8]
        evidence = (
            f"OSV matched {dependency.ecosystem}:{dependency.name}@{dependency.version} "
            f"from {dependency.manifest_file} to advisory {advisory_id}."
        )
        if affected_range:
            evidence += f" Affected range: {affected_range}."
        findings.append(
            DependencyFinding(
                id="DEP-OSV",
                package=dependency.name,
                ecosystem=dependency.ecosystem,
                manifest_file=dependency.manifest_file,
                line=dependency.line,
                installed_version=dependency.version,
                affected_range=affected_range,
                cve_ids=cve_ids,
                advisory_ids=advisory_ids,
                fixed_versions=fixed_versions,
                severity=severity,
                confidence="high",
                title=f"{dependency.name} {advisory_id}: {summary}"[:180],
                evidence=evidence,
                recommendation=(
                    f"Upgrade {dependency.name} to an official fixed version"
                    + (f" ({', '.join(fixed_versions[:4])})" if fixed_versions else "")
                    + " and verify the affected feature is not reachable."
                ),
                references=references,
                source="osv",
            )
        )
    return findings


def osv_affected_entries_for_dependency(vulnerability: dict[str, Any], dependency: DependencyPackage) -> tuple[list[dict[str, Any]], bool]:
    entries = [item for item in vulnerability.get("affected") or [] if isinstance(item, dict)]
    scoped = [item for item in entries if isinstance(item.get("package"), dict)]
    if not scoped:
        return entries, False
    expected_ecosystem = osv_ecosystem(dependency.ecosystem) or dependency.ecosystem
    matched: list[dict[str, Any]] = []
    for item in scoped:
        package = item["package"]
        package_name = str(package.get("name") or "")
        package_ecosystem = str(package.get("ecosystem") or "")
        if package_key(package_name, dependency.ecosystem) != package_key(dependency.name, dependency.ecosystem):
            continue
        if package_ecosystem and package_ecosystem.casefold() != expected_ecosystem.casefold():
            continue
        matched.append(item)
    return matched, True


def osv_affected_summary(
    vulnerability: dict[str, Any], *, affected_entries: list[dict[str, Any]] | None = None
) -> tuple[str | None, list[str]]:
    ranges: list[str] = []
    fixed: list[str] = []
    entries = affected_entries if affected_entries is not None else vulnerability.get("affected") or []
    for affected in entries:
        if not isinstance(affected, dict):
            continue
        for raw_range in affected.get("ranges") or []:
            if not isinstance(raw_range, dict):
                continue
            events: list[str] = []
            for event in raw_range.get("events") or []:
                if not isinstance(event, dict):
                    continue
                for key in ("introduced", "fixed", "last_affected", "limit"):
                    if key not in event:
                        continue
                    value = str(event[key])
                    events.append(f"{key}={value}")
                    if key == "fixed":
                        fixed.append(value)
            if events:
                ranges.append(f"{raw_range.get('type') or 'ECOSYSTEM'}({', '.join(events)})")
        for version in affected.get("versions") or []:
            if len(ranges) >= 8:
                break
            ranges.append(str(version))
    return ("; ".join(ranges[:8]) or None, list(dict.fromkeys(fixed))[:12])


def osv_severity(vulnerability: dict[str, Any]) -> DependencySeverity:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        value = str(database_specific.get("severity") or "").lower()
        if value in ALLOWED_SEVERITIES:
            return value  # type: ignore[return-value]
    for item in vulnerability.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = str(item.get("score") or "")
        numeric = parse_cvss_score(score)
        if numeric is not None:
            if numeric >= 9:
                return "critical"
            if numeric >= 7:
                return "high"
            if numeric >= 4:
                return "medium"
            return "low"
    return "unknown"


def parse_cvss_score(value: str) -> float | None:
    raw = str(value or "").strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", raw):
        return min(10.0, max(0.0, float(raw)))
    if raw.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return cvss_v3_base_score(raw)
    # A few feeds append an explicit numeric base score to a vector.
    explicit = re.search(r"(?:^|[;,\s])(?:base(?:score)?[=:])\s*(\d+(?:\.\d+)?)$", raw, flags=re.I)
    return min(10.0, max(0.0, float(explicit.group(1)))) if explicit else None


def cvss_v3_base_score(vector: str) -> float | None:
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
        scope_changed = metrics["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        pr_weights = {"N": 0.85, "L": 0.68, "H": 0.5} if scope_changed else {"N": 0.85, "L": 0.62, "H": 0.27}
        pr = pr_weights[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact_weights = {"H": 0.56, "L": 0.22, "N": 0.0}
        confidentiality = impact_weights[metrics["C"]]
        integrity = impact_weights[metrics["I"]]
        availability = impact_weights[metrics["A"]]
    except (KeyError, ValueError):
        return None

    impact_subscore = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    if scope_changed:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
    else:
        impact = 6.42 * impact_subscore
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    base = min(10.0, 1.08 * (impact + exploitability)) if scope_changed else min(10.0, impact + exploitability)
    return math.ceil((base - 1e-10) * 10) / 10


def osv_ecosystem(ecosystem: str) -> str | None:
    return {
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "go": "Go",
        "crates.io": "crates.io",
        "rubygems": "RubyGems",
        "packagist": "Packagist",
        "nuget": "NuGet",
    }.get(ecosystem.lower())


def analyze_dependencies_with_llm(
    repo_path: Path,
    manifests: list[DependencyManifest],
    config: LLMConfig | None,
) -> tuple[list[DependencyFinding], dict[str, Any]]:
    config = config or LLMConfig(enabled=False)
    package_count = sum(len(manifest.dependencies) for manifest in manifests)
    fixture_mode = bool(config.response_file) or config.provider == "fixture"
    if fixture_mode:
        osv_findings: list[DependencyFinding] = []
        osv_diagnostics: dict[str, Any] = {
            "enabled": False,
            "complete": False,
            "message": "OSV network lookup skipped for deterministic fixture transport.",
        }
    else:
        osv_findings, osv_diagnostics = analyze_dependencies_with_osv(manifests)
    diagnostics: dict[str, Any] = {
        "enabled": bool(config.enabled or osv_diagnostics.get("enabled")),
        "llm_enabled": config.enabled,
        "provider": config.provider,
        "model": config.model,
        "manifests": len(manifests),
        "dependencies": package_count,
        "concurrency": max(1, min(12, int(getattr(config, "concurrency", 1) or 1))),
        "chunks": 0,
        "accepted": 0,
        "rejected": [],
        "chunk_errors": [],
        "error": None,
        "osv": osv_diagnostics,
        "complete": bool(osv_diagnostics.get("complete")),
    }
    if not manifests or package_count == 0:
        diagnostics["message"] = "未发现可解析的依赖清单。"
        return [], diagnostics
    if not config.enabled:
        diagnostics["message"] = "确定性 OSV 扫描已完成；未启用 LLM 依赖解释。"
        diagnostics["accepted"] = len(osv_findings)
        return osv_findings, diagnostics

    try:
        chunks = split_dependency_manifests(manifests, DEPENDENCY_LLM_CHUNK_SIZE)
        diagnostics["chunks"] = len(chunks)
        workers = bounded_worker_count(config, len(chunks))
        diagnostics["concurrency"] = workers
        chunk_results: list[tuple[list[DependencyFinding], dict[str, Any]]] = [([], {}) for _ in chunks]
        if workers == 1:
            for index, chunk in enumerate(chunks):
                chunk_results[index] = analyze_dependency_chunk(repo_path, chunk, config, index)
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="auditforge-dependency") as executor:
                future_map = {
                    executor.submit(analyze_dependency_chunk, repo_path, chunk, config, index): index for index, chunk in enumerate(chunks)
                }
                for future in as_completed(future_map):
                    index = future_map[future]
                    chunk_results[index] = future.result()
        llm_findings = merge_dependency_findings(chunk_results, limit=MAX_DEPENDENCY_FINDINGS)
        for index, (_, chunk_diagnostics) in enumerate(chunk_results):
            for rejection in chunk_diagnostics.get("rejected", []):
                item = dict(rejection) if isinstance(rejection, dict) else {"reason": str(rejection)}
                item.setdefault("chunk", index + 1)
                diagnostics["rejected"].append(item)
            if chunk_diagnostics.get("error"):
                diagnostics["chunk_errors"].append({"chunk": index + 1, "error": chunk_diagnostics["error"]})
        findings = merge_dependency_finding_list([*osv_findings, *llm_findings])
        diagnostics["accepted"] = len(findings)
        diagnostics["llm_accepted"] = len(llm_findings)
        diagnostics["osv_accepted"] = len(osv_findings)
        diagnostics["complete"] = bool(osv_diagnostics.get("complete")) and not diagnostics["chunk_errors"]
        if diagnostics["chunk_errors"] and not findings:
            diagnostics["error"] = "; ".join(str(item["error"]) for item in diagnostics["chunk_errors"][:3])
        return findings, diagnostics
    except Exception as exc:  # noqa: BLE001 - dependency scan should not fail the code audit
        diagnostics["error"] = str(exc)
        diagnostics["accepted"] = len(osv_findings)
        diagnostics["complete"] = False
        return osv_findings, diagnostics


def analyze_dependency_chunk(
    repo_path: Path,
    manifests: list[DependencyManifest],
    config: LLMConfig,
    chunk_index: int,
) -> tuple[list[DependencyFinding], dict[str, Any]]:
    diagnostics: dict[str, Any] = {
        "chunk": chunk_index + 1,
        "dependencies": sum(len(manifest.dependencies) for manifest in manifests),
        "accepted": 0,
        "rejected": [],
        "error": None,
    }
    try:
        prompt = build_dependency_prompt(repo_path, manifests, config.max_prompt_chars, config.user_prompt)
        raw = load_llm_json_response(
            prompt,
            config,
            system_prompt=with_output_contract(
                (config.system_prompt or DEFAULT_DEPENDENCY_SYSTEM_PROMPT).strip() or DEFAULT_DEPENDENCY_SYSTEM_PROMPT,
                DEPENDENCY_OUTPUT_CONTRACT,
            ),
            temperature=0,
        )
        parsed = parse_json_object(raw)
        findings = normalize_dependency_findings(parsed, manifests, diagnostics, limit=MAX_DEPENDENCY_FINDINGS)
        diagnostics["accepted"] = len(findings)
        return findings, diagnostics
    except Exception as exc:  # noqa: BLE001 - one dependency chunk must not fail the whole scan
        diagnostics["error"] = str(exc)
        return [], diagnostics


def split_dependency_manifests(
    manifests: list[DependencyManifest], chunk_size: int = DEPENDENCY_LLM_CHUNK_SIZE
) -> list[list[DependencyManifest]]:
    chunk_size = max(1, chunk_size)
    dependencies: list[tuple[DependencyManifest, DependencyPackage]] = [
        (manifest, dependency) for manifest in manifests for dependency in manifest.dependencies
    ]
    chunks: list[list[DependencyManifest]] = []
    for offset in range(0, len(dependencies), chunk_size):
        grouped: dict[str, tuple[DependencyManifest, list[DependencyPackage]]] = {}
        for manifest, dependency in dependencies[offset : offset + chunk_size]:
            if manifest.file not in grouped:
                grouped[manifest.file] = (manifest, [])
            grouped[manifest.file][1].append(dependency)
        chunks.append(
            [
                DependencyManifest(
                    file=manifest.file,
                    ecosystem=manifest.ecosystem,
                    package_manager=manifest.package_manager,
                    dependencies=list(items),
                    skipped_reason=manifest.skipped_reason,
                )
                for manifest, items in grouped.values()
            ]
        )
    return chunks


def merge_dependency_findings(
    chunk_results: list[tuple[list[DependencyFinding], dict[str, Any]]],
    limit: int,
) -> list[DependencyFinding]:
    flattened = [finding for findings, _ in chunk_results for finding in findings]
    return merge_dependency_finding_list(flattened)[: max(0, limit)]


def merge_dependency_finding_list(flattened: list[DependencyFinding]) -> list[DependencyFinding]:
    flattened = sorted(flattened, key=dependency_finding_sort_key)
    findings: list[DependencyFinding] = []
    seen: set[tuple[str, str, str, str, tuple[str, ...], str | None]] = set()
    for finding in flattened:
        advisory_ids = tuple(sorted(finding.advisory_ids or finding.cve_ids))
        key = (
            finding.ecosystem.lower(),
            package_key(finding.package, finding.ecosystem),
            normalize_path(finding.manifest_file),
            str(finding.installed_version or ""),
            advisory_ids,
            finding.affected_range,
        )
        if key in seen:
            continue
        seen.add(key)
        findings.append(replace(finding, id=f"DEP-{len(findings) + 1:03d}"))
    return findings


def dependency_finding_sort_key(finding: DependencyFinding) -> tuple[int, int, int, str, str, str]:
    confidence_rank = {"high": 0, "medium": 1, "low": 2}.get(str(finding.confidence), 3)
    source_rank = 0 if finding.source == "osv" else 1
    return (
        -severity_rank(finding.severity),
        confidence_rank,
        source_rank,
        finding.ecosystem,
        package_key(finding.package, finding.ecosystem),
        finding.manifest_file,
    )


def bounded_worker_count(config: LLMConfig, task_count: int) -> int:
    if task_count <= 0:
        return 1
    return max(1, min(task_count, 12, int(getattr(config, "concurrency", 1) or 1)))


def build_dependency_prompt(
    repo_path: Path,
    manifests: list[DependencyManifest],
    max_chars: int,
    custom_instructions: str | None = None,
) -> str:
    inventory = [
        {
            "file": manifest.file,
            "ecosystem": manifest.ecosystem,
            "packageManager": manifest.package_manager,
            "dependencies": [dependency.to_dict() for dependency in manifest.dependencies[:200]],
            "skippedReason": manifest.skipped_reason,
        }
        for manifest in manifests
    ]
    excerpts: list[dict[str, Any]] = []
    used = 0
    repo_path = repo_path.resolve()
    for manifest in manifests:
        path = (repo_path / manifest.file).resolve()
        try:
            path.relative_to(repo_path)
        except ValueError:
            continue
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")[:8000]
        if used + len(text) > max_chars:
            break
        used += len(text)
        excerpts.append({"file": manifest.file, "content": text})
    prompt = {
        "role": "dependency_vulnerability_candidate_generator",
        "task": (custom_instructions or DEFAULT_DEPENDENCY_USER_PROMPT).strip() or DEFAULT_DEPENDENCY_USER_PROMPT,
        "rules": [
            "只输出 JSON object，不要 Markdown。",
            "只能报告 inventory 中出现的依赖包。",
            "依赖名、生态、installedVersion、manifestFile 必须与 inventory 对齐；不能改写成另一个包名或跨生态混用。",
            "优先给出明确 CVE ID；没有明确 CVE 时可给出 known vulnerable range 或过旧风险，但 confidence 必须为 low 或 medium。",
            "如果版本是范围、变量、BOM 继承、通配符、latest、未固定或无法解析，不能给 high confidence。",
            "如果不确定，不要编造 CVE、公告链接或修复版本；可以输出空 findings。",
            "不要把依赖风险写成已确认漏洞，recommendation 必须是升级或人工复核建议。",
            "同一 package/ecosystem/CVE 不要重复输出；多 CVE 可合并到同一 finding。",
            "evidence 必须说明：依赖在哪个清单、当前版本/约束、疑似受影响范围、为什么需要复核。",
            "references 只能放看起来可信的公开公告 URL，例如 NVD、OSV、GHSA、供应商公告；不确定就留空。",
            "severity 按远程代码执行/认证绕过/敏感信息泄露/DoS 等影响保守判断；不知道就用 unknown。",
        ],
        "inventoryPolicy": {
            "sourceOfTruth": "inventory 是唯一事实来源；manifestExcerpts 只用于核对行和上下文。",
            "allowedPackages": "findings[].package 必须等于 inventory.dependencies[].name 中的一个值。",
            "versionUncertainty": "specifier 不是精确版本时，必须在 evidence 说明版本不确定性并降低 confidence。",
            "scopeHandling": "development/test/optional/peer scope 需要在 evidence 中说明，通常不能直接高置信。",
        },
        "offlineKnowledgePolicy": {
            "memoryIsNotAuthority": "模型记忆不是权威漏洞库；没有明确公告编号或影响范围时，confidence 不能为 high。",
            "whenToReturnEmpty": [
                "只知道该组件历史上有漏洞，但无法匹配当前版本范围。",
                "包名和生态可能混淆，或 inventory 中只有变量/范围版本。",
                "风险只来自版本较旧但没有明确安全公告线索。",
                "引用链接、修复版本或 CVE ID 不能可靠确认。",
            ],
            "allowedUncertainFinding": "可以输出 low/medium 的复核候选，但 evidence 必须明确写出不确定来源和需要 OSV/NVD/GHSA/供应商公告复核。",
            "highConfidenceRequires": "high 必须同时满足包名生态精确匹配、安装版本明确、公告影响范围明确、当前版本落入范围。",
        },
        "versionReasoningRules": [
            "精确版本（例如 ==1.2.3、1.2.3、v1.2.3）可以和受影响范围直接比较。",
            "范围版本（例如 >=、<=、~、^、*、latest、x、变量、Maven property、BOM 继承）只能说明可能受影响，除非 inventory 已解析出精确 installedVersion。",
            "npm ^ 和 ~、Python ~=、Maven version range、Go pseudo-version 需要保守解释，不能直接等同于某个固定版本。",
            "预发布、fork、replace、classifier、optional/test scope 会改变风险判断，必须在 evidence 中注明。",
            "如果无法判断版本是否落入 affectedRange，confidence 最高为 medium；如果仅凭版本过旧，confidence 最高为 low。",
        ],
        "versionComparisonChecklist": [
            "确认 installedVersion 是否是精确版本；如果只是 specifier，说明实际安装版本可能不同。",
            "确认 affectedRange 的上下界是否包含当前版本；边界不确定时不要 high。",
            "确认修复版本是否属于同一主版本/生态/发行线；不要跨语言或跨 artifact 套用。",
            "Maven property、parent BOM、dependencyManagement 未解析时，evidence 必须说明可能需要构建工具解析。",
            "npm lockfile 缺失时不要假定 ^ 或 ~ 一定安装了最低版本。",
            "Go module path 带 /v2、replace、fork 或 pseudo-version 时，必须降低置信或说明限制。",
        ],
        "ecosystemNormalization": {
            "pypi": "包名大小写通常不敏感，连字符/下划线可能等价，但输出 package 必须保持 inventory 原始名称。",
            "npm": "scope package（如 @scope/name）必须完整匹配；不要和无 scope 同名包混用。",
            "maven": "groupId:artifactId 必须一起匹配；不能只根据 artifactId 判定。",
            "go": "module path 必须完整匹配；replace/fork/major version suffix 需要降低置信或说明限制。",
        },
        "packageIdentityExamples": [
            "maven: org.apache.logging.log4j:log4j-core 与 org.apache.logging.log4j:log4j-api 不是同一组件，不能混报。",
            "npm: @babel/core 与 babel-core、core-js 与 @babel/core 不是同一组件。",
            "pypi: python-jose、jose、python-jose-cryptodome 需要按 inventory 原始包名输出并说明不确定性。",
            "go: github.com/gin-gonic/gin 与 gopkg.in/gin-gonic/gin.v1 或 fork module 不能只按短名匹配。",
        ],
        "advisoryEvidencePolicy": {
            "preferredSources": ["NVD", "OSV", "GHSA", "vendor advisory", "ecosystem advisory", "release notes"],
            "referenceRules": [
                "只有在你确信 URL 形式和公告身份匹配时才填写 references。",
                "不确定引用时 references 留空，并在 evidence 中说明需要外部 SCA 源复核。",
                "cveIds 可以为空；不要为了显得完整而编造 CVE/GHSA/OSV ID。",
            ],
            "confidenceDowngrade": [
                "依赖只出现在 dev/test scope。",
                "版本来自变量、BOM、lockfile 缺失或未固定范围。",
                "公告只影响可选功能、特定配置或特定运行环境。",
                "只记得组件曾经有漏洞但不确定当前版本范围。",
            ],
        },
        "riskTaxonomy": {
            "critical": "公开已知 RCE、供应链接管、默认可利用认证绕过，且版本明确落入受影响范围。",
            "high": "SQL/模板/反序列化/SSRF 等高影响漏洞，或明确高危 CVE 且版本匹配。",
            "medium": "XSS、信息泄露、权限校验缺陷、DoS 或版本疑似受影响但上下文不完整。",
            "low": "过旧、未固定、潜在风险或需要人工核实的弱信号。",
            "unknown": "可能有公告但严重性或版本影响无法可靠判断。",
        },
        "confidenceRubric": {
            "high": "包名、生态、精确版本和 CVE/公告影响范围高度匹配。",
            "medium": "包名和生态匹配，但版本约束、影响范围或修复版本存在不确定。",
            "low": "仅基于过旧版本、宽泛约束、模型记忆或疑似公告，需要 SCA 工具复核。",
        },
        "falsePositiveGuidance": [
            "不要把同名不同生态的包混淆，例如 npm package 与 PyPI package。",
            "不要把传递依赖当成直接依赖，除非 inventory 明确包含它。",
            "不要把已经大于修复版本的组件报为受影响。",
            "不要因为版本老就强行绑定 CVE；过旧风险可以没有 CVE。",
            "不要把插件、示例、注释或 manifestExcerpts 中非依赖字段当成依赖。",
            "不要把框架本身的通用历史漏洞套到所有版本；必须说明当前版本为何可能受影响。",
            "不要把缺少 lockfile 解释为已确认漏洞；它只能是供应链风险或复核建议。",
        ],
        "scaOutputQualityGate": [
            "title 要包含组件名和风险类型，避免泛泛写“存在漏洞”。",
            "evidence 必须包含 manifestFile、installedVersion/specifier、affectedRange 或不确定原因。",
            "recommendation 不能只写“升级”，应写建议使用 OSV/NVD/GHSA/生态 advisory 复核并升级到官方修复版本。",
            "references 不确定时留空；不要生成看似真实但无法保证的 URL。",
            "同一包多个 CVE 可合并，但不同生态或不同 manifest 的同名包不能合并。",
        ],
        "evidenceChecklist": [
            "manifestFile 和行号/清单位置（如果 inventory 有 line）。",
            "installedVersion 或 specifier。",
            "CVE/GHSA/OSV ID 或 unknown affected range。",
            "为什么此版本可能落入受影响范围。",
            "scope、版本不确定性、是否需要外部 SCA 源复核。",
            "升级或复核建议。",
        ],
        "outputSchema": {
            "findings": [
                {
                    "package": "依赖名，必须来自 inventory",
                    "ecosystem": "pypi|maven|npm|go|crates.io|rubygems|packagist|nuget",
                    "installedVersion": "当前版本或版本约束",
                    "affectedRange": "受影响版本范围",
                    "cveIds": ["CVE-YYYY-NNNN"],
                    "severity": "critical|high|medium|low|unknown",
                    "confidence": "low|medium|high",
                    "title": "中文风险标题",
                    "evidence": "为什么该组件/版本需要复核",
                    "recommendation": "建议升级版本或复核动作",
                    "manifestFile": "依赖清单文件",
                    "references": ["可选引用 URL"],
                }
            ]
        },
        "inventory": inventory,
        "manifestExcerpts": excerpts,
    }
    return json.dumps(prompt, ensure_ascii=False)


def normalize_dependency_findings(
    parsed: dict[str, Any],
    manifests: list[DependencyManifest],
    diagnostics: dict[str, Any],
    limit: int,
) -> list[DependencyFinding]:
    inventory = dependency_index(manifests)
    findings: list[DependencyFinding] = []
    seen: set[tuple[str, str, str, str, tuple[str, ...]]] = set()
    if "findings" not in parsed:
        diagnostics["rejected"].append(
            {
                "reason": "schema_error: missing required root key findings",
                "root_keys": sorted(str(key) for key in parsed.keys())[:20],
            }
        )
        return findings
    raw_findings = parsed.get("findings") or []
    if not isinstance(raw_findings, list):
        diagnostics["rejected"].append({"reason": "schema_error: findings must be a list", "actual_type": type(raw_findings).__name__})
        return findings
    for item in raw_findings:
        if len(findings) >= limit:
            break
        if not isinstance(item, dict):
            diagnostics["rejected"].append({"reason": "finding is not object"})
            continue
        package = str(item.get("package") or item.get("name") or "").strip()
        ecosystem = str(item.get("ecosystem") or "").strip().lower()
        if not package or not ecosystem:
            diagnostics["rejected"].append({"reason": "missing package or ecosystem", "item": safe_reject_item(item)})
            continue
        if not inventory.get((ecosystem, package_key(package, ecosystem))):
            diagnostics["rejected"].append({"reason": "package not in dependency inventory", "package": package, "ecosystem": ecosystem})
            continue
        schema_errors = validate_dependency_finding_schema(item)
        if schema_errors:
            diagnostics["rejected"].append({"reason": "schema_error: " + "；".join(schema_errors[:4]), "item": safe_reject_item(item)})
            continue
        manifest_file = normalize_path(str(item.get("manifestFile") or ""))
        installed_version = clean_optional(item.get("installedVersion"))
        dependency, resolution_error = resolve_dependency_instance(
            inventory,
            ecosystem,
            package,
            manifest_file,
            installed_version,
        )
        if not dependency:
            diagnostics["rejected"].append(
                {
                    "reason": resolution_error or "package not in dependency inventory",
                    "package": package,
                    "ecosystem": ecosystem,
                    "manifest": manifest_file,
                }
            )
            continue
        cve_ids = normalize_cve_ids(item.get("cveIds") or item.get("cves") or item.get("cve_ids") or [])
        advisory_ids = normalize_advisory_ids(item.get("advisoryIds") or item.get("advisory_ids") or cve_ids)
        key = (
            ecosystem,
            package_key(package, ecosystem),
            dependency.manifest_file,
            str(dependency.version or dependency.specifier or ""),
            tuple(advisory_ids),
        )
        if key in seen:
            diagnostics["rejected"].append({"reason": "duplicate", "package": package, "ecosystem": ecosystem})
            continue
        seen.add(key)
        severity = normalize_severity(str(item.get("severity") or "unknown"))
        confidence = normalize_confidence(str(item.get("confidence") or "low"))
        title = clean_text(item.get("title") or f"{dependency.name} 依赖风险候选", 180)
        evidence = clean_text(item.get("evidence") or item.get("reason") or "LLM 判断该依赖版本需要进行 CVE 复核。", 900)
        recommendation = clean_text(item.get("recommendation") or "使用 OSV/NVD 或企业 SCA 工具复核，并升级到官方修复版本。", 600)
        findings.append(
            DependencyFinding(
                id=f"DEP-{len(findings) + 1:03d}",
                package=dependency.name,
                ecosystem=dependency.ecosystem,
                manifest_file=dependency.manifest_file,
                line=dependency.line,
                installed_version=dependency.version or dependency.specifier,
                affected_range=clean_optional(item.get("affectedRange")),
                cve_ids=cve_ids,
                advisory_ids=advisory_ids,
                severity=severity,
                confidence=confidence,
                title=title,
                evidence=evidence,
                recommendation=recommendation,
                references=normalize_references(item.get("references") or item.get("refs") or []),
                source="llm",
            )
        )
    return sorted(findings, key=lambda finding: severity_rank(finding.severity), reverse=True)


def validate_dependency_finding_schema(item: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in ("package", "ecosystem", "installedVersion", "affectedRange", "title", "evidence", "recommendation", "manifestFile"):
        if key not in item and not (key == "package" and "name" in item):
            errors.append(f"{key} 缺失")
    ecosystem = str(item.get("ecosystem") or "").strip().lower()
    if ecosystem and ecosystem not in {"pypi", "maven", "npm", "go", "crates.io", "rubygems", "packagist", "nuget"}:
        errors.append("ecosystem 枚举值非法")
    severity = str(item.get("severity") or "").strip().lower()
    if severity not in ALLOWED_SEVERITIES:
        errors.append("severity 缺失或枚举值非法")
    confidence = str(item.get("confidence") or "").strip().lower()
    if confidence not in ALLOWED_CONFIDENCE:
        errors.append("confidence 缺失或枚举值非法")
    cve_ids = item.get("cveIds") or item.get("cves") or item.get("cve_ids") or []
    if cve_ids is not None and not isinstance(cve_ids, (list, str)):
        errors.append("cveIds 必须是数组或字符串")
    references = item.get("references") or item.get("refs") or []
    if references is not None and not isinstance(references, (list, str)):
        errors.append("references 必须是数组或字符串")
    for key in ("title", "evidence", "recommendation"):
        if key in item and (not isinstance(item.get(key), str) or not str(item.get(key)).strip()):
            errors.append(f"{key} 必须是非空字符串")
    return errors


def dependency_index(manifests: list[DependencyManifest]) -> dict[tuple[str, str], list[DependencyPackage]]:
    index: dict[tuple[str, str], list[DependencyPackage]] = {}
    for manifest in manifests:
        for dependency in manifest.dependencies:
            key = (dependency.ecosystem.lower(), package_key(dependency.name, dependency.ecosystem))
            index.setdefault(key, []).append(dependency)
    return index


def resolve_dependency_instance(
    inventory: dict[tuple[str, str], list[DependencyPackage]],
    ecosystem: str,
    package: str,
    manifest_file: str,
    installed_version: str | None,
) -> tuple[DependencyPackage | None, str | None]:
    candidates = list(inventory.get((ecosystem, package_key(package, ecosystem)), []))
    if not candidates:
        return None, "package not in dependency inventory"
    exact_manifest = [item for item in candidates if normalize_path(item.manifest_file) == manifest_file]
    if manifest_file:
        if not exact_manifest:
            return None, "manifestFile does not match dependency inventory"
        candidates = exact_manifest
    if installed_version:
        exact_version_matches = [item for item in candidates if installed_version in {str(item.version or ""), str(item.specifier or "")}]
        if exact_version_matches:
            candidates = exact_version_matches
    if len(candidates) != 1:
        return None, "dependency instance is ambiguous across manifests or versions"
    return candidates[0], None


def strip_inline_comment(line: str) -> str:
    if " #" not in line:
        return line
    return line.split(" #", 1)[0]


def normalize_specifier(value: str) -> str:
    return value.strip().rstrip(";").strip()


def exact_version(specifier: str | None) -> str | None:
    if not specifier:
        return None
    match = re.match(r"^\s*(?:==|===)\s*([^,;\s]+)", specifier)
    if match:
        candidate = match.group(1)
        return candidate if any(char.isdigit() for char in candidate) else None
    if re.match(r"^[0-9A-Za-z_.!+-]+$", specifier) and any(char.isdigit() for char in specifier):
        return specifier
    return None


def child_text(node: ET.Element, name: str) -> str:
    child = node.find(f"{{*}}{name}")
    return child.text.strip() if child is not None and child.text else ""


def pom_properties(root: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    properties = root.find(".//{*}properties")
    if properties is None:
        return props
    for child in list(properties):
        tag = child.tag.split("}", 1)[-1]
        if child.text:
            props[tag] = child.text.strip()
    return props


def substitute_property(value: str, properties: dict[str, str]) -> str:
    if not value:
        return ""
    current = value.strip()
    for _ in range(12):
        replaced = re.sub(r"\$\{([^}]+)\}", lambda match: properties.get(match.group(1), match.group(0)), current)
        if replaced == current:
            break
        current = replaced
    return current


def ecosystem_for_manifest(name: str) -> str:
    if name.startswith("requirements") and name.endswith(".txt") or name in {"pyproject.toml", "uv.lock", "poetry.lock", "Pipfile.lock"}:
        return "pypi"
    if name == "pom.xml":
        return "maven"
    if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}:
        return "npm"
    if name in {"go.mod", "go.sum"}:
        return "go"
    if name == "Cargo.lock":
        return "crates.io"
    if name == "Gemfile.lock":
        return "rubygems"
    if name == "composer.lock":
        return "packagist"
    if name == "packages.lock.json":
        return "nuget"
    return "unknown"


def package_manager_for_manifest(name: str) -> str:
    known = {
        "pom.xml": "maven",
        "package.json": "npm",
        "package-lock.json": "npm",
        "npm-shrinkwrap.json": "npm",
        "yarn.lock": "yarn",
        "pnpm-lock.yaml": "pnpm",
        "go.mod": "go",
        "go.sum": "go",
        "Cargo.lock": "cargo",
        "Gemfile.lock": "bundler",
        "composer.lock": "composer",
        "packages.lock.json": "nuget",
        "pyproject.toml": "pyproject",
        "uv.lock": "uv",
        "poetry.lock": "poetry",
        "Pipfile.lock": "pipenv",
    }
    return known.get(name, "pip" if name.startswith("requirements") else "unknown")


def normalize_cve_ids(value: object) -> list[str]:
    if isinstance(value, str):
        raw_items = re.findall(r"CVE-\d{4}-\d{4,}", value, flags=re.I)
    elif isinstance(value, list):
        raw_items = []
        for item in value:
            raw_items.extend(re.findall(r"CVE-\d{4}-\d{4,}", str(item), flags=re.I))
    else:
        raw_items = []
    seen: set[str] = set()
    out: list[str] = []
    for item in raw_items:
        cve = item.upper()
        if cve in seen:
            continue
        seen.add(cve)
        out.append(cve)
    return out[:12]


def normalize_advisory_ids(value: object) -> list[str]:
    items = value if isinstance(value, list) else [value] if value else []
    identifiers: list[str] = []
    for item in items:
        identifiers.extend(
            match.upper()
            for match in re.findall(
                r"(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Za-z-]{8,}|OSV-[0-9A-Za-z_.-]+|[A-Z]+SA-\d{4}-\d+)",
                str(item),
                flags=re.I,
            )
        )
    return list(dict.fromkeys(identifiers))[:24]


def normalize_references(value: object) -> list[str]:
    items = value if isinstance(value, list) else [value] if value else []
    references: list[str] = []
    for item in items:
        ref = str(item or "").strip()
        if not ref or len(ref) > 400:
            continue
        references.append(ref)
    return references[:8]


def normalize_severity(value: str) -> DependencySeverity:
    normalized = value.strip().lower()
    return normalized if normalized in ALLOWED_SEVERITIES else "unknown"  # type: ignore[return-value]


def normalize_confidence(value: str) -> Confidence:
    normalized = value.strip().lower()
    return normalized if normalized in ALLOWED_CONFIDENCE else "low"  # type: ignore[return-value]


def clean_text(value: object, limit: int) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def clean_optional(value: object) -> str | None:
    cleaned = clean_text(value, 240)
    return cleaned or None


def package_key(value: str, ecosystem: str = "pypi") -> str:
    normalized = value.strip()
    if ecosystem.lower() == "pypi":
        return re.sub(r"[-_.]+", "-", normalized.lower())
    if ecosystem.lower() in {"npm", "crates.io", "rubygems", "packagist", "nuget"}:
        return normalized.lower()
    return normalized


def make_purl(ecosystem: str, name: str, version: str | None) -> str:
    purl_type = {
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "go": "golang",
        "crates.io": "cargo",
        "rubygems": "gem",
        "packagist": "composer",
        "nuget": "nuget",
    }.get(ecosystem.lower(), ecosystem.lower())
    encoded_name = "/".join(urllib.parse.quote(part, safe="") for part in name.split("/"))
    value = f"pkg:{purl_type}/{encoded_name}"
    return f"{value}@{urllib.parse.quote(version, safe='.+-_~:')}" if version else value


def dedupe_dependencies(dependencies: list[DependencyPackage]) -> list[DependencyPackage]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[DependencyPackage] = []
    for dependency in dependencies:
        key = (
            dependency.ecosystem.lower(),
            package_key(dependency.name, dependency.ecosystem),
            normalize_path(dependency.manifest_file),
            str(dependency.version or dependency.specifier or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(dependency)
    return output


def dependency_resolution_key(dependency: DependencyPackage) -> tuple[str, str, str]:
    manifest_parent = normalize_path(Path(dependency.manifest_file).parent)
    return (
        dependency.ecosystem.lower(),
        package_key(dependency.name, dependency.ecosystem),
        "" if manifest_parent == "." else manifest_parent,
    )


def env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def severity_rank(severity: str) -> int:
    return {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)


def safe_reject_item(item: dict[str, Any]) -> dict[str, Any]:
    return {str(key): clean_text(value, 120) for key, value in list(item.items())[:8]}
