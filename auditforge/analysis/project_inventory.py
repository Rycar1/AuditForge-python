from __future__ import annotations

import os
from pathlib import Path
from typing import Any

MAX_INVENTORY_FILE_BYTES = 2 * 1024 * 1024
MAX_INVENTORY_FILES = 100_000
INVENTORY_READ_CHUNK_BYTES = 64 * 1024

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".shannon",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "target",
    "uploads",
    "uploaded_files",
    "media",
    "tmp",
    "temp",
    "package-staging",
}

LANGUAGE_BY_SUFFIX = {
    ".py": ("python", "Python"),
    ".js": ("javascript", "JavaScript"),
    ".jsx": ("javascript", "JavaScript"),
    ".mjs": ("javascript", "JavaScript"),
    ".cjs": ("javascript", "JavaScript"),
    ".ts": ("typescript", "TypeScript"),
    ".tsx": ("typescript", "TypeScript"),
    ".java": ("java", "Java"),
    ".go": ("go", "Go"),
    ".php": ("php", "PHP"),
    ".rb": ("ruby", "Ruby"),
    ".cs": ("csharp", "C#"),
    ".kt": ("kotlin", "Kotlin"),
    ".kts": ("kotlin", "Kotlin"),
    ".rs": ("rust", "Rust"),
    ".scala": ("scala", "Scala"),
    ".c": ("c", "C"),
    ".h": ("c", "C"),
    ".cc": ("cpp", "C++"),
    ".cpp": ("cpp", "C++"),
    ".cxx": ("cpp", "C++"),
    ".hpp": ("cpp", "C++"),
    ".swift": ("swift", "Swift"),
    ".dart": ("dart", "Dart"),
    ".html": ("html", "HTML"),
    ".htm": ("html", "HTML"),
    ".css": ("css", "CSS"),
    ".scss": ("scss", "SCSS"),
    ".sass": ("sass", "Sass"),
    ".vue": ("vue", "Vue"),
    ".svelte": ("svelte", "Svelte"),
    ".json": ("json", "JSON"),
    ".jsonc": ("json", "JSON"),
    ".toml": ("toml", "TOML"),
    ".yaml": ("yaml", "YAML"),
    ".yml": ("yaml", "YAML"),
    ".xml": ("xml", "XML"),
    ".sql": ("sql", "SQL"),
    ".sh": ("shell", "Shell"),
    ".bash": ("shell", "Shell"),
    ".zsh": ("shell", "Shell"),
    ".ps1": ("powershell", "PowerShell"),
    ".bat": ("batch", "Batch"),
    ".cmd": ("batch", "Batch"),
    ".md": ("markdown", "Markdown"),
    ".mdx": ("markdown", "Markdown"),
    ".txt": ("text", "Text"),
    ".ini": ("ini", "INI"),
    ".cfg": ("ini", "INI"),
    ".conf": ("config", "Config"),
    ".properties": ("properties", "Properties"),
}

LANGUAGE_BY_NAME = {
    "dockerfile": ("dockerfile", "Dockerfile"),
    "makefile": ("makefile", "Makefile"),
    "rakefile": ("ruby", "Ruby"),
    "gemfile": ("ruby", "Ruby"),
    "pipfile": ("toml", "TOML"),
}


def build_project_inventory(repo_path: Path) -> dict[str, Any]:
    repo_path = repo_path.resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError(f"待盘点路径不存在或不是目录：{repo_path}")
    language_totals: dict[str, dict[str, Any]] = {}
    counted_files = 0
    skipped_files = 0
    total_bytes = 0
    visited_files = 0
    skipped_symlinks = 0
    truncated = False
    errors: list[str] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [name for name in dirs if not should_skip_dir(name) and not (Path(root) / name).is_symlink()]
        for name in files:
            visited_files += 1
            if visited_files > MAX_INVENTORY_FILES:
                truncated = True
                break
            absolute = Path(root) / name
            if absolute.is_symlink():
                skipped_files += 1
                skipped_symlinks += 1
                continue
            try:
                absolute.resolve().relative_to(repo_path)
            except (OSError, ValueError) as exc:
                skipped_files += 1
                errors.append(f"{absolute}: {exc}")
                continue
            language = language_for_path(absolute)
            if not language:
                continue
            try:
                stat = absolute.stat()
            except OSError:
                skipped_files += 1
                continue
            if stat.st_size > MAX_INVENTORY_FILE_BYTES:
                skipped_files += 1
                continue
            file_stats = inventory_file_stats(absolute)
            if file_stats is None:
                skipped_files += 1
                continue
            is_binary, lines = file_stats
            if is_binary:
                skipped_files += 1
                continue
            language_id, label = language
            bucket = language_totals.setdefault(
                language_id,
                {"id": language_id, "language": label, "files": 0, "lines": 0, "bytes": 0},
            )
            bucket["files"] += 1
            bucket["lines"] += lines
            bucket["bytes"] += stat.st_size
            counted_files += 1
            total_bytes += stat.st_size
        if truncated:
            break

    total_lines = sum(int(item["lines"]) for item in language_totals.values())
    languages = sorted(language_totals.values(), key=lambda item: (-int(item["lines"]), str(item["language"])))
    for item in languages:
        item["percent"] = round((int(item["lines"]) / total_lines * 100), 1) if total_lines else 0.0
    return {
        "source_root": str(repo_path),
        "total_lines": total_lines,
        "language_count": len(languages),
        "file_count": counted_files,
        "total_bytes": total_bytes,
        "skipped_files": skipped_files,
        "skipped_symlinks": skipped_symlinks,
        "truncated": truncated,
        "max_files": MAX_INVENTORY_FILES,
        "errors": errors[:100],
        "languages": languages,
    }


def language_for_path(path: Path) -> tuple[str, str] | None:
    by_name = LANGUAGE_BY_NAME.get(path.name.lower())
    if by_name:
        return by_name
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith("workspace-")


def is_binary_file(path: Path) -> bool:
    file_stats = inventory_file_stats(path)
    return file_stats is None or file_stats[0]


def inventory_file_stats(path: Path) -> tuple[bool, int] | None:
    """Return binary status and physical line count without materializing a file.

    Project inventory previously opened every eligible source file twice: once for
    a small binary probe and again to decode the complete contents solely to
    count lines.  Scan indexing immediately reads those same files afterwards,
    so avoiding the intermediate decoded string keeps cold large-project scans
    much flatter in memory while retaining the exact line-count convention.
    """

    newline_count = 0
    has_content = False
    ends_with_newline = False
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(INVENTORY_READ_CHUNK_BYTES):
                if b"\x00" in chunk:
                    return True, 0
                has_content = True
                newline_count += chunk.count(b"\n")
                ends_with_newline = chunk.endswith(b"\n")
    except OSError:
        return None
    if not has_content:
        return False, 0
    return False, newline_count + (0 if ends_with_newline else 1)


def count_physical_lines(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def inventory_summary(inventory: dict[str, Any] | None) -> str:
    if not isinstance(inventory, dict):
        return "项目盘点未生成"
    total_lines = int(inventory.get("total_lines") or 0)
    language_count = int(inventory.get("language_count") or 0)
    return f"共 {total_lines:,} 行代码 · {language_count} 种语言"
