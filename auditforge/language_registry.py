"""Dispatch structured lightweight frontends for supported non-Python languages."""

from __future__ import annotations

from typing import Any

from .language_frontend import LanguageAnalysisResult


def analyze_language_frontend(source_file: Any) -> LanguageAnalysisResult | None:
    """Return additional framework-aware facts for a supported language.

    The caller retains the legacy generic extraction as a conservative baseline;
    these packs add language/framework-specific facts and are intentionally
    isolated so a malformed file cannot break the whole repository scan.
    """

    language = str(source_file.file.language)
    if language == "javascript":
        from .javascript_analysis import analyze_javascript

        return analyze_javascript(source_file)
    if language == "typescript":
        from .javascript_analysis import analyze_typescript

        return analyze_typescript(source_file)
    if language in {"java", "go"}:
        from .java_go_analysis import analyze_go, analyze_java

        return analyze_java(source_file) if language == "java" else analyze_go(source_file)
    if language == "php":
        from .php_analysis import analyze_php

        return analyze_php(source_file)
    return None


def frontend_id(language: str) -> str | None:
    return {
        "javascript": "javascript-v1",
        "typescript": "typescript-v1",
        "java": "java-v1",
        "go": "go-v1",
        "php": "php-v2",
    }.get(language)
