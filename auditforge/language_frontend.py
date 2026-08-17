"""Shared fact builder for lightweight non-Python language frontends.

The repository deliberately has no compiler/runtime dependency for every source
language.  These helpers keep the language packs structured: each pack supplies
syntax and framework recognition, then emits the same facts consumed by the
graph, taint, LLM and reporting stages.  ``analysis_method`` remains
``heuristic`` until a grammar-backed frontend is installed, so reports never
overstate parser precision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import (
    CallSiteFact,
    ClassFact,
    CodeAnchor,
    ControlFlowFact,
    DataFlowFact,
    FunctionFact,
    RouteFact,
    SanitizerFact,
    SinkFact,
    SourceFact,
)
from .utils import sha256_text, stable_id

SINK_TAXONOMY: dict[str, tuple[str, list[str]]] = {
    "raw_sql": ("sql_injection", ["CWE-89"]),
    "command_execution": ("command_injection", ["CWE-78"]),
    "file_path": ("path_traversal", ["CWE-22"]),
    "deserialization": ("unsafe_deserialization", ["CWE-502"]),
    "code_evaluation": ("code_injection", ["CWE-95"]),
    "html_output": ("cross_site_scripting", ["CWE-79"]),
    "external_request": ("server_side_request_forgery", ["CWE-918"]),
    "template_compilation": ("template_injection", ["CWE-94"]),
    "prototype_mutation": ("prototype_pollution", ["CWE-1321"]),
    "auth_primitive": ("authentication_failure", ["CWE-287"]),
    "authorization_decision": ("authorization_failure", ["CWE-862"]),
}


@dataclass
class LanguageAnalysisResult:
    functions: list[FunctionFact] = field(default_factory=list)
    classes: list[ClassFact] = field(default_factory=list)
    routes: list[RouteFact] = field(default_factory=list)
    call_sites: list[CallSiteFact] = field(default_factory=list)
    data_flows: list[DataFlowFact] = field(default_factory=list)
    control_flows: list[ControlFlowFact] = field(default_factory=list)
    sources: list[SourceFact] = field(default_factory=list)
    sinks: list[SinkFact] = field(default_factory=list)
    sanitizers: list[SanitizerFact] = field(default_factory=list)


class LanguageFactBuilder:
    """Create language-neutral facts while retaining stable source anchors."""

    def __init__(self, source_file: Any) -> None:
        self.source_file = source_file
        self.result = LanguageAnalysisResult()

    @property
    def path(self) -> str:
        return str(self.source_file.file.path)

    @property
    def lines(self) -> list[str]:
        return list(self.source_file.lines)

    def anchor(self, line: int, end_line: int | None = None, symbol: str | None = None) -> CodeAnchor:
        start = max(1, line)
        end = max(start, end_line if end_line is not None else start)
        snippet = "\n".join(self.lines[start - 1 : end])
        return CodeAnchor(
            file=self.path,
            start_line=start,
            end_line=end,
            snippet_hash=sha256_text(snippet),
            symbol=symbol,
        )

    def add_function(
        self,
        name: str,
        line: int,
        params: list[str],
        end_line: int,
        *,
        qualified_name: str | None = None,
        class_id: str | None = None,
    ) -> FunctionFact:
        fact = FunctionFact(
            id=stable_id("function", self.path, line, qualified_name or name),
            name=name,
            anchor=self.anchor(line, end_line, name),
            params=params,
            qualified_name=qualified_name or name,
            class_id=class_id,
            analysis_method="heuristic",
        )
        self.result.functions.append(fact)
        return fact

    def add_class(self, name: str, line: int, end_line: int, *, qualified_name: str | None = None) -> ClassFact:
        fact = ClassFact(
            id=stable_id("class", self.path, line, qualified_name or name),
            name=name,
            anchor=self.anchor(line, end_line, name),
            qualified_name=qualified_name or name,
            analysis_method="heuristic",
        )
        self.result.classes.append(fact)
        return fact

    def function_for_line(self, line: int) -> FunctionFact | None:
        matching = [item for item in self.result.functions if item.anchor.start_line <= line <= item.anchor.end_line]
        return min(matching, key=lambda item: item.anchor.end_line - item.anchor.start_line, default=None)

    def add_route(
        self,
        method: str,
        path: str,
        line: int,
        framework: str,
        *,
        handler: FunctionFact | None = None,
    ) -> RouteFact:
        fact = RouteFact(
            id=stable_id("route", self.path, line, f"{method}:{path}"),
            method=method,
            path=path,
            framework=framework,
            anchor=self.anchor(line, line, f"{method} {path}"),
            handler_function_id=handler.id if handler else None,
            analysis_method="heuristic",
        )
        self.result.routes.append(fact)
        return fact

    def add_source(
        self,
        kind: str,
        expression: str,
        line: int,
        variables: list[str],
        *,
        confidence: str = "high",
        function: FunctionFact | None = None,
    ) -> SourceFact:
        function = function or self.function_for_line(line)
        fact = SourceFact(
            id=stable_id("source", self.path, line, f"{kind}:{expression}"),
            kind=kind,
            expression=expression,
            anchor=self.anchor(line, line, variables[0] if variables else kind),
            confidence=confidence,  # type: ignore[arg-type]
            variables=dedupe_strings(variables),
            input_variables=dedupe_strings(variables),
            enclosing_function_id=function.id if function else None,
            analysis_method="heuristic",
        )
        self.result.sources.append(fact)
        return fact

    def add_sink(
        self,
        kind: str,
        expression: str,
        line: int,
        variables: list[str],
        *,
        confidence: str = "high",
        function: FunctionFact | None = None,
    ) -> SinkFact:
        function = function or self.function_for_line(line)
        taxonomy_id, cwe_ids = SINK_TAXONOMY[kind]
        vuln_class = {
            "raw_sql": "injection",
            "command_execution": "injection",
            "file_path": "injection",
            "deserialization": "injection",
            "code_evaluation": "injection",
            "html_output": "xss",
            "external_request": "ssrf",
            "template_compilation": "injection",
            "prototype_mutation": "injection",
            "auth_primitive": "auth",
            "authorization_decision": "authz",
        }[kind]
        fact = SinkFact(
            id=stable_id("sink", self.path, line, f"{kind}:{expression}"),
            kind=kind,
            vuln_class=vuln_class,  # type: ignore[arg-type]
            expression=expression,
            anchor=self.anchor(line, line, kind),
            confidence=confidence,  # type: ignore[arg-type]
            variables=dedupe_strings(variables),
            enclosing_function_id=function.id if function else None,
            analysis_method="heuristic",
            taxonomy_id=taxonomy_id,
            cwe_ids=list(cwe_ids),
        )
        self.result.sinks.append(fact)
        return fact

    def add_sanitizer(
        self,
        kind: str,
        expression: str,
        line: int,
        output_variables: list[str],
        input_variables: list[str],
        applies_to: list[str],
        *,
        confidence: str = "medium",
        function: FunctionFact | None = None,
        end_line: int | None = None,
        symbol: str | None = None,
    ) -> SanitizerFact:
        function = function or self.function_for_line(line)
        fact = SanitizerFact(
            id=stable_id("sanitizer", self.path, line, f"{kind}:{expression}"),
            kind=kind,
            expression=expression,
            anchor=self.anchor(line, end_line or line, symbol or kind),
            confidence=confidence,  # type: ignore[arg-type]
            variables=dedupe_strings(output_variables),
            input_variables=dedupe_strings(input_variables),
            enclosing_function_id=function.id if function else None,
            analysis_method="heuristic",
            applies_to_sink_kinds=applies_to,
        )
        self.result.sanitizers.append(fact)
        return fact

    def add_assignment(
        self,
        target: str,
        sources: list[str],
        expression: str,
        line: int,
        *,
        function: FunctionFact | None = None,
    ) -> DataFlowFact:
        function = function or self.function_for_line(line)
        fact = DataFlowFact(
            id=stable_id("dfg", self.path, line, f"assignment:{target}:{expression}"),
            kind="assignment",
            target=target,
            sources=dedupe_strings(sources),
            expression=expression,
            anchor=self.anchor(line, line, target),
            enclosing_function_id=function.id if function else None,
            analysis_method="heuristic",
        )
        self.result.data_flows.append(fact)
        return fact

    def add_return(self, expression: str, sources: list[str], line: int, *, function: FunctionFact | None = None) -> DataFlowFact:
        function = function or self.function_for_line(line)
        fact = DataFlowFact(
            id=stable_id("dfg", self.path, line, f"return:{expression}"),
            kind="return",
            target=None,
            sources=dedupe_strings(sources),
            expression=expression,
            anchor=self.anchor(line, line, "return"),
            enclosing_function_id=function.id if function else None,
            analysis_method="heuristic",
        )
        self.result.data_flows.append(fact)
        return fact

    def add_call(
        self,
        callee: str,
        line: int,
        arguments: list[list[str]],
        *,
        keywords: dict[str, list[str]] | None = None,
        function: FunctionFact | None = None,
    ) -> CallSiteFact:
        function = function or self.function_for_line(line)
        keyword_sources = keywords or {}
        fact = CallSiteFact(
            id=stable_id("callsite", self.path, line, f"{callee}:{len(self.result.call_sites)}"),
            callee=callee,
            anchor=self.anchor(line, line, callee),
            enclosing_function_id=function.id if function else None,
            argument_sources=[dedupe_strings(item) for item in arguments],
            keyword_sources={key: dedupe_strings(value) for key, value in keyword_sources.items()},
            analysis_method="heuristic",
        )
        self.result.call_sites.append(fact)
        self.result.data_flows.append(
            DataFlowFact(
                id=stable_id("dfg", self.path, line, f"call:{callee}:{len(self.result.data_flows)}"),
                kind="call_argument",
                target=callee,
                sources=dedupe_strings([name for item in arguments for name in item]),
                expression=callee,
                anchor=fact.anchor,
                enclosing_function_id=fact.enclosing_function_id,
                argument_sources=fact.argument_sources,
                keyword_sources=fact.keyword_sources,
                analysis_method="heuristic",
            )
        )
        return fact

    def add_control(
        self, kind: str, condition: str, line: int, variables: list[str], *, function: FunctionFact | None = None
    ) -> ControlFlowFact:
        function = function or self.function_for_line(line)
        fact = ControlFlowFact(
            id=stable_id("cfg", self.path, line, f"{kind}:{condition}"),
            kind=kind,  # type: ignore[arg-type]
            condition=condition,
            variables=dedupe_strings(variables),
            anchor=self.anchor(line, line, kind),
            enclosing_function_id=function.id if function else None,
            analysis_method="heuristic",
        )
        self.result.control_flows.append(fact)
        return fact


IDENTIFIER = re.compile(r"\b[A-Za-z_$][\w$]*\b")
ACCESS_PATH = re.compile(r"\b[A-Za-z_$][\w$]*(?:\s*(?:\?\.)?\s*[A-Za-z_$][\w$]*|\s*\[\s*['\"][^'\"]+['\"]\s*\])*")
NON_VARIABLES = {
    "async",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "default",
    "else",
    "false",
    "for",
    "function",
    "if",
    "in",
    "interface",
    "let",
    "new",
    "nil",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "static",
    "struct",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "undefined",
    "var",
    "while",
}


def extract_variables(expression: str) -> list[str]:
    """Return compact variable/access-path references, excluding literals/keywords."""

    stripped = strip_literals_and_comments(expression)
    values: list[str] = []
    for match in ACCESS_PATH.finditer(stripped):
        value = re.sub(r"\s+", "", match.group(0)).replace("?.", ".")
        root = value.split(".", 1)[0].split("[", 1)[0]
        if root.lower() in NON_VARIABLES or value.isdigit():
            continue
        values.append(value)
    return dedupe_strings(values)


def split_arguments(raw: str) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    quote: str | None = None
    depth = 0
    escaped = False
    for char in raw:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
            continue
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            result.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        result.append("".join(current).strip())
    return result


def find_brace_block_end(lines: list[str], start_line: int) -> int:
    depth = 0
    seen = False
    for index in range(start_line - 1, len(lines)):
        text = strip_literals_and_comments(lines[index])
        for char in text:
            if char == "{":
                depth += 1
                seen = True
            elif char == "}":
                depth -= 1
        if seen and depth <= 0:
            return index + 1
    return min(len(lines), start_line + 120)


def strip_literals_and_comments(text: str) -> str:
    text = re.sub(r"//.*$", "", text)
    text = re.sub(r"#.*$", "", text)
    return re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", "''", text)


def parse_parameters(raw: str) -> list[str]:
    parameters: list[str] = []
    for value in split_arguments(raw):
        value = re.sub(r"=.*$", "", value).strip()
        value = value.replace("...", "").strip()
        if not value:
            continue
        # Java/Go/PHP type declarations can precede the parameter name, while
        # TypeScript annotations follow it. Keep the most likely final identifier.
        identifiers = [item for item in IDENTIFIER.findall(value) if item.lower() not in NON_VARIABLES]
        if identifiers:
            parameters.append(identifiers[-1] if " " in value and ":" not in value else identifiers[0])
    return dedupe_strings(parameters)


def dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
