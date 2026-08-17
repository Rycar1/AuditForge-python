from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Confidence = Literal["low", "medium", "high"]
VulnClass = Literal["injection", "xss", "ssrf", "auth", "authz"]
AnalysisMethod = Literal["ast", "heuristic", "fallback"]
CandidateOrigin = Literal["deterministic", "llm"]
DependencySeverity = Literal["critical", "high", "medium", "low", "unknown"]
NodeKind = Literal[
    "File",
    "Symbol",
    "Function",
    "Class",
    "Route",
    "Source",
    "Sink",
    "Sanitizer",
    "CallSite",
    "DataFlow",
    "ControlFlow",
    "Variable",
]
EdgeKind = Literal["DEFINES", "IMPORTS", "CALLS", "READS", "WRITES", "FLOWS_TO_CANDIDATE", "GUARDED_BY"]
TraceStepKind = Literal["assignment", "call", "return", "branch", "framework_binding", "llm_inferred"]
VerificationStatus = Literal[
    "confirmed",
    "sandbox_confirmed",
    "sandbox_executed",
    "blocked",
    "false_positive",
    "not_reproducible",
    "needs_manual_review",
]
DataFlowKind = Literal["assignment", "return", "call_argument"]
ControlFlowKind = Literal["if", "elif", "else", "for", "while", "switch", "case", "catch"]


@dataclass(frozen=True)
class CodeAnchor:
    file: str
    start_line: int
    end_line: int
    snippet_hash: str
    symbol: str | None = None
    start_col: int | None = None
    end_col: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CodeNode:
    id: str
    kind: NodeKind
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)
    anchor: CodeAnchor | None = None
    language: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CodeEdge:
    from_id: str
    to_id: str
    kind: EdgeKind
    confidence: Confidence
    evidence: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["from"] = data.pop("from_id")
        data["to"] = data.pop("to_id")
        return data


@dataclass(frozen=True)
class FunctionFact:
    id: str
    name: str
    anchor: CodeAnchor
    params: list[str]
    qualified_name: str | None = None
    parent_function_id: str | None = None
    class_id: str | None = None
    analysis_method: AnalysisMethod = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ClassFact:
    id: str
    name: str
    anchor: CodeAnchor
    qualified_name: str | None = None
    analysis_method: AnalysisMethod = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RouteFact:
    id: str
    method: str
    path: str
    framework: str
    anchor: CodeAnchor
    handler_function_id: str | None = None
    analysis_method: AnalysisMethod = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CallSiteFact:
    id: str
    callee: str
    anchor: CodeAnchor
    enclosing_function_id: str | None = None
    argument_sources: list[list[str]] = field(default_factory=list)
    keyword_sources: dict[str, list[str]] = field(default_factory=dict)
    analysis_method: AnalysisMethod = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ImportFact:
    id: str
    module: str
    aliases: dict[str, str]
    anchor: CodeAnchor
    analysis_method: AnalysisMethod = "heuristic"
    kind: str = "module"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DataFlowFact:
    id: str
    kind: DataFlowKind
    target: str | None
    sources: list[str]
    expression: str
    anchor: CodeAnchor
    enclosing_function_id: str | None = None
    argument_sources: list[list[str]] = field(default_factory=list)
    keyword_sources: dict[str, list[str]] = field(default_factory=dict)
    ssa_safe_overwrite: bool = False
    analysis_method: AnalysisMethod = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ControlFlowFact:
    id: str
    kind: ControlFlowKind
    condition: str
    variables: list[str]
    anchor: CodeAnchor
    enclosing_function_id: str | None = None
    analysis_method: AnalysisMethod = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceFact:
    id: str
    kind: str
    expression: str
    anchor: CodeAnchor
    confidence: Confidence
    variables: list[str] = field(default_factory=list)
    input_variables: list[str] = field(default_factory=list)
    enclosing_function_id: str | None = None
    analysis_method: AnalysisMethod = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SinkFact:
    id: str
    kind: str
    vuln_class: VulnClass
    expression: str
    anchor: CodeAnchor
    confidence: Confidence
    variables: list[str] = field(default_factory=list)
    enclosing_function_id: str | None = None
    analysis_method: AnalysisMethod = "heuristic"
    taxonomy_id: str | None = None
    cwe_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SanitizerFact:
    id: str
    kind: str
    expression: str
    anchor: CodeAnchor
    confidence: Confidence
    variables: list[str] = field(default_factory=list)
    input_variables: list[str] = field(default_factory=list)
    enclosing_function_id: str | None = None
    analysis_method: AnalysisMethod = "heuristic"
    applies_to_sink_kinds: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IndexedFile:
    id: str
    path: str
    language: str
    bytes: int
    lines: int
    parsed_by: AnalysisMethod
    skipped_reason: str | None = None
    analysis_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CodeFacts:
    files: list[IndexedFile] = field(default_factory=list)
    functions: list[FunctionFact] = field(default_factory=list)
    classes: list[ClassFact] = field(default_factory=list)
    routes: list[RouteFact] = field(default_factory=list)
    call_sites: list[CallSiteFact] = field(default_factory=list)
    imports: list[ImportFact] = field(default_factory=list)
    data_flows: list[DataFlowFact] = field(default_factory=list)
    control_flows: list[ControlFlowFact] = field(default_factory=list)
    sources: list[SourceFact] = field(default_factory=list)
    sinks: list[SinkFact] = field(default_factory=list)
    sanitizers: list[SanitizerFact] = field(default_factory=list)
    analysis_diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": [x.to_dict() for x in self.files],
            "functions": [x.to_dict() for x in self.functions],
            "classes": [x.to_dict() for x in self.classes],
            "routes": [x.to_dict() for x in self.routes],
            "call_sites": [x.to_dict() for x in self.call_sites],
            "imports": [x.to_dict() for x in self.imports],
            "data_flows": [x.to_dict() for x in self.data_flows],
            "control_flows": [x.to_dict() for x in self.control_flows],
            "sources": [x.to_dict() for x in self.sources],
            "sinks": [x.to_dict() for x in self.sinks],
            "sanitizers": [x.to_dict() for x in self.sanitizers],
            "analysis_diagnostics": self.analysis_diagnostics,
        }


@dataclass
class CodeGraph:
    nodes: list[CodeNode] = field(default_factory=list)
    edges: list[CodeEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": [x.to_dict() for x in self.nodes], "edges": [x.to_dict() for x in self.edges]}


@dataclass(frozen=True)
class TraceStep:
    kind: TraceStepKind
    explanation: str
    confidence: Confidence
    from_anchor: CodeAnchor | None = None
    to_anchor: CodeAnchor | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["from"] = data.pop("from_anchor")
        data["to"] = data.pop("to_anchor")
        return data


@dataclass(frozen=True)
class TraceCandidate:
    id: str
    vuln_class: VulnClass
    source: CodeAnchor
    sink: CodeAnchor
    steps: list[TraceStep]
    sanitizers: list[CodeAnchor]
    blockers: list[str]
    confidence: Confidence
    static_evidence: str
    verification_hint: str
    route_id: str | None = None
    origin: CandidateOrigin = "deterministic"
    reviewer_notes: list[str] = field(default_factory=list)
    taxonomy_id: str | None = None
    cwe_ids: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        from .fingerprints import finding_fingerprint

        return finding_fingerprint(self)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data


@dataclass(frozen=True)
class VerificationPlan:
    candidate_id: str
    status: Literal["planned"]
    mode: Literal["safe_http", "manual"]
    goal: str
    preconditions: list[str]
    steps: list[str]
    success_criteria: list[str]
    safety_gates: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerificationResult:
    candidate_id: str
    status: VerificationStatus
    evidence: list[str]
    request_log: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DependencyPackage:
    name: str
    ecosystem: str
    package_manager: str
    manifest_file: str
    line: int | None = None
    version: str | None = None
    specifier: str | None = None
    scope: str | None = None
    group_id: str | None = None
    direct: bool | None = True
    resolved: bool = False
    purl: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DependencyManifest:
    file: str
    ecosystem: str
    package_manager: str
    dependencies: list[DependencyPackage]
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "ecosystem": self.ecosystem,
            "package_manager": self.package_manager,
            "dependencies": [item.to_dict() for item in self.dependencies],
            "skipped_reason": self.skipped_reason,
        }


@dataclass(frozen=True)
class DependencyFinding:
    id: str
    package: str
    ecosystem: str
    manifest_file: str
    severity: DependencySeverity
    confidence: Confidence
    title: str
    evidence: str
    recommendation: str
    installed_version: str | None = None
    affected_range: str | None = None
    line: int | None = None
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    advisory_ids: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    source: str = "llm"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    repo_path: str
    target_url: str | None
    facts: CodeFacts
    graph: CodeGraph
    candidates: list[TraceCandidate]
    plans: list[VerificationPlan]
    verification_results: list[VerificationResult]
    llm_diagnostics: dict[str, Any] = field(default_factory=dict)
    dependency_inventory: list[DependencyManifest] = field(default_factory=list)
    dependency_findings: list[DependencyFinding] = field(default_factory=list)
    dependency_diagnostics: dict[str, Any] = field(default_factory=dict)
    project_inventory: dict[str, Any] = field(default_factory=dict)
    analysis_coverage: dict[str, Any] = field(default_factory=dict)

    def stats(self) -> dict[str, int]:
        llm_candidates = sum(1 for candidate in self.candidates if candidate.origin == "llm")
        sandbox_confirmed = sum(1 for verification in self.verification_results if verification.status == "sandbox_confirmed")
        sandbox_executed = sum(1 for verification in self.verification_results if verification.status == "sandbox_executed")
        dependencies = sum(len(manifest.dependencies) for manifest in self.dependency_inventory)
        dependency_critical = sum(1 for finding in self.dependency_findings if finding.severity == "critical")
        dependency_high = sum(1 for finding in self.dependency_findings if finding.severity == "high")
        inventory = self.project_inventory or {}
        analysis = self.facts.analysis_diagnostics or {}
        coverage = self.analysis_coverage or {}
        coverage_summary = coverage.get("summary") if isinstance(coverage.get("summary"), dict) else {}
        rescan = coverage.get("auto_rescan") if isinstance(coverage.get("auto_rescan"), dict) else {}
        return {
            "code_lines": int(inventory.get("total_lines") or 0),
            "languages": int(inventory.get("language_count") or 0),
            "inventory_files": int(inventory.get("file_count") or 0),
            "files": len(self.facts.files),
            "functions": len(self.facts.functions),
            "classes": len(self.facts.classes),
            "routes": len(self.facts.routes),
            "call_sites": len(self.facts.call_sites),
            "data_flows": len(self.facts.data_flows),
            "control_flows": len(self.facts.control_flows),
            "sources": len(self.facts.sources),
            "sinks": len(self.facts.sinks),
            "sanitizers": len(self.facts.sanitizers),
            "analysis_analyzed_files": int(analysis.get("analyzed_files") or 0),
            "analysis_ast_files": int(analysis.get("ast_files") or 0),
            "analysis_heuristic_files": int(analysis.get("heuristic_files") or 0),
            "analysis_language_frontend_files": int(analysis.get("language_frontend_files") or 0),
            "analysis_skipped_files": int(analysis.get("skipped_files") or 0),
            "analysis_error_files": int(analysis.get("error_files") or 0),
            "analysis_truncated_files": int(analysis.get("truncated_files") or 0),
            "analysis_truncated": int(bool(analysis.get("truncated"))),
            "analysis_confidence_score": round(float(coverage.get("score") or 0)),
            "analysis_blindspots": int(coverage_summary.get("blindspots") or 0),
            "analysis_high_priority_blindspots": int(coverage_summary.get("high_priority_blindspots") or 0),
            "analysis_unresolved_calls": int(coverage_summary.get("unresolved_calls") or 0),
            "analysis_rescan_tasks": int(rescan.get("executed") or 0),
            "candidates": len(self.candidates),
            "llm_candidates": llm_candidates,
            "verification_results": len(self.verification_results),
            "sandbox_confirmed": sandbox_confirmed,
            "sandbox_executed": sandbox_executed,
            "dependency_manifests": len(self.dependency_inventory),
            "dependencies": dependencies,
            "dependency_findings": len(self.dependency_findings),
            "dependency_critical": dependency_critical,
            "dependency_high": dependency_high,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_path": self.repo_path,
            "target_url": self.target_url,
            "stats": self.stats(),
            "facts": self.facts.to_dict(),
            "graph": self.graph.to_dict(),
            "candidates": [x.to_dict() for x in self.candidates],
            "plans": [x.to_dict() for x in self.plans],
            "verification_results": [x.to_dict() for x in self.verification_results],
            "llm_diagnostics": self.llm_diagnostics,
            "dependency_inventory": [x.to_dict() for x in self.dependency_inventory],
            "dependency_findings": [x.to_dict() for x in self.dependency_findings],
            "dependency_diagnostics": self.dependency_diagnostics,
            "project_inventory": self.project_inventory,
            "analysis_coverage": self.analysis_coverage,
        }
