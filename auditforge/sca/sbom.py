from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import DependencyFinding, DependencyManifest, DependencyPackage


def build_cyclonedx_sbom(
    repo_path: str,
    manifests: list[DependencyManifest],
    findings: list[DependencyFinding],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic CycloneDX 1.5 inventory with advisory links."""

    generated_at = generated_at or datetime.now(UTC).isoformat()
    components: list[dict[str, Any]] = []
    references: dict[tuple[str, str, str, str], str] = {}
    seen: set[tuple[str, str, str, str]] = set()
    for manifest in manifests:
        for dependency in manifest.dependencies:
            key = component_key(dependency)
            if key in seen:
                continue
            seen.add(key)
            bom_ref = component_reference(dependency)
            references[key] = bom_ref
            component: dict[str, Any] = {
                "type": "library",
                "bom-ref": bom_ref,
                "name": dependency.name,
                "properties": [
                    {"name": "auditforge:manifest", "value": dependency.manifest_file},
                    {"name": "auditforge:package-manager", "value": dependency.package_manager},
                    {"name": "auditforge:resolved", "value": str(bool(dependency.resolved)).lower()},
                ],
            }
            if dependency.version:
                component["version"] = dependency.version
            if dependency.purl:
                component["purl"] = dependency.purl
            if dependency.scope:
                component["scope"] = "excluded" if dependency.scope.lower() in {"dev", "test", "development"} else "required"
                component["properties"].append({"name": "auditforge:scope", "value": dependency.scope})
            if dependency.direct is not None:
                component["properties"].append({"name": "auditforge:direct", "value": str(dependency.direct).lower()})
            components.append(component)

    vulnerabilities: list[dict[str, Any]] = []
    for finding in findings:
        affected_refs = matching_component_references(finding, manifests, references)
        advisory_ids = finding.advisory_ids or finding.cve_ids or [finding.id]
        primary_id = advisory_ids[0]
        vulnerability: dict[str, Any] = {
            "id": primary_id,
            "source": {"name": "OSV" if finding.source == "osv" else "AuditForge"},
            "ratings": [{"severity": finding.severity if finding.severity != "unknown" else "unknown"}],
            "description": finding.evidence,
            "recommendation": finding.recommendation,
            "properties": [
                {"name": "auditforge:confidence", "value": finding.confidence},
                {"name": "auditforge:manifest", "value": finding.manifest_file},
            ],
        }
        if affected_refs:
            vulnerability["affects"] = [{"ref": item} for item in affected_refs]
        if finding.references:
            vulnerability["advisories"] = [{"url": item} for item in finding.references]
        if len(advisory_ids) > 1:
            vulnerability["properties"].append({"name": "auditforge:advisory-aliases", "value": ",".join(advisory_ids[1:])})
        vulnerabilities.append(vulnerability)

    project_name = Path(repo_path).name or "auditforge-scan-target"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "tools": {"components": [{"type": "application", "name": "AuditForge", "version": "0.2.0"}]},
            "component": {"type": "application", "name": project_name},
        },
        "components": sorted(components, key=lambda item: (item["name"].casefold(), item.get("version", ""), item["bom-ref"])),
        "vulnerabilities": vulnerabilities,
    }


def component_key(dependency: DependencyPackage) -> tuple[str, str, str, str]:
    return (
        dependency.ecosystem.casefold(),
        dependency.name.casefold(),
        str(dependency.version or dependency.specifier or ""),
        dependency.manifest_file.replace("\\", "/"),
    )


def component_reference(dependency: DependencyPackage) -> str:
    material = "\0".join(component_key(dependency))
    return "urn:auditforge:component:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def matching_component_references(
    finding: DependencyFinding,
    manifests: list[DependencyManifest],
    references: dict[tuple[str, str, str, str], str],
) -> list[str]:
    matches: list[str] = []
    for manifest in manifests:
        for dependency in manifest.dependencies:
            if dependency.ecosystem.casefold() != finding.ecosystem.casefold():
                continue
            if dependency.name.casefold() != finding.package.casefold():
                continue
            if dependency.manifest_file.replace("\\", "/") != finding.manifest_file.replace("\\", "/"):
                continue
            if finding.installed_version and dependency.version and finding.installed_version != dependency.version:
                continue
            reference = references.get(component_key(dependency))
            if reference and reference not in matches:
                matches.append(reference)
    return matches
