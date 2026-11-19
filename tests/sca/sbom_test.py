from __future__ import annotations

from auditforge.core.models import DependencyFinding, DependencyManifest, DependencyPackage
from auditforge.sca.sbom import build_cyclonedx_sbom


def test_cyclonedx_sbom_links_findings_to_exact_component() -> None:
    dependency = DependencyPackage(
        name="demo",
        ecosystem="pypi",
        package_manager="pip",
        manifest_file="requirements.txt",
        version="1.0.0",
        resolved=True,
        purl="pkg:pypi/demo@1.0.0",
    )
    finding = DependencyFinding(
        id="DEP-OSV",
        package="demo",
        ecosystem="pypi",
        manifest_file="requirements.txt",
        installed_version="1.0.0",
        severity="high",
        confidence="high",
        title="demo advisory",
        evidence="OSV matched demo",
        recommendation="upgrade",
        advisory_ids=["GHSA-aaaa-bbbb-cccc"],
        source="osv",
    )

    sbom = build_cyclonedx_sbom(
        "C:/repo/example",
        [DependencyManifest("requirements.txt", "pypi", "pip", [dependency])],
        [finding],
        generated_at="2026-07-15T00:00:00+00:00",
    )

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["components"][0]["purl"] == "pkg:pypi/demo@1.0.0"
    assert sbom["vulnerabilities"][0]["id"] == "GHSA-aaaa-bbbb-cccc"
    assert sbom["vulnerabilities"][0]["affects"] == [{"ref": sbom["components"][0]["bom-ref"]}]
