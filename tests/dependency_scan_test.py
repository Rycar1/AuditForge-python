from __future__ import annotations

import json
from pathlib import Path

import auditforge.dependency_scan as dependency_scan
from auditforge.dependency_scan import (
    analyze_dependencies_with_osv,
    build_dependency_prompt,
    normalize_dependency_findings,
    package_key,
    scan_dependency_manifests,
    split_dependency_manifests,
)
from auditforge.engine import run_scan
from auditforge.llm_candidates import LLMConfig
from auditforge.models import DependencyManifest, DependencyPackage
from auditforge.store import read_dashboard_data


def test_dependency_manifest_parser_extracts_requirements_and_pom() -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "dependency_scan_project"

    manifests = scan_dependency_manifests(repo)
    packages = {
        (dependency.ecosystem, dependency.name, dependency.version) for manifest in manifests for dependency in manifest.dependencies
    }

    assert ("pypi", "Flask", "0.12") in packages
    assert ("pypi", "Django", "1.11.0") in packages
    assert ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1") in packages


def test_maven_parent_properties_and_dependency_management_resolve_versions(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    child = tmp_path / "child"
    parent.mkdir()
    child.mkdir()
    (parent / "pom.xml").write_text(
        """
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>example</groupId><artifactId>parent</artifactId><version>1.2.3</version>
          <properties><shared.version>2.8.1</shared.version><nested.version>${shared.version}</nested.version></properties>
          <dependencyManagement><dependencies>
            <dependency><groupId>com.example</groupId><artifactId>managed</artifactId><version>${nested.version}</version></dependency>
          </dependencies></dependencyManagement>
        </project>
        """,
        encoding="utf-8",
    )
    (child / "pom.xml").write_text(
        """
        <project>
          <modelVersion>4.0.0</modelVersion>
          <parent><groupId>example</groupId><artifactId>parent</artifactId><version>1.2.3</version><relativePath>../parent/pom.xml</relativePath></parent>
          <artifactId>child</artifactId>
          <dependencies>
            <dependency><groupId>com.example</groupId><artifactId>managed</artifactId></dependency>
            <dependency><groupId>com.example</groupId><artifactId>project-version</artifactId><version>${project.version}</version></dependency>
          </dependencies>
        </project>
        """,
        encoding="utf-8",
    )

    manifests = scan_dependency_manifests(tmp_path)
    packages = {
        (dependency.name, dependency.version, dependency.resolved)
        for manifest in manifests
        if manifest.file == "child/pom.xml"
        for dependency in manifest.dependencies
    }

    assert ("com.example:managed", "2.8.1", True) in packages
    assert ("com.example:project-version", "1.2.3", True) in packages


def test_dependency_prompt_accepts_custom_task_instructions() -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "dependency_scan_project"
    manifests = scan_dependency_manifests(repo)

    prompt = build_dependency_prompt(repo, manifests, 24000, "只关注高危及以上依赖组件风险。")

    assert "只关注高危及以上依赖组件风险。" in prompt
    assert "dependency_vulnerability_candidate_generator" in prompt


def test_dependency_prompt_contains_sca_review_rubrics() -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "dependency_scan_project"
    manifests = scan_dependency_manifests(repo)

    payload = json.loads(build_dependency_prompt(repo, manifests, 24000))

    assert payload["role"] == "dependency_vulnerability_candidate_generator"
    assert "inventoryPolicy" in payload
    assert "offlineKnowledgePolicy" in payload
    assert "versionReasoningRules" in payload
    assert "versionComparisonChecklist" in payload
    assert "ecosystemNormalization" in payload
    assert "packageIdentityExamples" in payload
    assert "advisoryEvidencePolicy" in payload
    assert "riskTaxonomy" in payload
    assert "confidenceRubric" in payload
    assert "falsePositiveGuidance" in payload
    assert "scaOutputQualityGate" in payload
    assert "evidenceChecklist" in payload
    assert payload["inventory"]


def test_dependency_scan_splits_dependencies_into_parallel_chunks() -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "dependency_scan_project"
    manifests = scan_dependency_manifests(repo)

    chunks = split_dependency_manifests(manifests, chunk_size=2)

    assert [sum(len(manifest.dependencies) for manifest in chunk) for chunk in chunks] == [2, 2]
    assert {manifest.file for chunk in chunks for manifest in chunk} <= {manifest.file for manifest in manifests}


def test_dependency_llm_scan_writes_findings_report_and_store(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "dependency_scan_project"
    response_file = Path(__file__).resolve().parents[1] / "fixtures" / "dependency_scan_response.json"

    result = run_scan(
        repo,
        tmp_path,
        dependency_scan=True,
        dependency_llm_config=LLMConfig(enabled=True, provider="fixture", response_file=str(response_file), max_candidates=5),
    )

    stats = result.stats()
    assert stats["dependency_manifests"] == 2
    assert stats["dependencies"] == 4
    assert stats["dependency_findings"] == 2
    assert stats["dependency_critical"] == 1
    assert result.dependency_findings[0].cve_ids == ["CVE-2021-44228"]
    assert any(rejected["reason"] == "package not in dependency inventory" for rejected in result.dependency_diagnostics["rejected"])
    assert (tmp_path / "result_sections.json").exists()
    assert (tmp_path / "result_sections" / "dependency_vulnerabilities.json").exists()

    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "## 依赖风险扫描" in report
    assert "CVE-2021-44228" in report

    dashboard = read_dashboard_data(tmp_path)
    artifacts = dashboard["artifacts"]
    assert len(artifacts["dependency_inventory"]) == 2
    assert len(artifacts["dependency_findings"]) == 2
    assert artifacts["result_sections"]["summary"]["dependency_vulnerabilities"] == 2
    assert artifacts["result_sections"]["summary"]["candidate_vulnerabilities"] == 0


def test_dependency_llm_malformed_schema_is_rejected(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "dependency_scan_project"
    response_file = tmp_path / "bad-dependency-response.json"
    response_file.write_text('{"items":[]}', encoding="utf-8")

    result = run_scan(
        repo,
        tmp_path,
        dependency_scan=True,
        dependency_llm_config=LLMConfig(enabled=True, provider="fixture", response_file=str(response_file), max_candidates=5),
    )

    assert result.dependency_findings == []
    assert result.dependency_diagnostics["rejected"][0]["reason"].startswith("schema_error")


def test_lockfiles_provide_resolved_transitive_versions(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "flask"\nversion = "2.0.0"\n\n[[package]]\nname = "werkzeug"\nversion = "2.0.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/express": {"name": "express", "version": "4.17.1"},
                    "node_modules/express/node_modules/debug": {"name": "debug", "version": "2.6.9"},
                },
            }
        ),
        encoding="utf-8",
    )

    manifests = scan_dependency_manifests(tmp_path)
    packages = [item for manifest in manifests for item in manifest.dependencies]

    assert any(item.name == "werkzeug" and item.resolved and item.direct is None for item in packages)
    assert any(item.name == "express" and item.direct is True for item in packages)
    assert any(item.name == "debug" and item.direct is False for item in packages)
    assert all(item.purl for item in packages)


def test_additional_ecosystem_lockfiles_are_parsed(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text(
        'lodash@^4.17.0:\n  version "4.17.20"\n\n"@scope/pkg@^1.0.0":\n  version "1.2.3"\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\npackages:\n  axios@1.6.0:\n    resolution: {}\n",
        encoding="utf-8",
    )
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.197"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
        encoding="utf-8",
    )
    (tmp_path / "Gemfile.lock").write_text(
        "GEM\n  specs:\n    rack (2.2.8)\n\nDEPENDENCIES\n  rack\n\nBUNDLED WITH\n   2.5.0\n",
        encoding="utf-8",
    )
    (tmp_path / "composer.lock").write_text(
        json.dumps({"packages": [{"name": "symfony/http-foundation", "version": "v6.4.1"}], "packages-dev": []}),
        encoding="utf-8",
    )
    (tmp_path / "packages.lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1"}}},
            }
        ),
        encoding="utf-8",
    )

    manifests = scan_dependency_manifests(tmp_path)
    packages = {(item.ecosystem, item.name, item.version): item for manifest in manifests for item in manifest.dependencies}

    assert ("npm", "lodash", "4.17.20") in packages
    assert ("npm", "@scope/pkg", "1.2.3") in packages
    assert ("npm", "axios", "1.6.0") in packages
    assert ("crates.io", "serde", "1.0.197") in packages
    assert packages[("rubygems", "rack", "2.2.8")].direct is True
    assert ("packagist", "symfony/http-foundation", "6.4.1") in packages
    assert packages[("nuget", "Newtonsoft.Json", "13.0.1")].direct is True
    assert all(item.resolved and item.purl for item in packages.values())


def test_requirements_include_files_are_followed(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("-r deps/base.in\n", encoding="utf-8")
    (tmp_path / "deps").mkdir()
    (tmp_path / "deps" / "base.in").write_text("urllib3==1.26.0\n", encoding="utf-8")

    manifests = scan_dependency_manifests(tmp_path)
    packages = [item for manifest in manifests for item in manifest.dependencies]

    dependency = next(item for item in packages if item.name == "urllib3")
    assert dependency.manifest_file == "deps/base.in"
    assert dependency.resolved is True


def test_osv_query_is_deterministic_and_keeps_non_cve_advisory_identity() -> None:
    dependency = DependencyPackage(
        name="demo",
        ecosystem="pypi",
        package_manager="pip",
        manifest_file="requirements.txt",
        version="1.0.0",
        specifier="==1.0.0",
        resolved=True,
    )
    manifests = [DependencyManifest("requirements.txt", "pypi", "pip", [dependency])]

    def transport(_endpoint, payload):
        assert payload["queries"][0]["package"] == {"name": "demo", "ecosystem": "PyPI"}
        return {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-aaaa-bbbb-cccc",
                            "aliases": ["CVE-2026-12345"],
                            "summary": "demo issue",
                            "database_specific": {"severity": "HIGH"},
                            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}],
                            "references": [{"url": "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"}],
                        }
                    ]
                }
            ]
        }

    findings, diagnostics = analyze_dependencies_with_osv(manifests, transport=transport)

    assert diagnostics["complete"] is True
    assert findings[0].source == "osv"
    assert findings[0].advisory_ids == ["GHSA-aaaa-bbbb-cccc", "CVE-2026-12345"]
    assert findings[0].cve_ids == ["CVE-2026-12345"]
    assert findings[0].fixed_versions == ["1.0.1"]


def test_osv_querybatch_ids_are_enriched_with_historical_advisory_details() -> None:
    dependency = DependencyPackage(
        name="demo",
        ecosystem="npm",
        package_manager="npm",
        manifest_file="package-lock.json",
        version="1.0.0",
        resolved=True,
    )
    manifests = [DependencyManifest("package-lock.json", "npm", "npm", [dependency])]

    def transport(_endpoint, _payload):
        return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-01-01T00:00:00Z"}]}]}

    def detail_transport(_endpoint, advisory_id):
        assert advisory_id == "GHSA-aaaa-bbbb-cccc"
        return {
            "id": advisory_id,
            "aliases": ["CVE-2026-54321"],
            "summary": "historical issue",
            "database_specific": {"severity": "critical"},
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}],
        }

    findings, diagnostics = analyze_dependencies_with_osv(
        manifests,
        transport=transport,
        detail_transport=detail_transport,
    )

    assert diagnostics["detail_queries"] == 1
    assert diagnostics["detail_failures"] == 0
    assert findings[0].cve_ids == ["CVE-2026-54321"]
    assert findings[0].severity == "critical"


def test_osv_retries_transient_batches_and_filters_multi_package_details(monkeypatch) -> None:
    dependency = DependencyPackage(
        name="demo",
        ecosystem="npm",
        package_manager="npm",
        manifest_file="package-lock.json",
        version="1.0.0",
        resolved=True,
    )
    manifests = [DependencyManifest("package-lock.json", "npm", "npm", [dependency])]
    attempts = 0

    def transport(_endpoint, _payload):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("temporary OSV timeout")
        return {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-aaaa-bbbb-cccc",
                            "summary": "multi-package advisory",
                            "severity": [
                                {
                                    "type": "CVSS_V3",
                                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            ],
                            "affected": [
                                {
                                    "package": {"ecosystem": "npm", "name": "other-package"},
                                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
                                },
                                {
                                    "package": {"ecosystem": "npm", "name": "demo"},
                                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
                                },
                            ],
                        }
                    ]
                }
            ]
        }

    monkeypatch.setattr(dependency_scan, "OSV_RETRY_DELAYS_SECONDS", (0, 0))
    findings, diagnostics = analyze_dependencies_with_osv(manifests, transport=transport)

    assert attempts == 2
    assert diagnostics["query_retries"] == 1
    assert findings[0].fixed_versions == ["1.0.1"]
    assert findings[0].severity == "critical"


def test_dependency_identity_keeps_same_package_versions_in_separate_manifests() -> None:
    manifests = [
        DependencyManifest(
            "prod/requirements.txt",
            "pypi",
            "pip",
            [DependencyPackage("Django", "pypi", "pip", "prod/requirements.txt", version="1.11", resolved=True)],
        ),
        DependencyManifest(
            "tools/requirements.txt",
            "pypi",
            "pip",
            [DependencyPackage("Django", "pypi", "pip", "tools/requirements.txt", version="5.0", resolved=True)],
        ),
    ]
    diagnostics = {"rejected": []}
    payload = {
        "findings": [
            {
                "package": "Django",
                "ecosystem": "pypi",
                "installedVersion": "5.0",
                "affectedRange": "<5.0.1",
                "cveIds": ["CVE-2026-9999"],
                "severity": "high",
                "confidence": "high",
                "title": "Django advisory",
                "evidence": "exact version match",
                "recommendation": "upgrade",
                "manifestFile": "tools/requirements.txt",
                "references": [],
            }
        ]
    }

    findings = normalize_dependency_findings(payload, manifests, diagnostics, limit=10)

    assert findings[0].manifest_file == "tools/requirements.txt"
    assert findings[0].installed_version == "5.0"
    assert package_key("foo.bar", "npm") != package_key("foo-bar", "npm")
