from __future__ import annotations

from pathlib import Path
from typing import Any

from triage.ingest.gitleaks_json import parse_gitleaks_json
from triage.ingest.sarif import parse_sarif
from triage.model import Kind, Severity


def trivy_sarif(message: str, tags: list[str], uri: str = "package-lock.json") -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "rules": [
                            {
                                "id": "CVE-2025-0001",
                                "shortDescription": {"text": "elliptic: signature malleability"},
                                "properties": {"security-severity": "7.5", "tags": tags},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "CVE-2025-0001",
                        "level": "error",
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri, "uriBaseId": "ROOTPATH"},
                                    "region": {"startLine": 10, "endLine": 20},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_trivy_dependency_fields(tmp_path: Path) -> None:
    msg = (
        "Package: elliptic\nInstalled Version: 6.6.1\nVulnerability CVE-2025-0001\n"
        "Severity: HIGH\nFixed Version: 6.6.2\nLink: [CVE-2025-0001](https://example.test)"
    )
    [f] = parse_sarif(trivy_sarif(msg, ["vulnerability", "security", "HIGH"]), tmp_path)
    assert f.kind is Kind.DEPENDENCY
    assert f.severity is Severity.HIGH  # from security-severity 7.5
    assert f.package is not None
    assert (f.package.name, f.package.version, f.package.fixed_version) == (
        "elliptic",
        "6.6.1",
        "6.6.2",
    )
    assert f.package.ecosystem == "npm"


def test_trivy_empty_fixed_version_does_not_swallow_next_line(tmp_path: Path) -> None:
    """Regression: an empty `Fixed Version:` once captured the following `Link:` line."""
    msg = (
        "Package: elliptic\nInstalled Version: 6.6.1\nVulnerability CVE-2025-0001\n"
        "Severity: HIGH\nFixed Version: \nLink: [CVE-2025-0001](https://example.test)"
    )
    [f] = parse_sarif(trivy_sarif(msg, ["vulnerability", "security", "HIGH"]), tmp_path)
    assert f.package is not None and f.package.fixed_version is None


def test_trivy_misconfig_and_secret_kinds(tmp_path: Path) -> None:
    [cfg] = parse_sarif(trivy_sarif("Message: Use a tag", ["misconfiguration"], "x.tf"), tmp_path)
    assert cfg.kind is Kind.CONFIG and cfg.message == "Use a tag"
    [sec] = parse_sarif(trivy_sarif("token ****", ["secret"], "a.ts"), tmp_path)
    assert sec.kind is Kind.SECRET
    assert "****" not in sec.message  # the rule title is used, not the scanner's message


def test_gitleaks_json_reads_location_only(tmp_path: Path) -> None:
    (tmp_path / "repo").mkdir()
    data = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "repo/src/a.ts",
            "StartLine": 3,
            "EndLine": 3,
            "StartColumn": 5,
            "EndColumn": 30,
            "Secret": "REDACTED",
            "Match": "REDACTED",
            "Fingerprint": "repo/src/a.ts:generic:3",
        },
        {
            "RuleID": "generic-api-key",
            "File": "../../outside.ts",
            "StartLine": 1,
        },
    ]
    found = list(parse_gitleaks_json(data, tmp_path / "repo"))
    assert len(found) == 1  # the path outside the root is dropped
    assert found[0].location.path == "src/a.ts"
    assert found[0].severity is Severity.HIGH
    assert "REDACTED" not in found[0].model_dump_json()
