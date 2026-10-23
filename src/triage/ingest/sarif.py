"""Generic SARIF 2.1.0 reader.

SARIF is a wide format and every scanner fills a different subset of it. This reader takes
only what all three target scanners agree on (ruleId, level, physical location, rule metadata)
and confines scanner-specific knowledge to the small `_classify_*` and `_package_*` helpers.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from triage.ingest.errors import IngestError
from triage.model import Confidence, Kind, Location, Package, RawFinding, Severity
from triage.source import normalize_path

_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
_TAG_SEVERITY = {s.value.upper(): s for s in Severity} | {"UNKNOWN": Severity.MEDIUM}
_CWE = re.compile(r"\bCWE-(\d+)\b")

# Semgrep groups rules by language prefix; these prefixes are configuration, not code.
_SEMGREP_CONFIG_PREFIXES = ("yaml.", "dockerfile.", "terraform.", "hcl.", "json.", "kubernetes.")


def severity_from_score(score: float) -> Severity:
    """CVSS v3 qualitative bands, which is what `security-severity` carries."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _scanner_name(run: dict[str, Any]) -> str:
    name = str(run.get("tool", {}).get("driver", {}).get("name", "unknown")).lower()
    for known in ("semgrep", "trivy", "gitleaks"):
        if known in name:
            return known
    return re.sub(r"[^a-z0-9_-]+", "-", name).strip("-") or "unknown"


def _tags(rule: dict[str, Any], result: dict[str, Any]) -> list[str]:
    tags = list(rule.get("properties", {}).get("tags", []))
    tags += list(result.get("properties", {}).get("tags", []))
    return [str(t) for t in tags]


def _classify(scanner: str, rule_id: str, tags: list[str]) -> Kind:
    lowered = {t.lower() for t in tags}
    if scanner == "gitleaks" or "secret" in lowered:
        return Kind.SECRET
    if scanner == "trivy":
        if "vulnerability" in lowered:
            return Kind.DEPENDENCY
        if "misconfiguration" in lowered:
            return Kind.CONFIG
    if scanner == "semgrep":
        if ".secrets." in rule_id or rule_id.startswith("generic.secrets"):
            return Kind.SECRET
        if rule_id.startswith(_SEMGREP_CONFIG_PREFIXES):
            return Kind.CONFIG
    if any("CWE-798" in t for t in tags):
        return Kind.SECRET
    return Kind.CODE


def _severity(
    scanner: str, rule: dict[str, Any], result: dict[str, Any], tags: list[str]
) -> Severity:
    if scanner == "gitleaks":
        # No severity model of its own; matches the native JSON adapter.
        return Severity.HIGH
    for props in (result.get("properties", {}), rule.get("properties", {})):
        score = props.get("security-severity")
        if score is not None:
            try:
                return severity_from_score(float(score))
            except (TypeError, ValueError):
                pass
    for tag in tags:
        if tag.upper() in _TAG_SEVERITY:
            return _TAG_SEVERITY[tag.upper()]
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
    return _LEVEL.get(str(level), Severity.MEDIUM)


_TRIVY_MESSAGE = re.compile(r"^Message:\s*(.+)$", re.MULTILINE)
_TRIVY_FIELD = re.compile(r"^(Package|Installed Version|Fixed Version):[ \t]*(.*)$", re.MULTILINE)


def _trivy_package(message: str, path: str) -> Package | None:
    """Trivy's SARIF puts package coordinates only in the message text."""
    fields = {m.group(1): m.group(2).strip() for m in _TRIVY_FIELD.finditer(message)}
    if "Package" not in fields or "Installed Version" not in fields:
        return None
    return Package(
        name=fields["Package"],
        version=fields["Installed Version"],
        fixed_version=fields.get("Fixed Version") or None,
        ecosystem=_ecosystem_for(path),
    )


_ECOSYSTEMS = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "pypi",
    "poetry.lock": "pypi",
    "uv.lock": "pypi",
    "Pipfile.lock": "pypi",
    "go.mod": "go",
    "go.sum": "go",
    "Gemfile.lock": "rubygems",
    "pom.xml": "maven",
    "Cargo.lock": "cargo",
    "composer.lock": "packagist",
}


def _ecosystem_for(path: str) -> str | None:
    return _ECOSYSTEMS.get(Path(path).name)


def _rule_confidence(tags: list[str]) -> Confidence | None:
    for tag in tags:
        level, _, word = tag.upper().partition(" ")
        if word == "CONFIDENCE" and level.lower() in Confidence.__members__.values():
            return Confidence(level.lower())
    return None


def _first_text(*candidates: Any) -> str:
    for c in candidates:
        if isinstance(c, dict):
            c = c.get("text")
        if isinstance(c, str) and c.strip():
            return c.strip()
    return ""


def parse_sarif(data: dict[str, Any], root: Path) -> Iterator[RawFinding]:
    if not isinstance(data, dict) or "runs" not in data:
        raise IngestError("not a SARIF log: missing 'runs'")
    for run in data["runs"]:
        scanner = _scanner_name(run)
        rules_list = run.get("tool", {}).get("driver", {}).get("rules", []) or []
        rules = {r.get("id"): r for r in rules_list if isinstance(r, dict)}
        for result in run.get("results", []) or []:
            rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "unknown")
            rule = rules.get(rule_id, {})
            locations = result.get("locations") or []
            if not locations:
                continue
            phys = locations[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri")
            if not uri:
                continue
            path = normalize_path(str(uri), root)
            if path is None:
                continue  # points outside the scanned root; never follow it
            region = phys.get("region", {})
            tags = _tags(rule, result)
            kind = _classify(scanner, rule_id, tags)
            message = _first_text(result.get("message"), rule.get("shortDescription"))
            package = _trivy_package(message, path) if kind is Kind.DEPENDENCY else None
            if scanner == "trivy" and (m := _TRIVY_MESSAGE.search(message)):
                message = m.group(1).strip()
            title = _first_text(rule.get("shortDescription"), rule.get("name"), message)
            yield RawFinding(
                scanner=scanner,
                rule_id=rule_id,
                kind=kind,
                severity=_severity(scanner, rule, result, tags),
                message=title if kind is Kind.SECRET else message,
                location=Location(
                    path=path,
                    start_line=region.get("startLine"),
                    end_line=region.get("endLine") or region.get("startLine"),
                    start_column=region.get("startColumn"),
                    end_column=region.get("endColumn"),
                ),
                cwe=tuple(sorted({f"CWE-{m}" for t in tags for m in _CWE.findall(t)})),
                package=package,
                rule_confidence=_rule_confidence(tags),
                scanner_snippet=_first_text(region.get("snippet")) or None,
                help_uri=rule.get("helpUri"),
            )


def load_sarif(path: Path, root: Path) -> list[RawFinding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IngestError(f"{path}: {exc}") from exc
    return list(parse_sarif(data, root))
