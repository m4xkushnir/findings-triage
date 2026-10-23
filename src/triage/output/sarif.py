"""SARIF 2.1.0 output, shaped for GitHub code scanning.

- `partialFingerprints` carries the triage fingerprint, so alerts keep their identity across
  pushes even when line numbers move.
- Suppressed findings stay in the file with a SARIF `suppressions` entry (kind "external",
  the justification is the rule's reason) instead of being dropped, so the consumer can show
  them as dismissed and the decision stays visible.
- `security-severity` holds the *effective* severity, which is what code scanning sorts by.
"""

from __future__ import annotations

from typing import Any

from triage.model import Bucket, Report, Severity, TriagedFinding

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}
INFORMATION_URI = "https://github.com/m4xkushnir/findings-triage"


def _rule_id(t: TriagedFinding) -> str:
    source = next(s for s in t.finding.sources if s.rule_id == t.finding.rule_id)
    return f"{source.scanner}/{t.finding.rule_id}"


def _result(t: TriagedFinding, with_baseline: bool) -> dict[str, Any]:
    f = t.finding
    loc = f.location
    region: dict[str, Any] = {}
    if loc.start_line is not None:
        region["startLine"] = loc.start_line
        region["endLine"] = loc.end_line or loc.start_line
    physical: dict[str, Any] = {"artifactLocation": {"uri": loc.path}}
    if region:
        physical["region"] = region

    text = f.title
    if t.enrichment is not None:
        text += f" | {t.enrichment.reasoning}"
    result: dict[str, Any] = {
        "ruleId": _rule_id(t),
        "level": _LEVEL[t.effective_severity],
        "message": {"text": text},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"triageFingerprint/v1": f.fingerprint},
        "properties": {
            "security-severity": _SCORE[t.effective_severity],
            "triage/bucket": t.bucket.value,
            "triage/kind": f.kind.value,
            "triage/reportedSeverity": f.severity.value,
            "triage/sources": [f"{s.scanner}:{s.rule_id}" for s in f.sources],
            "triage/decisions": list(t.decisions),
        },
    }
    if f.package is not None:
        result["properties"]["triage/package"] = f.package.model_dump(mode="json")
    if t.enrichment is not None:
        result["properties"]["triage/enrichment"] = t.enrichment.model_dump(
            mode="json", exclude={"cached"}
        )
    if with_baseline:
        result["baselineState"] = "new" if t.is_new else "unchanged"
    if t.bucket is Bucket.SUPPRESSED and t.suppression is not None:
        s = t.suppression
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": f"{s.rule_id}: {s.reason} ({s.author})",
            }
        ]
    return result


def render_sarif(report: Report) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    for t in report.findings:
        rid = _rule_id(t)
        if rid not in rules:
            rule: dict[str, Any] = {"id": rid, "shortDescription": {"text": t.finding.title}}
            if t.finding.help_uri:
                rule["helpUri"] = t.finding.help_uri
            if t.finding.cwe:
                rule["properties"] = {"tags": ["security", *t.finding.cwe]}
            rules[rid] = rule
    with_baseline = report.fixed is not None
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "findings-triage",
                        "version": report.tool_version,
                        "informationUri": INFORMATION_URI,
                        "rules": [rules[k] for k in sorted(rules)],
                    }
                },
                "results": [_result(t, with_baseline) for t in report.findings],
                "properties": {
                    "triage/asOf": report.as_of,
                    "triage/commit": report.run.commit,
                    "triage/stats": report.stats.model_dump(mode="json"),
                },
            }
        ],
    }
