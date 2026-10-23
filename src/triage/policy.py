"""Turns a finding, its suppression check and its enrichment into a bucket.

The LLM advises and this module decides, within bounds an LLM cannot talk its way past:

  - Nothing is hidden because of the LLM. Only a suppression rule written by a person moves a
    finding to SUPPRESSED; the strongest an LLM verdict can do is move it to REVIEW.
  - Severity moves at most two levels down from what the scanner reported, and at most one up.
  - Low-confidence verdicts do not change severity at all; they are shown, not applied.
  - A secret outside test code never drops below MEDIUM: whether it is live cannot be seen
    from the code, so it is treated as live.

Buckets:
  SUPPRESSED  an active suppression rule matched
  ACTIONABLE  effective severity >= MEDIUM, not judged unlikely-exploitable, and something
              can be done (a dependency needs a published fix)
  REVIEW      everything else: low severity, judged unlikely, or no fix to apply yet
"""

from __future__ import annotations

from triage.enrich.heuristic import path_class
from triage.model import (
    Bucket,
    Confidence,
    Enrichment,
    Finding,
    Kind,
    Severity,
    TriagedFinding,
    Verdict,
)
from triage.suppress import SuppressionResult

MAX_DOWNGRADE = 2
MAX_UPGRADE = 1


def effective_severity(finding: Finding, enrichment: Enrichment | None) -> tuple[Severity, str]:
    reported = finding.severity
    if enrichment is None:
        return reported, f"severity {reported.value} as reported"
    if enrichment.confidence is Confidence.LOW and enrichment.source.startswith("llm:"):
        return reported, "LLM confidence low; reported severity kept"
    suggested = enrichment.suggested_severity
    floor = reported.shift(MAX_DOWNGRADE)
    ceiling = reported.shift(-MAX_UPGRADE)
    bounded = suggested
    if bounded.rank < floor.rank:
        bounded = floor
    if bounded.rank > ceiling.rank:
        bounded = ceiling
    if finding.kind is Kind.SECRET and path_class(finding.location.path) != "test":
        bounded = Severity.at_least(bounded, Severity.MEDIUM)
    if bounded is reported:
        return reported, f"severity {reported.value} confirmed"
    note = f"severity {reported.value} -> {bounded.value}"
    if bounded is not suggested:
        note += f" (suggested {suggested.value}, bounded by policy)"
    return bounded, note


def decide(
    finding: Finding,
    suppression: SuppressionResult,
    enrichment: Enrichment | None,
    is_new: bool | None = None,
) -> TriagedFinding:
    decisions: list[str] = []
    for lapsed in suppression.expired:
        decisions.append(f"suppression {lapsed.rule_id} expired on {lapsed.expires}; not applied")

    if suppression.applied is not None:
        ref = suppression.applied
        until = f" until {ref.expires}" if ref.expires else ""
        decisions.append(f"suppressed by {ref.rule_id} ({ref.author}{until}): {ref.reason}")
        return TriagedFinding(
            finding=finding,
            bucket=Bucket.SUPPRESSED,
            effective_severity=finding.severity,
            suppression=ref,
            enrichment=None,
            is_new=is_new,
            decisions=tuple(decisions),
        )

    severity, note = effective_severity(finding, enrichment)
    decisions.append(note)
    if enrichment is not None:
        decisions.append(
            f"{enrichment.source}: exploitable={enrichment.exploitable.value}, "
            f"reachable={enrichment.reachable.value}, confidence={enrichment.confidence.value}"
        )

    bucket = Bucket.ACTIONABLE
    if severity.rank < Severity.MEDIUM.rank:
        bucket = Bucket.REVIEW
        decisions.append("below medium: review")
    elif (
        enrichment is not None
        and enrichment.exploitable is Verdict.UNLIKELY
        and enrichment.confidence is not Confidence.LOW
    ):
        bucket = Bucket.REVIEW
        decisions.append("judged unlikely to be exploitable: review")
    elif finding.kind is Kind.DEPENDENCY and finding.package and not finding.package.fixed_version:
        bucket = Bucket.REVIEW
        decisions.append("no fixed version published: review")
    else:
        decisions.append("actionable")

    return TriagedFinding(
        finding=finding,
        bucket=bucket,
        effective_severity=severity,
        enrichment=enrichment,
        is_new=is_new,
        decisions=tuple(decisions),
    )
