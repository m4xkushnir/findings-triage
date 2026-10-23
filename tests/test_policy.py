from __future__ import annotations

from conftest import raw

from triage.engine import build_run
from triage.model import Bucket, Confidence, Enrichment, Finding, Kind, Package, Severity, Verdict
from triage.policy import decide
from triage.suppress import SuppressionResult

NONE = SuppressionResult(applied=None, expired=())


def finding(**kw) -> Finding:  # type: ignore[no-untyped-def]
    return build_run([raw(**kw)], None, root_name="r", commit=None, scanners=[]).findings[0]


def llm(
    sev: Severity,
    exploitable: Verdict = Verdict.UNKNOWN,
    confidence: Confidence = Confidence.HIGH,
) -> Enrichment:
    return Enrichment(
        source="llm:claude-opus-5-5",
        exploitable=exploitable,
        reachable=Verdict.UNKNOWN,
        suggested_severity=sev,
        confidence=confidence,
        reasoning="r",
    )


def test_llm_cannot_hide_a_finding() -> None:
    t = decide(finding(), NONE, llm(Severity.INFO, Verdict.UNLIKELY))
    assert t.bucket is Bucket.REVIEW  # visible, never suppressed


def test_downgrade_is_bounded_to_two_levels() -> None:
    t = decide(finding(severity=Severity.CRITICAL), NONE, llm(Severity.INFO))
    assert t.effective_severity is Severity.MEDIUM


def test_upgrade_is_bounded_to_one_level() -> None:
    t = decide(finding(severity=Severity.LOW), NONE, llm(Severity.CRITICAL))
    assert t.effective_severity is Severity.MEDIUM


def test_low_confidence_llm_does_not_change_severity() -> None:
    t = decide(finding(), NONE, llm(Severity.LOW, confidence=Confidence.LOW))
    assert t.effective_severity is Severity.HIGH
    assert t.bucket is Bucket.ACTIONABLE


def test_secret_outside_tests_never_below_medium() -> None:
    f = finding(kind=Kind.SECRET, scanner="gitleaks", rule="k", path="src/cfg.ts")
    assert decide(f, NONE, llm(Severity.LOW)).effective_severity is Severity.MEDIUM


def test_dependency_without_fix_goes_to_review() -> None:
    pkg = Package(name="p", version="1", fixed_version=None)
    f = finding(kind=Kind.DEPENDENCY, scanner="trivy", rule="CVE-1", package=pkg)
    t = decide(f, NONE, None)
    assert t.bucket is Bucket.REVIEW
    assert "no fixed version" in t.decisions[-1]


def test_decision_trail_is_recorded() -> None:
    t = decide(finding(severity=Severity.CRITICAL), NONE, llm(Severity.INFO))
    assert t.decisions[0] == "severity critical -> medium (suggested info, bounded by policy)"
    assert t.decisions[-1] == "actionable"
