"""Deterministic enrichment, used when no LLM is configured or a call fails.

These rules are deliberately few and explainable. Each one answers a question a reviewer
asks first: is this code shipped at all, is the secret obviously fake, is there a fix to apply.
Anything they cannot decide stays `unknown`, never `unlikely`.
"""

from __future__ import annotations

import re

from triage.model import Confidence, Enrichment, Finding, Kind, Severity, Verdict

HEURISTIC_VERSION = "heuristic:v2"

_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|e2e|cypress|testdata|test-data|__mocks__|mocks?)(/|$)"
    r"|(^|/)[^/]*[._-](test|spec)\.[a-z]+$"
    r"|(^|/)test_[^/]*\.py$"
    r"|_test\.go$",
    re.IGNORECASE,
)
_NON_SHIPPED_PATH = re.compile(
    r"(^|/)(docs?|examples?|samples?|fixtures?|benchmarks?|vendor|third_party|node_modules)(/|$)",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(
    r"example|dummy|fake|sample|placeholder|changeme|change_me|your[_-]|xxxx|<secret>\s*$|redacted",
    re.IGNORECASE,
)


def path_class(path: str) -> str:
    if _TEST_PATH.search(path):
        return "test"
    if _NON_SHIPPED_PATH.search(path):
        return "non-shipped"
    return "production"


def enrich(finding: Finding) -> Enrichment:
    where = path_class(finding.location.path)
    sev = finding.severity

    if finding.kind is Kind.DEPENDENCY and where != "production":
        return _result(
            Verdict.UNLIKELY,
            Verdict.UNLIKELY,
            sev.shift(1),
            Confidence.MEDIUM,
            f"Declared in a {where} manifest, which the shipped package does not install.",
        )

    if finding.kind is Kind.DEPENDENCY:
        pkg = finding.package
        if pkg is not None and pkg.fixed_version:
            why = (
                f"{pkg.name} {pkg.version} is affected; upgrading to {pkg.fixed_version} fixes it."
            )
        else:
            why = "No fixed version is published; reachability of the vulnerable code is unknown."
        return _result(Verdict.UNKNOWN, Verdict.UNKNOWN, sev, Confidence.LOW, why)

    if finding.kind is Kind.SECRET:
        # Only the masked snippet is ever inspected; the secret value itself is not available.
        placeholder = bool(_PLACEHOLDER.search(finding.snippet.replace("<SECRET>", "")))
        if where != "production" or placeholder:
            reason = (
                f"lives in {where} files" if where != "production" else "looks like a placeholder"
            )
            return _result(
                Verdict.UNLIKELY,
                Verdict.UNKNOWN,
                Severity.LOW,
                Confidence.MEDIUM,
                f"Credential {reason}; confirm it is not valid anywhere before closing.",
            )
        return _result(
            Verdict.LIKELY,
            Verdict.UNKNOWN,
            Severity.at_least(sev, Severity.HIGH),
            Confidence.LOW,
            "Committed credential in shipped code. Treat as exposed: rotate, then remove.",
        )

    if where in ("test", "non-shipped"):
        return _result(
            Verdict.UNLIKELY,
            Verdict.UNLIKELY,
            sev.shift(2),
            Confidence.MEDIUM,
            f"Matched in {where} code, which is not part of the deployed application.",
        )
    if finding.rule_confidence is Confidence.LOW:
        return _result(
            Verdict.UNKNOWN,
            Verdict.UNKNOWN,
            sev.shift(1),
            Confidence.MEDIUM,
            "The rule's author labels it low-confidence (expect false positives); "
            "demoted one level until a reviewer or the LLM pass confirms it.",
        )
    return _result(
        Verdict.UNKNOWN,
        Verdict.UNKNOWN,
        sev,
        Confidence.LOW,
        "Matched in shipped code; exploitability needs a reviewer or the LLM pass.",
    )


def _result(
    exploitable: Verdict, reachable: Verdict, sev: Severity, conf: Confidence, why: str
) -> Enrichment:
    return Enrichment(
        source=HEURISTIC_VERSION,
        exploitable=exploitable,
        reachable=reachable,
        suggested_severity=sev,
        confidence=conf,
        reasoning=why,
    )
