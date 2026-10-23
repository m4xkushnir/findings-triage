"""Core data model.

A scanner result goes through three shapes:

  RawFinding    what one scanner said, normalized (ingest/)
  Finding       one deduplicated issue with a stable fingerprint (fingerprint.py, dedup.py)
  TriagedFinding  a Finding plus the decisions taken about it (suppress.py, enrich/, policy.py)

Every model is a frozen pydantic model so that a run serializes to the same bytes every time.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Kind(StrEnum):
    CODE = "code"  # SAST: a pattern in first-party source
    DEPENDENCY = "dependency"  # SCA: a vulnerable third-party package
    SECRET = "secret"  # a credential committed to the tree
    CONFIG = "config"  # IaC / Dockerfile / manifest misconfiguration


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def shift(self, steps: int) -> Severity:
        """Move `steps` levels toward INFO (positive) or CRITICAL (negative), clamped."""
        order = list(Severity)
        idx = min(max(order.index(self) + steps, 0), len(order) - 1)
        return order[idx]

    @classmethod
    def at_least(cls, value: Severity, floor: Severity) -> Severity:
        return value if value.rank >= floor.rank else floor


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Verdict(StrEnum):
    LIKELY = "likely"
    UNLIKELY = "unlikely"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Package(Frozen):
    name: str
    version: str
    fixed_version: str | None = None
    ecosystem: str | None = None


class Location(Frozen):
    path: str  # POSIX path relative to the scanned root
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None


class RawFinding(Frozen):
    scanner: str  # "semgrep", "trivy", "gitleaks", ...
    rule_id: str
    kind: Kind
    severity: Severity
    message: str
    location: Location
    cwe: tuple[str, ...] = ()
    package: Package | None = None
    # The rule author's own precision label (Semgrep's "LOW CONFIDENCE" tag etc.), if any.
    rule_confidence: Confidence | None = None
    # Snippet the scanner itself reported, if any. Never trusted for secrets.
    scanner_snippet: str | None = None
    help_uri: str | None = None


class SourceRef(Frozen):
    """One scanner's report of a deduplicated finding."""

    scanner: str
    rule_id: str
    fingerprint: str
    severity: Severity


class Finding(Frozen):
    fingerprint: str
    # Fingerprints of the other scanners' reports merged into this one. A diff matches on
    # the fingerprint or any alias, so adding a scanner never makes old findings look new.
    aliases: tuple[str, ...] = ()
    kind: Kind
    rule_id: str  # rule of the primary source
    title: str
    severity: Severity  # highest severity among sources
    location: Location
    cwe: tuple[str, ...] = ()
    package: Package | None = None
    rule_confidence: Confidence | None = None
    sources: tuple[SourceRef, ...]
    # Normalized, secret-masked lines the fingerprint was computed from.
    snippet: str = ""
    # Secret-masked surrounding code, captured at scan time so enrichment and reports can be
    # rebuilt from the run file alone, without the repository.
    context: str = ""
    context_start_line: int | None = None
    help_uri: str | None = None


class RunMeta(Frozen):
    tool_version: str
    fingerprint_version: str
    root_name: str  # basename only; absolute paths would make runs machine-specific
    commit: str | None = None
    scanners: tuple[str, ...]
    raw_count: int
    raw_by_scanner: dict[str, int]
    cross_scanner_duplicates: int
    same_scanner_duplicates: int


class Run(Frozen):
    """The snapshot written by `triage scan`. Everything downstream reads only this."""

    schema_version: Literal[1] = 1
    meta: RunMeta
    findings: tuple[Finding, ...]


# --- triage decisions -------------------------------------------------------------------


class Enrichment(Frozen):
    source: str  # "llm:<model>" or "heuristic:<version>"
    exploitable: Verdict
    reachable: Verdict
    suggested_severity: Severity
    confidence: Confidence
    reasoning: str
    cached: bool = False
    # Usage is recorded for LLM results only; all None for heuristics.
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: int | None = None


class Bucket(StrEnum):
    ACTIONABLE = "actionable"
    REVIEW = "review"
    SUPPRESSED = "suppressed"


class SuppressionRef(Frozen):
    rule_id: str
    reason: str
    author: str
    created: str
    expires: str | None = None


class TriagedFinding(Frozen):
    finding: Finding
    bucket: Bucket
    effective_severity: Severity
    suppression: SuppressionRef | None = None
    enrichment: Enrichment | None = None
    # None when the report has no baseline; otherwise whether the finding is new since it.
    is_new: bool | None = None
    # Human-readable chain of decisions, in the order they were taken.
    decisions: tuple[str, ...] = Field(default_factory=tuple)


class FixedRef(Frozen):
    """A baseline finding that no longer appears."""

    fingerprint: str
    kind: Kind
    rule_id: str
    path: str
    title: str


class Stats(Frozen):
    raw: int
    after_dedup: int
    cross_scanner_duplicates: int
    same_scanner_duplicates: int
    suppressed: int
    actionable: int
    review: int
    expired_suppressions: int
    by_kind: dict[str, int]
    actionable_by_severity: dict[str, int]
    llm_verdicts: int
    llm_input_tokens: int
    llm_output_tokens: int


class Report(Frozen):
    """Everything a rendered report contains. A pure function of its inputs: no clocks."""

    schema_version: Literal[1] = 1
    tool_version: str
    fingerprint_version: str
    prompt_version: str
    heuristic_version: str
    as_of: str
    run: RunMeta
    enrich_mode: str
    stats: Stats
    findings: tuple[TriagedFinding, ...]
    baseline_commit: str | None = None
    fixed: tuple[FixedRef, ...] | None = None
    warnings: tuple[str, ...] = ()
