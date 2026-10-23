"""The two pipelines, kept free of I/O policy so tests can drive them directly.

  build_run     raw scanner findings -> fingerprinted, deduplicated Run snapshot
  build_report  Run (+ suppressions, enrichment, baseline) -> Report

`build_report` takes `as_of` as an argument instead of reading the clock, because suppression
expiry depends on the date. With the same Run, suppression file, cache and `as_of`, it returns
an identical Report.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from triage import __version__
from triage.dedup import drop_exact_repeats, merge
from triage.enrich import EnrichMode, EnrichOutcome, run_enrichment
from triage.enrich.heuristic import HEURISTIC_VERSION
from triage.enrich.prompt import PROMPT_VERSION
from triage.fingerprint import FINGERPRINT_VERSION, fingerprint_all
from triage.model import (
    Bucket,
    Finding,
    FixedRef,
    RawFinding,
    Report,
    Run,
    RunMeta,
    Stats,
    TriagedFinding,
)
from triage.policy import decide
from triage.source import SourceTree
from triage.suppress import SuppressionFile, Suppressor


def build_run(
    raws: Sequence[RawFinding],
    root: Path | None,
    *,
    root_name: str,
    commit: str | None,
    scanners: Sequence[str],
) -> Run:
    raw_by_scanner = Counter(r.scanner for r in raws)
    unique, exact_repeats = drop_exact_repeats(raws)
    fingerprinted = fingerprint_all(unique, SourceTree(root))
    findings, stats = merge(fingerprinted)
    meta = RunMeta(
        tool_version=__version__,
        fingerprint_version=FINGERPRINT_VERSION,
        root_name=root_name,
        commit=commit,
        scanners=tuple(sorted(set(scanners) | set(raw_by_scanner))),
        raw_count=len(raws),
        raw_by_scanner=dict(sorted(raw_by_scanner.items())),
        cross_scanner_duplicates=stats.cross_scanner_duplicates,
        same_scanner_duplicates=stats.same_scanner_duplicates + exact_repeats,
    )
    return Run(meta=meta, findings=tuple(findings))


# --- diff --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Diff:
    new: tuple[Finding, ...]
    fixed: tuple[Finding, ...]
    unchanged: tuple[Finding, ...]


def _ids(finding: Finding) -> set[str]:
    return {finding.fingerprint, *finding.aliases}


def diff_runs(base: Run, head: Run) -> Diff:
    """Match findings across runs by fingerprint or any alias."""
    base_ids = {i for f in base.findings for i in _ids(f)}
    head_ids = {i for f in head.findings for i in _ids(f)}
    new = tuple(f for f in head.findings if not _ids(f) & base_ids)
    unchanged = tuple(f for f in head.findings if _ids(f) & base_ids)
    fixed = tuple(f for f in base.findings if not _ids(f) & head_ids)
    return Diff(new=new, fixed=fixed, unchanged=unchanged)


# --- report ------------------------------------------------------------------------------

_BUCKET_ORDER = {Bucket.ACTIONABLE: 0, Bucket.REVIEW: 1, Bucket.SUPPRESSED: 2}


def _sort_key(t: TriagedFinding) -> tuple[int, int, str, int, str]:
    f = t.finding
    return (
        _BUCKET_ORDER[t.bucket],
        -t.effective_severity.rank,
        f.location.path,
        f.location.start_line or 0,
        f.fingerprint,
    )


@dataclass
class ReportResult:
    report: Report
    enrichment: EnrichOutcome
    stale_suppressions: list[str]


def build_report(
    run: Run,
    *,
    suppressions: SuppressionFile,
    as_of: dt.date,
    enrich_mode: EnrichMode,
    cache_dir: Path | None,
    baseline: Run | None = None,
    max_llm_findings: int = 200,
    llm_client: object = None,
) -> ReportResult:
    suppressor = Suppressor(suppressions, as_of)
    checks = {f.fingerprint: suppressor.check(f) for f in run.findings}

    # Suppressed findings are settled by a person; do not spend LLM calls on them.
    open_findings = [f for f in run.findings if checks[f.fingerprint].applied is None]
    outcome = run_enrichment(
        open_findings,
        enrich_mode,
        cache_dir=cache_dir,
        max_llm_findings=max_llm_findings,
        client=llm_client,
    )

    diff = diff_runs(baseline, run) if baseline is not None else None
    new_ids = {f.fingerprint for f in diff.new} if diff else set()

    triaged = sorted(
        (
            decide(
                f,
                checks[f.fingerprint],
                outcome.verdicts.get(f.fingerprint),
                is_new=(f.fingerprint in new_ids) if diff else None,
            )
            for f in run.findings
        ),
        key=_sort_key,
    )

    warnings = []
    stale = suppressor.stale()
    if stale:
        warnings.append("suppression rules matched nothing: " + ", ".join(stale))
    expired = sorted({e.rule_id for c in checks.values() for e in c.expired})
    if expired:
        warnings.append("expired suppression rules resurfaced findings: " + ", ".join(expired))
    if outcome.llm is not None and outcome.llm.disabled_reason:
        warnings.append(f"LLM disabled mid-run ({outcome.llm.disabled_reason}); heuristics used")

    buckets = Counter(t.bucket for t in triaged)
    llm_verdicts = [
        t.enrichment
        for t in triaged
        if t.enrichment is not None and t.enrichment.source.startswith("llm:")
    ]
    stats = Stats(
        raw=run.meta.raw_count,
        after_dedup=len(run.findings),
        cross_scanner_duplicates=run.meta.cross_scanner_duplicates,
        same_scanner_duplicates=run.meta.same_scanner_duplicates,
        suppressed=buckets[Bucket.SUPPRESSED],
        actionable=buckets[Bucket.ACTIONABLE],
        review=buckets[Bucket.REVIEW],
        expired_suppressions=sum(1 for c in checks.values() if c.expired),
        by_kind=dict(sorted(Counter(f.kind.value for f in run.findings).items())),
        actionable_by_severity=dict(
            sorted(
                Counter(
                    t.effective_severity.value for t in triaged if t.bucket is Bucket.ACTIONABLE
                ).items()
            )
        ),
        llm_verdicts=len(llm_verdicts),
        llm_input_tokens=sum(e.input_tokens or 0 for e in llm_verdicts),
        llm_output_tokens=sum(e.output_tokens or 0 for e in llm_verdicts),
    )

    fixed = None
    if diff is not None:
        fixed = tuple(
            FixedRef(
                fingerprint=f.fingerprint,
                kind=f.kind,
                rule_id=f.rule_id,
                path=f.location.path,
                title=f.title,
            )
            for f in diff.fixed
        )

    # `cached` reflects this invocation, not the content; strip it so a first run and its
    # replay from cache produce the same report.
    triaged = [
        t.model_copy(update={"enrichment": t.enrichment.model_copy(update={"cached": False})})
        if t.enrichment is not None
        else t
        for t in triaged
    ]

    report = Report(
        tool_version=__version__,
        fingerprint_version=FINGERPRINT_VERSION,
        prompt_version=PROMPT_VERSION,
        heuristic_version=HEURISTIC_VERSION,
        as_of=as_of.isoformat(),
        run=run.meta,
        # cache-only serves LLM verdicts; labelling it "llm" lets a replay match the original.
        enrich_mode=(
            EnrichMode.LLM if outcome.mode is EnrichMode.CACHE_ONLY else outcome.mode
        ).value,
        stats=stats,
        findings=tuple(triaged),
        baseline_commit=baseline.meta.commit if baseline else None,
        fixed=fixed,
        warnings=tuple(warnings),
    )
    return ReportResult(report=report, enrichment=outcome, stale_suppressions=stale)
