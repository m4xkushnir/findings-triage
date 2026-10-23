"""Enrichment: an opinion on each finding that suppression did not already settle.

Modes:
  off         no enrichment; buckets come from scanner severity alone
  heuristic   deterministic rules only (enrich/heuristic.py)
  llm         Claude for the top findings by severity, heuristics for the rest and on failure
  cache-only  cached LLM verdicts where present, heuristics otherwise; never calls the API.
              The mode for CI replays and for reproducing a report exactly.
  auto        llm when credentials are configured, heuristic otherwise
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from triage.enrich import heuristic
from triage.enrich.cache import VerdictCache
from triage.enrich.claude import DEFAULT_EFFORT, DEFAULT_MODEL, ClaudeEnricher, LLMStats
from triage.model import Enrichment, Finding


class EnrichMode(StrEnum):
    OFF = "off"
    HEURISTIC = "heuristic"
    LLM = "llm"
    CACHE_ONLY = "cache-only"
    AUTO = "auto"


def llm_configured() -> bool:
    """Whether Anthropic credentials appear to be configured. Checks presence only."""
    if os.environ.get("TRIAGE_LLM_PROVIDER", "anthropic").lower() in ("none", "off", ""):
        return False
    if any(os.environ.get(v) for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")):
        return True
    return bool(os.environ.get("ANTHROPIC_PROFILE"))


@dataclass
class EnrichOutcome:
    mode: EnrichMode
    verdicts: dict[str, Enrichment]
    llm: LLMStats | None


def resolve_mode(mode: EnrichMode) -> EnrichMode:
    if mode is EnrichMode.AUTO:
        return EnrichMode.LLM if llm_configured() else EnrichMode.HEURISTIC
    return mode


def run_enrichment(
    findings: Sequence[Finding],
    mode: EnrichMode,
    *,
    cache_dir: Path | None,
    max_llm_findings: int = 200,
    client: object = None,
) -> EnrichOutcome:
    mode = resolve_mode(mode)
    if mode is EnrichMode.OFF:
        return EnrichOutcome(mode, {}, None)

    verdicts: dict[str, Enrichment] = {}
    stats = None
    if mode in (EnrichMode.LLM, EnrichMode.CACHE_ONLY):
        enricher = ClaudeEnricher(
            model=os.environ.get("TRIAGE_LLM_MODEL", DEFAULT_MODEL),
            effort=os.environ.get("TRIAGE_LLM_EFFORT", DEFAULT_EFFORT),
            cache=VerdictCache(cache_dir),
            client=client,
            max_workers=int(os.environ.get("TRIAGE_LLM_CONCURRENCY", "4")),
            cache_only=mode is EnrichMode.CACHE_ONLY,
        )
        # Spend the LLM budget on the findings most worth a second opinion.
        ranked = sorted(
            findings,
            key=lambda f: (-f.severity.rank, f.location.path, f.location.start_line or 0),
        )
        verdicts = enricher.enrich_many(ranked[:max_llm_findings])
        stats = enricher.stats

    for finding in findings:
        if finding.fingerprint not in verdicts:
            verdicts[finding.fingerprint] = heuristic.enrich(finding)
    return EnrichOutcome(mode, verdicts, stats)
