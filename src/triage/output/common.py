"""Helpers shared by the Markdown and HTML renderers."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

import yaml

from triage.model import Bucket, Report, TriagedFinding


@cache
def pricing() -> dict[str, Any]:
    text = resources.files("triage.data").joinpath("pricing.yaml").read_text("utf-8")
    data: dict[str, Any] = yaml.safe_load(text)
    return data


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float | None:
    price = pricing()["models"].get(model)
    if price is None:
        return None
    return float(input_tokens * price["input"] + output_tokens * price["output"]) / 1_000_000


@dataclass(frozen=True)
class LLMUsage:
    model: str
    verdicts: int
    input_tokens: int
    output_tokens: int
    cost_usd: float | None


def llm_usage(report: Report) -> list[LLMUsage]:
    per_model: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for t in report.findings:
        e = t.enrichment
        if e is None or not e.source.startswith("llm:"):
            continue
        row = per_model[e.source.removeprefix("llm:")]
        row[0] += 1
        row[1] += e.input_tokens or 0
        row[2] += e.output_tokens or 0
    return [
        LLMUsage(model, n, i, o, estimate_cost(model, i, o))
        for model, (n, i, o) in sorted(per_model.items())
    ]


def location(t: TriagedFinding) -> str:
    loc = t.finding.location
    if loc.start_line is None:
        return loc.path
    if loc.end_line and loc.end_line != loc.start_line:
        return f"{loc.path}:{loc.start_line}-{loc.end_line}"
    return f"{loc.path}:{loc.start_line}"


def subject(t: TriagedFinding) -> str:
    """What the finding is about, in one line."""
    f = t.finding
    if f.package is not None:
        fix = f" -> {f.package.fixed_version}" if f.package.fixed_version else " (no fix)"
        return f"{f.rule_id} in {f.package.name} {f.package.version}{fix}"
    return f.title


def by_bucket(report: Report) -> dict[Bucket, list[TriagedFinding]]:
    groups: dict[Bucket, list[TriagedFinding]] = {b: [] for b in Bucket}
    for t in report.findings:
        groups[t.bucket].append(t)
    return groups
