"""Markdown report: the summary a reviewer reads in a PR comment or a CI job page."""

from __future__ import annotations

from triage.model import Bucket, Report, TriagedFinding
from triage.output.common import by_bucket, llm_usage, location, pricing, subject

MAX_ROWS = 200


def _cell(text: str, limit: int = 160) -> str:
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.replace("|", "\\|")


def _why(t: TriagedFinding) -> str:
    if t.suppression is not None:
        s = t.suppression
        until = f", until {s.expires}" if s.expires else ""
        return f"{s.rule_id} by {s.author}{until}: {s.reason}"
    if t.enrichment is not None:
        return t.enrichment.reasoning
    return ""


def _table(rows: list[TriagedFinding], *, with_new: bool) -> list[str]:
    head = "| Severity | Kind | Location | Finding | Why |"
    sep = "|---|---|---|---|---|"
    if with_new:
        head = "| New | " + head[2:]
        sep = "|---" + sep
    out = [head, sep]
    for t in rows[:MAX_ROWS]:
        sev = t.effective_severity.value
        if t.effective_severity is not t.finding.severity:
            sev += f" (was {t.finding.severity.value})"
        cells = [
            sev,
            t.finding.kind.value,
            f"`{_cell(location(t), 120)}`",
            _cell(subject(t)),
            _cell(_why(t), 220),
        ]
        if with_new:
            cells.insert(0, "new" if t.is_new else "")
        out.append("| " + " | ".join(cells) + " |")
    if len(rows) > MAX_ROWS:
        out.append(f"\n_{len(rows) - MAX_ROWS} more in report.json / report.sarif._")
    return out


def render_markdown(report: Report) -> str:
    s = report.stats
    run = report.run
    groups = by_bucket(report)
    with_new = report.fixed is not None
    lines = [
        f"# Security findings triage: {run.root_name}",
        "",
        f"Commit `{run.commit or 'unknown'}`, as of {report.as_of}, "
        f"scanners: {', '.join(run.scanners)}, enrichment: {report.enrich_mode}.",
        "",
        "| Stage | Count |",
        "|---|---|",
        f"| Raw scanner results | {s.raw} |",
        f"| After dedup | {s.after_dedup} |",
        f"| of which merged across scanners | {s.cross_scanner_duplicates} |",
        f"| Suppressed | {s.suppressed} |",
        f"| Review | {s.review} |",
        f"| **Actionable** | **{s.actionable}** |",
        "",
    ]
    if s.actionable_by_severity:
        parts = [f"{k}: {v}" for k, v in s.actionable_by_severity.items()]
        lines += ["Actionable by severity: " + ", ".join(parts) + ".", ""]
    if with_new:
        new = sum(1 for t in report.findings if t.is_new)
        fixed = len(report.fixed or ())
        lines += [
            f"Against baseline `{report.baseline_commit or 'unknown'}`: {new} new, {fixed} fixed.",
            "",
        ]
    if report.warnings:
        lines += ["## Warnings", ""] + [f"- {w}" for w in report.warnings] + [""]

    lines += [f"## Actionable ({len(groups[Bucket.ACTIONABLE])})", ""]
    if groups[Bucket.ACTIONABLE]:
        lines += _table(groups[Bucket.ACTIONABLE], with_new=with_new)
    else:
        lines.append("Nothing actionable.")
    lines.append("")

    for bucket, title in ((Bucket.REVIEW, "Review"), (Bucket.SUPPRESSED, "Suppressed")):
        rows = groups[bucket]
        lines += [
            "<details>",
            f"<summary>{title} ({len(rows)})</summary>",
            "",
            *(_table(rows, with_new=with_new) if rows else ["None."]),
            "",
            "</details>",
            "",
        ]

    if report.fixed:
        lines += ["<details>", f"<summary>Fixed since baseline ({len(report.fixed)})</summary>", ""]
        lines += [f"- `{f.path}` {f.rule_id}: {_cell(f.title)}" for f in report.fixed[:MAX_ROWS]]
        lines += ["", "</details>", ""]

    usage = llm_usage(report)
    if usage:
        lines += ["## LLM usage", ""]
        for u in usage:
            cost = f", est. ${u.cost_usd:.2f}" if u.cost_usd is not None else ""
            lines.append(
                f"- {u.model}: {u.verdicts} verdicts, {u.input_tokens:,} input / "
                f"{u.output_tokens:,} output tokens{cost}"
            )
        lines += [
            "",
            f"Token counts are as recorded when each verdict was generated; prices as of "
            f"{pricing()['as_of']}. Cached verdicts cost nothing to re-use.",
            "",
        ]

    lines += [
        "---",
        f"findings-triage {report.tool_version}, fingerprint {report.fingerprint_version}, "
        f"{report.prompt_version}, {report.heuristic_version}",
        "",
    ]
    return "\n".join(lines)
