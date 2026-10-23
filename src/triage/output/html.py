"""Self-contained HTML report: one file, no external requests, readable offline."""

from __future__ import annotations

from functools import cache

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from triage.model import Bucket, Report
from triage.output.common import by_bucket, llm_usage, location, subject


@cache
def _env() -> Environment:
    return Environment(
        loader=PackageLoader("triage.output", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def render_html(report: Report) -> str:
    groups = by_bucket(report)
    return (
        _env()
        .get_template("report.html.j2")
        .render(
            r=report,
            s=report.stats,
            bucket_counts=[(b.value, len(groups[b])) for b in Bucket],
            new_count=sum(1 for t in report.findings if t.is_new),
            usage=llm_usage(report),
            location=location,
            subject=subject,
        )
    )
