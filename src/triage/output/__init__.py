"""Report renderers. Each is a pure function of the Report; none reads the clock."""

from __future__ import annotations

import json
from typing import Any

from triage.model import Report
from triage.output.html import render_html
from triage.output.markdown import render_markdown
from triage.output.sarif import render_sarif

FORMATS = ("json", "sarif", "md", "html")


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return dumps(report.model_dump(mode="json"))
    if fmt == "sarif":
        return dumps(render_sarif(report))
    if fmt == "md":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    raise ValueError(f"unknown format: {fmt}")
