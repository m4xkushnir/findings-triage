"""Adapter for Gitleaks' native JSON report.

Gitleaks also writes SARIF, but its JSON carries the rule's entropy and tags as typed fields,
and it is the format most existing pipelines already archive. It also shows the adapter shape
for any scanner without SARIF output: map native fields onto RawFinding, normalize the path,
drop anything outside the root. The `Secret`, `Match` and `Line` fields are never read.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from triage.ingest.errors import IngestError
from triage.model import Kind, Location, RawFinding, Severity
from triage.source import normalize_path


def parse_gitleaks_json(data: list[dict[str, Any]], root: Path) -> Iterator[RawFinding]:
    if not isinstance(data, list):
        raise IngestError("Gitleaks JSON must be a list of findings")
    for item in data:
        path = normalize_path(str(item.get("File", "")), root)
        if path is None or not item.get("RuleID"):
            continue
        yield RawFinding(
            scanner="gitleaks",
            rule_id=str(item["RuleID"]),
            kind=Kind.SECRET,
            # Gitleaks has no severity model; a committed credential is high until shown
            # otherwise (test fixture, placeholder, revoked), which triage decides later.
            severity=Severity.HIGH,
            message=str(item.get("Description") or item["RuleID"]),
            location=Location(
                path=path,
                start_line=item.get("StartLine"),
                end_line=item.get("EndLine") or item.get("StartLine"),
                start_column=item.get("StartColumn"),
                end_column=item.get("EndColumn"),
            ),
            cwe=("CWE-798",),
        )
