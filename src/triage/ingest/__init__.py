"""Scanner output readers. Each returns RawFinding objects with root-relative paths."""

from __future__ import annotations

import json
from pathlib import Path

from triage.ingest.errors import IngestError
from triage.ingest.gitleaks_json import parse_gitleaks_json
from triage.ingest.sarif import parse_sarif
from triage.model import RawFinding

__all__ = ["IngestError", "load_report"]


def load_report(path: Path, root: Path) -> list[RawFinding]:
    """Load a report, detecting SARIF or a native format from its content."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IngestError(f"{path}: {exc}") from exc
    if isinstance(data, dict) and "runs" in data:
        return list(parse_sarif(data, root))
    if isinstance(data, list) and (not data or "RuleID" in data[0]):
        return list(parse_gitleaks_json(data, root))
    raise IngestError(f"{path}: unrecognized report format (expected SARIF or Gitleaks JSON)")
