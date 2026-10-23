from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage.auditlog import AuditLog, AuditLogError, verify


def make_log(path: Path, n: int = 3) -> None:
    log = AuditLog(path)
    for i in range(n):
        log.append("run1", "decision", fingerprint=f"fp{i}", bucket="review")
    log.flush()


def test_chain_verifies_and_appends_across_writers(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    make_log(path)
    make_log(path)  # a second writer continues the same chain
    result = verify(path)
    assert result.ok and result.events == 6


def test_edited_event_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    make_log(path)
    lines = path.read_text().splitlines()
    event = json.loads(lines[1])
    event["bucket"] = "suppressed"
    lines[1] = json.dumps(event)
    path.write_text("\n".join(lines) + "\n")
    result = verify(path)
    assert not result.ok and "event 2" in (result.error or "")


def test_deleted_event_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    make_log(path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not verify(path).ok


def test_refuses_to_extend_a_broken_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    make_log(path)
    path.write_text(path.read_text().replace("review", "actionable", 1))
    with pytest.raises(AuditLogError):
        AuditLog(path)
