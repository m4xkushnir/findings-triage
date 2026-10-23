"""Append-only, hash-chained decision log.

Each line is one JSON event. Its `hash` covers the canonical JSON of every other field,
including `prev`, the previous event's hash, so editing, deleting or reordering any line breaks
verification from that point on.

That makes the log tamper-evident, not tamper-proof: someone who can rewrite the file can
rebuild the whole chain. Anchoring the head hash somewhere the writer cannot change (a CI
artifact, a signed tag, the PR comment) closes that gap; `triage verify-log` prints the head
for that purpose.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(event: dict[str, Any]) -> str:
    body = {k: v for k, v in event.items() if k != "hash"}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


class AuditLogError(Exception):
    pass


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    events: int
    head: str
    error: str | None = None


def read_events(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditLogError(f"{path}:{lineno}: not JSON ({exc.msg})") from exc


def verify(path: Path) -> VerifyResult:
    prev = GENESIS
    count = 0
    try:
        for count, event in enumerate(read_events(path), 1):
            if event.get("seq") != count:
                return VerifyResult(False, count, prev, f"event {count}: seq is {event.get('seq')}")
            if event.get("prev") != prev:
                return VerifyResult(False, count, prev, f"event {count}: chain broken (prev)")
            if _hash(event) != event.get("hash"):
                return VerifyResult(False, count, prev, f"event {count}: content was modified")
            prev = event["hash"]
    except AuditLogError as exc:
        return VerifyResult(False, count, prev, str(exc))
    return VerifyResult(True, count, prev)


class AuditLog:
    """Writer. Verifies the existing chain before appending so it never extends a broken one."""

    def __init__(self, path: Path) -> None:
        self.path = path
        state = verify(path)
        if not state.ok:
            raise AuditLogError(f"{path}: refusing to append to a broken log: {state.error}")
        self._seq = state.events
        self._prev = state.head
        self._pending: list[dict[str, Any]] = []

    def append(self, run_id: str, event: str, **data: Any) -> None:
        self._seq += 1
        record: dict[str, Any] = {
            "seq": self._seq,
            "prev": self._prev,
            "recorded_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "run_id": run_id,
            "event": event,
            **data,
        }
        record["hash"] = _hash(record)
        self._prev = record["hash"]
        self._pending.append(record)

    def flush(self) -> None:
        if not self._pending:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            for record in self._pending:
                fh.write(canonical(record) + "\n")
        self._pending.clear()
