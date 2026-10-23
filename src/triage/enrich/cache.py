"""On-disk cache for LLM verdicts.

The key covers everything that can change the answer: the finding's fingerprint, the prompt
template version, the model, and a hash of the exact prompt text (so a change to the captured
code context also misses). Re-running a report with the same cache therefore makes no API calls
and produces the same bytes, which is what makes LLM-assisted reports replayable.

Entries are plain JSON, one file per key, so the cache can be committed or stored as a CI
artifact and reviewed like any other input.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from triage.model import Enrichment


def cache_key(fingerprint: str, prompt_version: str, model: str, prompt: str) -> str:
    prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    material = "\x00".join((fingerprint, prompt_version, model, prompt_sha))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class VerdictCache:
    def __init__(self, directory: Path | None) -> None:
        self.directory = directory

    def _path(self, key: str) -> Path | None:
        if self.directory is None:
            return None
        return self.directory / key[:2] / f"{key}.json"

    def get(self, key: str) -> Enrichment | None:
        path = self._path(key)
        if path is None or not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Enrichment.model_validate(data["enrichment"]).model_copy(update={"cached": True})
        except (OSError, json.JSONDecodeError, KeyError, ValidationError):
            return None  # a corrupt entry is a miss, never a crash

    def put(self, key: str, fingerprint: str, enrichment: Enrichment) -> None:
        path = self._path(key)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "key": key,
            "fingerprint": fingerprint,
            "enrichment": enrichment.model_dump(mode="json", exclude={"cached"}),
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(path)
