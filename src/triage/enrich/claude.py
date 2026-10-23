"""LLM enrichment through the Anthropic Messages API.

One request per finding, structured output constrained by RESPONSE_SCHEMA, verdicts cached by
fingerprint + prompt version + model + prompt hash. The `anthropic` package is an optional
dependency (`pip install findings-triage[llm]`); nothing here is imported unless LLM
enrichment is actually selected.

Failure handling is per finding and always degrades to the deterministic heuristic, so an
outage or a refusal changes how confident a report is, never whether it is produced:

  refusal (stop_reason)        heuristic for this finding, reason recorded
  rate limit / 5xx / network   the SDK retries; after that, heuristic for this finding
  auth / permission / model    LLM disabled for the rest of the run, heuristics from then on
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from triage.enrich.cache import VerdictCache, cache_key
from triage.enrich.prompt import PROMPT_VERSION, RESPONSE_SCHEMA, SYSTEM_PROMPT, build_prompt
from triage.model import Confidence, Enrichment, Finding, Severity, Verdict

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT = "medium"
MAX_TOKENS = 8000
REASONING_LIMIT = 600

# Models that accept server-side refusal fallbacks (`fallbacks: "default"`). A security-triage
# prompt is exactly the kind of request a cyber classifier can decline, and routing the retry
# server-side keeps that from turning into a missing verdict.
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class LLMVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exploitable: Verdict
    reachable: Verdict
    suggested_severity: Severity
    confidence: Confidence
    reasoning: str


class LLMFailure(Exception):
    def __init__(self, reason: str, *, fatal: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.fatal = fatal


@dataclass
class LLMStats:
    model: str
    requested: int = 0
    api_calls: int = 0
    cache_hits: int = 0
    failures: dict[str, int] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    wall_ms: int = 0
    disabled_reason: str | None = None


class ClaudeEnricher:
    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        effort: str = DEFAULT_EFFORT,
        cache: VerdictCache,
        client: Any = None,
        max_workers: int = 4,
        cache_only: bool = False,
    ) -> None:
        self.model = model
        self.effort = effort
        self.cache = cache
        self.cache_only = cache_only
        self.max_workers = max_workers
        self._client = client
        self._lock = threading.Lock()
        self.stats = LLMStats(model=model)

    def _get_client(self) -> Any:
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic()
        return self._client

    def _request(self, prompt: str) -> tuple[LLMVerdict, int, int, str]:
        import anthropic

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": {
                "effort": self.effort,
                "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA},
            },
        }
        if self.model in _FALLBACK_MODELS:
            kwargs["betas"] = [_FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
        try:
            response = self._get_client().beta.messages.create(**kwargs)
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            raise LLMFailure(f"auth: {exc.__class__.__name__}", fatal=True) from exc
        except anthropic.NotFoundError as exc:
            raise LLMFailure(f"model not found: {self.model}", fatal=True) from exc
        except anthropic.BadRequestError as exc:
            raise LLMFailure("bad request") from exc
        except anthropic.RateLimitError as exc:
            raise LLMFailure("rate limited") from exc
        except anthropic.APIStatusError as exc:
            raise LLMFailure(f"api error {exc.status_code}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMFailure("connection error") from exc

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) or "unspecified"
            raise LLMFailure(f"refusal ({category})")
        if response.stop_reason == "max_tokens":
            raise LLMFailure("truncated (max_tokens)")
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise LLMFailure("no text block in response")
        try:
            verdict = LLMVerdict.model_validate(json.loads(text))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise LLMFailure("response failed schema validation") from exc
        usage = response.usage
        return verdict, usage.input_tokens, usage.output_tokens, str(response.model)

    def _one(self, finding: Finding) -> Enrichment | None:
        prompt = build_prompt(finding)
        key = cache_key(finding.fingerprint, PROMPT_VERSION, self.model, prompt)
        hit = self.cache.get(key)
        if hit is not None:
            with self._lock:
                self.stats.cache_hits += 1
            return hit
        with self._lock:
            if self.cache_only or self.stats.disabled_reason:
                return None
        started = time.monotonic()
        try:
            verdict, tokens_in, tokens_out, served_by = self._request(prompt)
        except LLMFailure as failure:
            with self._lock:
                self.stats.failures[failure.reason] = self.stats.failures.get(failure.reason, 0) + 1
                if failure.fatal and not self.stats.disabled_reason:
                    self.stats.disabled_reason = failure.reason
            return None
        latency = int((time.monotonic() - started) * 1000)
        enrichment = Enrichment(
            source=f"llm:{served_by}",
            exploitable=verdict.exploitable,
            reachable=verdict.reachable,
            suggested_severity=verdict.suggested_severity,
            confidence=verdict.confidence,
            reasoning=" ".join(verdict.reasoning.split())[:REASONING_LIMIT],
            input_tokens=tokens_in,
            output_tokens=tokens_out,
            latency_ms=latency,
        )
        self.cache.put(key, finding.fingerprint, enrichment)
        with self._lock:
            self.stats.api_calls += 1
            self.stats.input_tokens += tokens_in
            self.stats.output_tokens += tokens_out
        return enrichment

    def enrich_many(self, findings: Sequence[Finding]) -> dict[str, Enrichment]:
        """Verdicts keyed by fingerprint. Findings without one fall back to heuristics."""
        self.stats.requested = len(findings)
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            results = list(pool.map(self._one, findings))
        self.stats.wall_ms = int((time.monotonic() - started) * 1000)
        return {f.fingerprint: r for f, r in zip(findings, results, strict=True) if r is not None}
