"""Measure the prompts the LLM layer would send for a run, without calling any API.

Builds the exact system and user prompt for every finding that would be enriched (unsuppressed,
top N by severity) and reports their size in characters. Token counts need the provider's
tokenizer, so tokens are given as a range from two chars-per-token ratios and labelled as an
estimate; run `triage report --enrich llm` with credentials for measured usage.

Usage:
    python eval/prompt_budget.py RUN_JSON [--suppressions FILE] [--max N]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from triage.enrich.prompt import SYSTEM_PROMPT, build_prompt
from triage.model import Run
from triage.output.common import pricing
from triage.suppress import Suppressor, load_suppressions

# Code and markup tokenize denser than English prose; bracket the estimate.
CHARS_PER_TOKEN = (3.0, 4.0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run")
    parser.add_argument("--suppressions")
    parser.add_argument("--max", type=int, default=200)
    parser.add_argument("--model", default="claude-opus-5-5")
    args = parser.parse_args()

    run = Run.model_validate_json(Path(args.run).read_bytes())
    sup = Suppressor(
        load_suppressions(Path(args.suppressions) if args.suppressions else None),
        dt.date(2026, 10, 23),
    )
    open_findings = [f for f in run.findings if sup.check(f).applied is None]
    ranked = sorted(open_findings, key=lambda f: (-f.severity.rank, f.location.path))
    chosen = ranked[: args.max]
    sizes = [len(SYSTEM_PROMPT) + len(build_prompt(f)) for f in chosen]
    total = sum(sizes)
    price = pricing()["models"][args.model]["input"]
    tokens = [total / r for r in reversed(CHARS_PER_TOKEN)]
    print(
        json.dumps(
            {
                "findings_enriched": len(chosen),
                "prompt_chars_total": total,
                "prompt_chars_mean": round(total / len(sizes)) if sizes else 0,
                "prompt_chars_max": max(sizes, default=0),
                "input_tokens_estimate": [round(t) for t in tokens],
                "input_cost_usd_estimate": [round(t * price / 1_000_000, 3) for t in tokens],
                "model": args.model,
                "note": "estimate from character counts; output tokens not estimated",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
