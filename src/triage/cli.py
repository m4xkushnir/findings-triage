"""Command line interface.

Exit codes (stable, for CI):
  0  success, nothing at or above --fail-on
  1  findings at or above --fail-on (report written)
  2  bad input: invalid suppression file, broken audit log, replay mismatch, usage error
  3  a scanner failed or its output could not be read
"""

from __future__ import annotations

import datetime as dt
import hashlib
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from triage import __version__
from triage.auditlog import AuditLog, AuditLogError, read_events, verify
from triage.engine import build_report, build_run, diff_runs
from triage.enrich import EnrichMode
from triage.ingest import IngestError, load_report
from triage.model import Bucket, Report, Run, Severity
from triage.output import FORMATS, render
from triage.output.common import estimate_cost
from triage.scanners import SCANNERS, ScannerError, git_commit, run_scanner
from triage.suppress import SuppressionError, load_suppressions

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Triage SAST, dependency and secret-scanner findings into a short, explainable list.",
)

EXIT_FINDINGS = 1
EXIT_INPUT = 2
EXIT_SCANNER = 3


def _err(message: str) -> None:
    typer.echo(message, err=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_run(path: Path) -> Run:
    try:
        return Run.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as exc:
        _err(f"error: {path} is not a triage run file: {exc}")
        raise typer.Exit(EXIT_INPUT) from exc


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command()
def scan(
    root: Annotated[Path, typer.Argument(help="Repository to scan.", exists=True, file_okay=False)],
    out: Annotated[Path, typer.Option("--out", "-o", help="Run file to write.")] = Path(
        ".triage/run.json"
    ),
    scanner: Annotated[
        list[str] | None,
        typer.Option("--scanner", "-s", help="Scanner to run (repeatable). Default: all three."),
    ] = None,
    inputs: Annotated[
        list[Path] | None,
        typer.Option("--input", "-i", help="Existing SARIF or Gitleaks JSON report (repeatable)."),
    ] = None,
    reports_dir: Annotated[
        Path | None, typer.Option(help="Where scanner reports go. Default: next to --out.")
    ] = None,
    semgrep_config: Annotated[str, typer.Option(help="Semgrep ruleset.")] = "p/default",
    trivy_db_repository: Annotated[str | None, typer.Option(help="Trivy DB OCI repo.")] = None,
    trivy_checks_repository: Annotated[
        str | None, typer.Option(help="Trivy checks bundle OCI repo.")
    ] = None,
) -> None:
    """Run scanners (or read their reports) and write a fingerprinted, deduplicated run file."""
    root = root.resolve()
    selected = list(scanner or ([] if inputs else list(SCANNERS)))
    unknown = [s for s in selected if s not in SCANNERS]
    if unknown:
        _err(f"error: unknown scanner(s): {', '.join(unknown)} (known: {', '.join(SCANNERS)})")
        raise typer.Exit(EXIT_INPUT)

    reports: list[Path] = list(inputs or [])
    options = {
        "semgrep_config": semgrep_config,
        "trivy_db_repository": trivy_db_repository or "",
        "trivy_checks_repository": trivy_checks_repository or "",
    }
    raw_dir = reports_dir or out.parent / "raw"
    for name in selected:
        try:
            result = run_scanner(name, root, raw_dir, options)
        except ScannerError as exc:
            _err(f"error: {exc}")
            raise typer.Exit(EXIT_SCANNER) from exc
        _err(f"{name}: {result.seconds:.1f}s -> {result.path}")
        reports.append(result.path)

    raws = []
    for report in reports:
        try:
            raws.extend(load_report(report, root))
        except IngestError as exc:
            _err(f"error: {exc}")
            raise typer.Exit(EXIT_SCANNER) from exc

    run = build_run(raws, root, root_name=root.name, commit=git_commit(root), scanners=selected)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(run.model_dump_json(indent=2) + "\n", encoding="utf-8")
    m = run.meta
    _err(
        f"{m.raw_count} raw -> {len(run.findings)} findings "
        f"({m.cross_scanner_duplicates} cross-scanner, {m.same_scanner_duplicates} same-scanner "
        f"duplicates merged) -> {out}"
    )


def _thresholds(fail_on: str) -> Severity | None:
    if fail_on == "never":
        return None
    try:
        return Severity(fail_on)
    except ValueError as exc:
        raise typer.BadParameter("use critical, high, medium, low, info or never") from exc


def _audit(
    log_path: Path,
    report: Report,
    outputs: dict[str, str],
    inputs: dict[str, Any],
    requested_mode: str,
) -> str:
    run_id = outputs["json"][:16]
    log = AuditLog(log_path)
    log.append(
        run_id,
        "report",
        as_of=report.as_of,
        tool_version=report.tool_version,
        requested_enrich_mode=requested_mode,
        enrich_mode=report.enrich_mode,
        inputs=inputs,
        outputs=outputs,
        stats=report.stats.model_dump(mode="json"),
    )
    for t in report.findings:
        f = t.finding
        log.append(
            run_id,
            "decision",
            fingerprint=f.fingerprint,
            aliases=list(f.aliases),
            rule=next(
                f"{s.scanner}:{s.rule_id}" for s in f.sources if s.fingerprint == f.fingerprint
            ),
            path=f.location.path,
            line=f.location.start_line,
            bucket=t.bucket.value,
            reported_severity=f.severity.value,
            effective_severity=t.effective_severity.value,
            suppression=t.suppression.model_dump(mode="json") if t.suppression else None,
            enrichment=t.enrichment.model_dump(mode="json", exclude={"cached"})
            if t.enrichment
            else None,
            is_new=t.is_new,
            decisions=list(t.decisions),
        )
    log.flush()
    return run_id


@app.command()
def report(
    run_file: Annotated[Path, typer.Argument(help="Run file from `triage scan`.", exists=True)],
    out_dir: Annotated[Path, typer.Option("--out-dir", "-o")] = Path(".triage/report"),
    suppressions: Annotated[
        Path | None, typer.Option("--suppressions", help="Suppression rules (YAML).")
    ] = None,
    enrich: Annotated[EnrichMode, typer.Option(help="Enrichment mode.")] = EnrichMode.AUTO,
    cache_dir: Annotated[Path, typer.Option(help="LLM verdict cache.")] = Path(".triage/cache"),
    max_llm_findings: Annotated[int, typer.Option(help="LLM budget, by severity.")] = 200,
    baseline: Annotated[
        Path | None, typer.Option(help="Earlier run file; marks findings new/unchanged.")
    ] = None,
    as_of: Annotated[
        str | None, typer.Option(help="Date for suppression expiry (YYYY-MM-DD). Default: today.")
    ] = None,
    fmt: Annotated[
        list[str] | None, typer.Option("--format", "-f", help=f"One of {', '.join(FORMATS)}.")
    ] = None,
    fail_on: Annotated[
        str, typer.Option(help="Exit 1 if an actionable finding is at or above this severity.")
    ] = "high",
    new_only: Annotated[
        bool, typer.Option(help="With --baseline, only new findings can fail the build.")
    ] = False,
    audit_log: Annotated[
        Path | None, typer.Option(help="Append every decision to this hash-chained log.")
    ] = None,
) -> None:
    """Apply suppressions, enrichment and policy to a run; write SARIF, Markdown, HTML, JSON."""
    threshold = _thresholds(fail_on)
    formats = fmt or list(FORMATS)
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        _err(f"error: unknown format(s): {', '.join(bad)}")
        raise typer.Exit(EXIT_INPUT)
    try:
        date = dt.date.fromisoformat(as_of) if as_of else dt.date.today()
    except ValueError as exc:
        _err(f"error: --as-of must be YYYY-MM-DD, got {as_of!r}")
        raise typer.Exit(EXIT_INPUT) from exc
    try:
        rules = load_suppressions(suppressions)
    except SuppressionError as exc:
        _err(f"error: invalid suppression file: {exc}")
        raise typer.Exit(EXIT_INPUT) from exc

    run = _load_run(run_file)
    base = _load_run(baseline) if baseline else None
    result = build_report(
        run,
        suppressions=rules,
        as_of=date,
        enrich_mode=enrich,
        cache_dir=cache_dir,
        baseline=base,
        max_llm_findings=max_llm_findings,
    )
    rep = result.report

    out_dir.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, str] = {}
    for f in sorted(set(formats) | {"json"}):
        text = render(rep, f)
        outputs[f] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if f in formats:
            (out_dir / f"report.{f}").write_text(text, encoding="utf-8")

    if audit_log is not None:
        inputs = {
            "run": {"path": str(run_file), "sha256": _sha256(run_file)},
            "suppressions": {"path": str(suppressions), "sha256": _sha256(suppressions)}
            if suppressions
            else None,
            "baseline": {"path": str(baseline), "sha256": _sha256(baseline)} if baseline else None,
            "cache_dir": str(cache_dir),
            "max_llm_findings": max_llm_findings,
        }
        try:
            run_id = _audit(audit_log, rep, outputs, inputs, enrich.value)
        except AuditLogError as exc:
            _err(f"error: {exc}")
            raise typer.Exit(EXIT_INPUT) from exc
        _err(f"audit: run {run_id} appended to {audit_log}")

    s = rep.stats
    _err(
        f"{s.raw} raw -> {s.after_dedup} after dedup -> {s.actionable} actionable "
        f"({s.review} review, {s.suppressed} suppressed); enrichment: {rep.enrich_mode}"
    )
    llm = result.enrichment.llm
    if llm is not None:
        cost = estimate_cost(llm.model, llm.input_tokens, llm.output_tokens)
        cost_text = f", est. ${cost:.2f}" if cost is not None else ""
        failures = ", ".join(f"{k}: {v}" for k, v in sorted(llm.failures.items())) or "none"
        _err(
            f"llm: {llm.api_calls} calls, {llm.cache_hits} cache hits, "
            f"{llm.input_tokens:,} in / {llm.output_tokens:,} out tokens{cost_text}, "
            f"{llm.wall_ms / 1000:.1f}s; failures: {failures}"
        )
    for warning in rep.warnings:
        _err(f"warning: {warning}")
    _err(f"wrote {', '.join(f'report.{f}' for f in formats)} to {out_dir}")

    if threshold is not None:
        failing = [
            t
            for t in rep.findings
            if t.bucket is Bucket.ACTIONABLE
            and t.effective_severity.rank >= threshold.rank
            and (not new_only or t.is_new)
        ]
        if failing:
            scope = "new " if new_only else ""
            _err(f"fail: {len(failing)} {scope}actionable finding(s) at or above {threshold.value}")
            raise typer.Exit(EXIT_FINDINGS)


@app.command()
def diff(
    base: Annotated[Path, typer.Argument(exists=True, help="Earlier run file.")],
    head: Annotated[Path, typer.Argument(exists=True, help="Later run file.")],
    show: Annotated[bool, typer.Option(help="List the new and fixed findings.")] = True,
) -> None:
    """Compare two runs: new, fixed and unchanged findings, matched by fingerprint."""
    d = diff_runs(_load_run(base), _load_run(head))
    typer.echo(f"new: {len(d.new)}  fixed: {len(d.fixed)}  unchanged: {len(d.unchanged)}")
    if show:
        for label, items in (("+", d.new), ("-", d.fixed)):
            for f in items:
                line = f":{f.location.start_line}" if f.location.start_line else ""
                typer.echo(f"{label} {f.fingerprint[:12]} {f.location.path}{line} {f.rule_id}")


@app.command()
def explain(
    fingerprint: Annotated[str, typer.Argument(help="Fingerprint or unique prefix.")],
    audit_log: Annotated[Path, typer.Option(exists=True)] = Path(".triage/audit.jsonl"),
    history: Annotated[bool, typer.Option("--all", help="Every run, not just the last.")] = False,
) -> None:
    """Explain from the audit log why a finding was shown, demoted or hidden."""
    matches = [
        e
        for e in read_events(audit_log)
        if e.get("event") == "decision"
        and any(i.startswith(fingerprint) for i in [e["fingerprint"], *e.get("aliases", [])])
    ]
    if not matches:
        _err(f"no decisions recorded for {fingerprint}")
        raise typer.Exit(EXIT_INPUT)
    ids = {e["fingerprint"] for e in matches}
    if len(ids) > 1 and len(fingerprint) < 32:
        _err(f"prefix {fingerprint} is ambiguous: {', '.join(sorted(i[:12] for i in ids))}")
        raise typer.Exit(EXIT_INPUT)
    for e in matches if history else matches[-1:]:
        typer.echo(f"run {e['run_id']} (recorded {e['recorded_at']}, event #{e['seq']})")
        typer.echo(f"  {e['rule']} at {e['path']}:{e.get('line') or ''}")
        typer.echo(
            f"  bucket: {e['bucket']}, severity {e['reported_severity']} -> "
            f"{e['effective_severity']}"
        )
        for step in e["decisions"]:
            typer.echo(f"  - {step}")


@app.command("verify-log")
def verify_log(audit_log: Annotated[Path, typer.Argument(exists=True)]) -> None:
    """Check the audit log's hash chain. Prints the head hash to anchor elsewhere."""
    result = verify(audit_log)
    if not result.ok:
        _err(f"BROKEN after {result.events - 1} valid events: {result.error}")
        raise typer.Exit(EXIT_INPUT)
    typer.echo(f"ok: {result.events} events, head {result.head}")


@app.command()
def replay(
    audit_log: Annotated[Path, typer.Option(exists=True)] = Path(".triage/audit.jsonl"),
    run_id: Annotated[str | None, typer.Option(help="Report run id. Default: latest.")] = None,
) -> None:
    """Re-derive a recorded report from its inputs and check it is byte-identical.

    LLM verdicts come from the cache only; replay never calls the API.
    """
    reports = [e for e in read_events(audit_log) if e.get("event") == "report"]
    if run_id:
        reports = [e for e in reports if e["run_id"].startswith(run_id)]
    if not reports:
        _err("no matching report event in the audit log")
        raise typer.Exit(EXIT_INPUT)
    event = reports[-1]
    inputs = event["inputs"]

    problems = []
    for key in ("run", "suppressions", "baseline"):
        ref = inputs.get(key)
        if ref is None:
            continue
        path = Path(ref["path"])
        if not path.exists():
            problems.append(f"{key}: {path} is missing")
        elif _sha256(path) != ref["sha256"]:
            problems.append(f"{key}: {path} changed since the report was made")
    if event["tool_version"] != __version__:
        problems.append(f"tool version {__version__} != recorded {event['tool_version']}")
    if problems:
        for p in problems:
            _err(f"cannot replay: {p}")
        raise typer.Exit(EXIT_INPUT)

    mode = EnrichMode(event["enrich_mode"])
    result = build_report(
        _load_run(Path(inputs["run"]["path"])),
        suppressions=load_suppressions(
            Path(inputs["suppressions"]["path"]) if inputs.get("suppressions") else None
        ),
        as_of=dt.date.fromisoformat(event["as_of"]),
        enrich_mode=EnrichMode.CACHE_ONLY if mode is EnrichMode.LLM else mode,
        cache_dir=Path(inputs["cache_dir"]),
        baseline=_load_run(Path(inputs["baseline"]["path"])) if inputs.get("baseline") else None,
        max_llm_findings=inputs.get("max_llm_findings", 200),
    )
    mismatched = []
    for fmt, expected in sorted(event["outputs"].items()):
        actual = hashlib.sha256(render(result.report, fmt).encode("utf-8")).hexdigest()
        if actual != expected:
            mismatched.append(fmt)
    if mismatched:
        _err(f"MISMATCH for run {event['run_id']}: {', '.join(mismatched)} differ")
        raise typer.Exit(EXIT_INPUT)
    typer.echo(
        f"ok: run {event['run_id']} reproduced byte-for-byte "
        f"({', '.join(sorted(event['outputs']))})"
    )


def main() -> None:  # pragma: no cover
    sys.exit(app())
