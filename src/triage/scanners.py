"""Runs the scanners. Each writes its report to a file that is then read by ingest/.

Commands are argument lists (never a shell string) and every scanner runs with telemetry off
where it has a switch for it. Gitleaks always runs with --redact so the secret value never
reaches disk.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


class ScannerError(Exception):
    pass


@dataclass(frozen=True)
class Scanner:
    name: str
    binary: str
    output_name: str

    def command(self, root: Path, output: Path, options: dict[str, str]) -> list[str]:
        if self.name == "semgrep":
            return [
                self.binary,
                "scan",
                "--config",
                options.get("semgrep_config", "p/default"),
                "--metrics=off",
                "--quiet",
                "--sarif",
                "--output",
                str(output),
                str(root),
            ]
        if self.name == "trivy":
            cmd = [self.binary, "fs", "--quiet", "--scanners", "vuln,secret,misconfig"]
            for flag, key in (
                ("--db-repository", "trivy_db_repository"),
                ("--checks-bundle-repository", "trivy_checks_repository"),
            ):
                if options.get(key):
                    cmd += [flag, options[key]]
            return [*cmd, "--format", "sarif", "--output", str(output), str(root)]
        if self.name == "gitleaks":
            return [
                self.binary,
                "dir",
                str(root),
                "--redact",
                "--no-banner",
                "--exit-code",
                "0",
                "--report-format",
                "json",
                "--report-path",
                str(output),
            ]
        raise ScannerError(f"unknown scanner {self.name}")


SCANNERS = {
    "semgrep": Scanner("semgrep", "semgrep", "semgrep.sarif"),
    "trivy": Scanner("trivy", "trivy", "trivy.sarif"),
    "gitleaks": Scanner("gitleaks", "gitleaks", "gitleaks.json"),
}


@dataclass(frozen=True)
class ScanOutput:
    scanner: str
    path: Path
    seconds: float


def run_scanner(
    name: str, root: Path, out_dir: Path, options: dict[str, str], timeout: int = 1800
) -> ScanOutput:
    scanner = SCANNERS[name]
    if shutil.which(scanner.binary) is None:
        raise ScannerError(f"{name}: '{scanner.binary}' not found on PATH")
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / scanner.output_name
    output.unlink(missing_ok=True)  # a stale report must not pass for this run's
    started = time.monotonic()
    try:
        proc = subprocess.run(
            scanner.command(root, output, options),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{name}: timed out after {timeout}s") from exc
    # Semgrep exits 1 when it has findings; the report file is the success signal.
    if not output.exists():
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-5:]
        raise ScannerError(
            f"{name}: exit {proc.returncode}, no report written: " + " / ".join(tail)
        )
    return ScanOutput(name, output, time.monotonic() - started)


def git_commit(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() or None if proc.returncode == 0 else None
