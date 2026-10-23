from __future__ import annotations

from pathlib import Path

from conftest import raw, write

from triage.fingerprint import fingerprint_all, mask_secret_line, normalize_code
from triage.model import Kind, Package, RawFinding
from triage.source import SourceTree, normalize_path

APP = """\
const db = require('db')

app.get('/u', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id)
})
"""


def fp(root: Path, *findings: RawFinding) -> list[str]:
    return [f.fingerprint for f in fingerprint_all(findings, SourceTree(root))]


def test_survives_lines_inserted_above(tmp_path: Path) -> None:
    write(tmp_path / "a", "app.js", APP)
    write(tmp_path / "b", "app.js", "// header\n" * 25 + APP)
    before = fp(tmp_path / "a", raw(line=4))
    after = fp(tmp_path / "b", raw(line=29))
    assert before == after


def test_survives_rewrapping(tmp_path: Path) -> None:
    wrapped = APP.replace(
        'db.query("SELECT * FROM users WHERE id = " + req.query.id)',
        'db.query(\n    "SELECT * FROM users WHERE id = " +\n    req.query.id\n  )',
    )
    write(tmp_path / "a", "app.js", APP)
    write(tmp_path / "b", "app.js", wrapped)
    # Semgrep reports the whole expression, so the region grows with the wrapping.
    assert fp(tmp_path / "a", raw(line=4)) == fp(tmp_path / "b", raw(line=4, end=7))


def test_survives_reformatting(tmp_path: Path) -> None:
    reformatted = APP.replace('  db.query("SELECT', '\t\t db.query(  "SELECT').replace(
        "\n\napp", "\n\n\n\napp"
    )
    write(tmp_path / "a", "app.js", APP)
    write(tmp_path / "b", "app.js", reformatted)
    assert fp(tmp_path / "a", raw(line=4)) == fp(tmp_path / "b", raw(line=6))


def test_survives_unrelated_edit_in_same_file(tmp_path: Path) -> None:
    write(tmp_path / "a", "app.js", APP)
    write(tmp_path / "b", "app.js", APP.replace("require('db')", "require('./db')"))
    assert fp(tmp_path / "a", raw(line=4)) == fp(tmp_path / "b", raw(line=4))


def test_changes_when_flagged_code_changes(tmp_path: Path) -> None:
    write(tmp_path / "a", "app.js", APP)
    write(tmp_path / "b", "app.js", APP.replace("req.query.id", "req.params.id"))
    assert fp(tmp_path / "a", raw(line=4)) != fp(tmp_path / "b", raw(line=4))


def test_changes_with_rule_or_path(tmp_path: Path) -> None:
    write(tmp_path, "app.js", APP)
    write(tmp_path, "other.js", APP)
    a, b, c = fp(tmp_path, raw(line=4), raw(line=4, rule="js.other"), raw(line=4, path="other.js"))
    assert len({a, b, c}) == 3


def test_identical_snippets_get_distinct_stable_ids(tmp_path: Path) -> None:
    body = "x = eval(input)\n"
    write(tmp_path / "a", "m.py", body + "pass\n" + body)
    write(tmp_path / "b", "m.py", body + "pass\n" * 10 + body)
    first = fp(tmp_path / "a", raw(path="m.py", line=1), raw(path="m.py", line=3))
    second = fp(tmp_path / "b", raw(path="m.py", line=1), raw(path="m.py", line=12))
    assert first[0] != first[1]
    assert first == second


def test_independent_of_input_order(tmp_path: Path) -> None:
    write(tmp_path, "m.py", "x = eval(a)\nx = eval(a)\n")
    a, b = raw(path="m.py", line=1), raw(path="m.py", line=2)
    assert fp(tmp_path, a, b) == list(reversed(fp(tmp_path, b, a)))


def test_dependency_ignores_lines(tmp_path: Path) -> None:
    pkg = Package(name="lodash", version="4.17.20", fixed_version="4.17.21", ecosystem="npm")
    common = {"scanner": "trivy", "rule": "CVE-2021-23337", "kind": Kind.DEPENDENCY}
    a = fp(tmp_path, raw(**common, path="package-lock.json", line=10, package=pkg))
    b = fp(tmp_path, raw(**common, path="package-lock.json", line=900, package=pkg))
    upgraded = pkg.model_copy(update={"version": "4.17.21"})
    c = fp(tmp_path, raw(**common, path="package-lock.json", line=10, package=upgraded))
    assert a == b
    assert a != c


def test_secret_value_never_in_fingerprint_input(tmp_path: Path) -> None:
    # Assembled at runtime so secret scanners run on this repository stay quiet.
    secret_a = "".join(["AKIA", "Z7Q2X4M9", "EXAMPLEAAA1"])
    secret_b = "".join(["AKIA", "B3N8R1T5", "ROTATEDBBB2"])
    line = 'const key = "{}"\n'
    write(tmp_path / "a", "cfg.js", line.format(secret_a))
    write(tmp_path / "b", "cfg.js", line.format(secret_b))
    finding = raw(
        scanner="gitleaks", rule="aws-access-token", kind=Kind.SECRET, path="cfg.js", line=1
    )
    [fa] = fingerprint_all([finding], SourceTree(tmp_path / "a"))
    [fb] = fingerprint_all([finding], SourceTree(tmp_path / "b"))
    assert secret_a not in fa.snippet + fa.context
    assert "<SECRET>" in fa.snippet
    # Rotating the value in place keeps the identity: it is the same exposure point.
    assert fa.fingerprint == fb.fingerprint


def test_mask_secret_line_uses_columns_and_token_shape() -> None:
    assert mask_secret_line("token=abc", 7, 9) == "token=<SECRET>"
    unquoted = mask_secret_line("password: s3cr3tValueThatIsLong_1234")
    assert "s3cr3t" not in unquoted
    assert "hunter2xx" not in mask_secret_line("pw = 'hunter2xx'")


def test_code_finding_in_credential_file_is_masked(tmp_path: Path) -> None:
    token = "".join(["npm_", "Zq8vN2pL7xR4tY6wB1mK9cH3dF5gJ0"])
    write(tmp_path, ".npmrc", f"//registry.npmjs.org/:_authToken={token}\n")
    [f] = fingerprint_all([raw(path=".npmrc", line=1, rule="npm.config")], SourceTree(tmp_path))
    assert token not in f.snippet + f.context


def test_pem_armor_is_rewritten() -> None:
    armor = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
    assert mask_secret_line(armor) == "[begin rsa private key]"


def test_normalize_code_is_whitespace_insensitive_only() -> None:
    assert normalize_code("  a  =  1\n\n\tb = 2  ") == "a = 1\nb = 2"
    assert normalize_code("a = 1") != normalize_code("a = 2")


def test_paths_outside_root_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    assert normalize_path("../../etc/passwd", root) is None
    assert normalize_path("/etc/passwd", root) is None
    assert normalize_path("src/a.py", root) == "src/a.py"
    assert normalize_path(f"file://{root}/src/a.py", root) == "src/a.py"
