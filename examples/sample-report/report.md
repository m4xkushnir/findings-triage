# Security findings triage: gin

Commit `0f09c3a9b4626d9fe9979cf4d0521d6ae32ab646`, as of 2026-10-23, scanners: gitleaks, semgrep, trivy, enrichment: heuristic.

| Stage | Count |
|---|---|
| Raw scanner results | 50 |
| After dedup | 49 |
| of which merged across scanners | 1 |
| Suppressed | 17 |
| Review | 23 |
| **Actionable** | **9** |

Actionable by severity: high: 1, medium: 8.

## Actionable (9)

| Severity | Kind | Location | Finding | Why |
|---|---|---|---|---|
| high | dependency | `go.mod:1` | CVE-2026-78669 in golang.org/x/net v0.57.0 -> 0.60.0 | golang.org/x/net v0.57.0 is affected; upgrading to 0.60.0 fixes it. |
| medium | code | `.github/dependabot.yml:3-6` | This Dependabot configuration does not set a cooldown period. | Matched in shipped code; exploitability needs a reviewer or the LLM pass. |
| medium | code | `.github/dependabot.yml:7-14` | This Dependabot configuration does not set a cooldown period. | Matched in shipped code; exploitability needs a reviewer or the LLM pass. |
| medium | code | `context.go:1162-1171` | A session cookie was detected without setting the 'HttpOnly' flag. | Matched in shipped code; exploitability needs a reviewer or the LLM pass. |
| medium | code | `context.go:1162-1171` | A session cookie was detected without setting the 'Secure' flag. | Matched in shipped code; exploitability needs a reviewer or the LLM pass. |
| medium | dependency | `go.mod:1` | CVE-2026-78660 in golang.org/x/net v0.57.0 -> 0.60.0 | golang.org/x/net v0.57.0 is affected; upgrading to 0.60.0 fixes it. |
| medium | dependency | `go.mod:1` | CVE-2026-97032 in golang.org/x/net v0.57.0 -> 0.60.0 | golang.org/x/net v0.57.0 is affected; upgrading to 0.60.0 fixes it. |
| medium | dependency | `go.mod:1` | CVE-2026-78659 in golang.org/x/net v0.57.0 -> 0.60.0 | golang.org/x/net v0.57.0 is affected; upgrading to 0.60.0 fixes it. |
| medium | dependency | `go.mod:1` | CVE-2026-78663 in golang.org/x/net v0.57.0 -> 0.60.0 | golang.org/x/net v0.57.0 is affected; upgrading to 0.60.0 fixes it. |

<details>
<summary>Review (23)</summary>

| Severity | Kind | Location | Finding | Why |
|---|---|---|---|---|
| low (was high) | secret | `context_test.go:654` | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | Credential lives in test files; confirm it is not valid anywhere before closing. |
| low (was high) | secret | `context_test.go:662` | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | Credential lives in test files; confirm it is not valid anywhere before closing. |
| low (was high) | secret | `context_test.go:3131` | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | Credential lives in test files; confirm it is not valid anywhere before closing. |
| low (was medium) | code | `render/bson.go:26` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/data.go:24` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:73` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:84` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:103` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:107` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:125` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:130` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:134` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:138` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:142` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/json.go:174` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/pdf.go:19` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/protobuf.go:29` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/text.go:36` | Detected 'Fprintf' or similar writing to 'http.ResponseWriter'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/text.go:39` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/toml.go:29` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was medium) | code | `render/yaml.go:29` | Detected directly writing or similar in 'http.ResponseWriter.write()'. | The rule's author labels it low-confidence (expect false positives); demoted one level until a reviewer or the LLM pass confirms it. |
| low (was high) | secret | `testdata/certificate/key.pem:1-27` | Identified a Private Key, which may compromise cryptographic security and sensitive data encryption. | Credential lives in test files; confirm it is not valid anywhere before closing. |
| info | dependency | `go.mod:1` | GO-2026-5932 in golang.org/x/crypto v0.56.0 (no fix) | No fixed version is published; reachability of the vulnerable code is unknown. |

</details>

<details>
<summary>Suppressed (17)</summary>

| Severity | Kind | Location | Finding | Why |
|---|---|---|---|---|
| medium | config | `.github/workflows/codeql.yml:36` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/codeql.yml:40` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/codeql.yml:49` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/gin.yml:19` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/gin.yml:23` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/gin.yml:27` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/gin.yml:61` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/gin.yml:67` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/gin.yml:71` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/gin.yml:84` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/goreleaser.yml:16` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/goreleaser.yml:20` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/goreleaser.yml:24` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/trivy-scan.yml:25` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/trivy-scan.yml:30` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/trivy-scan.yml:41` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |
| medium | config | `.github/workflows/trivy-scan.yml:47` | GitHub Actions step uses a mutable tag or branch reference. | GIN-001 by eval, until 2027-01-31: CI-only exposure. Accepted until the workflows are migrated to SHA pins; the expiry forces the decision to be revisited. |

</details>

---
findings-triage 0.1.0, fingerprint v1, triage-prompt/v1, heuristic:v2
