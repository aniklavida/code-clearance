# Code Clearance dogfood run

**Status: Implemented and tested** as a local self-scan of commit `f2137fa6b704dcd34a9f76a8f8da7afa52ea2219` with a clean working tree. The result is published in full below, including unavailable checks, findings that block clearance and residual limitations. This is not a flattering subset and it is not a release gate.

## Command and target

```bash
go build -trimpath -o .git/code-clearance-card17 ./cmd/code-clearance
.git/code-clearance-card17 scan --scope full --json . > .git/card17-dogfood-report.json
```

The scan was run on 2026-09-25 at commit `f2137fa6b704dcd34a9f76a8f8da7afa52ea2219`. The target was clean and the report identified 149 files. No source or configuration was changed by the scan. Raw artifacts were written under the ignored `.clearance/` store.

## Result

```text
Outcome: blocked
Reason: 11 blocking finding(s) detected
```

The complete report contained 23 normalized findings:

| Severity | Count |
|---|---:|
| critical | 2 |
| high | 9 |
| medium | 11 |
| unknown | 1 |

By tool:

| Tool | Version | Status | Findings |
|---|---:|---|---:|
| Gitleaks | v8.30.1 | `ok-findings` | 2 |
| OSV-Scanner | v2.5.1 | `ok-findings` | 21 |
| Semgrep | v1.90.0 | `not-installed` | 0 |
| Trivy | v0.58.0 | `not-installed` | 0 |

The 11 blocking findings were the two critical Gitleaks findings and nine high OSV-Scanner findings. The remaining 12 findings were disclosed in the report but did not block under the default critical/high policy.

## Findings

The two Gitleaks findings were:

| Rule | Severity | Location | Meaning |
|---|---|---|---|
| `private-key` | critical | `internal/mcpserver/unattended_test.go` | Deliberate private-key-shaped material used by the real-process integration test. |
| `private-key` | critical | `scripts/demo.sh` | Deliberate private-key-shaped material used to seed the throwaway demo fixture. |

The 21 OSV-Scanner findings were:

| Rule | Severity | Package | Location |
|---|---|---|---|
| `CVE-2024-47081` | medium | `requests@2.25.0` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2024-35195` | medium | `requests@2.25.0` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2020-8203` | high | `lodash@4.17.15` | `testdata/fixture-repo/package-lock.json` and `testdata/fixtures/js-ts/package-lock.json` |
| `CVE-2025-13465` | medium | `lodash@4.17.15` | `testdata/fixture-repo/package-lock.json` and `testdata/fixtures/js-ts/package-lock.json` |
| `CVE-2026-27205` | medium | `flask@2.0.1` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2021-23337` | high | `lodash@4.17.15` | `testdata/fixture-repo/package-lock.json` and `testdata/fixtures/js-ts/package-lock.json` |
| `CVE-2024-37891` | medium | `urllib3@1.26.9` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2026-44431` | high | `urllib3@1.26.9` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2026-25645` | medium | `requests@2.25.0` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2025-50181` | medium | `urllib3@1.26.9` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2026-39824` | unknown | `golang.org/x/sys@0.41.0` | `go.mod` |
| `CVE-2025-66418` | high | `urllib3@1.26.9` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2024-3651` | high | `idna@2.9.0` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2026-45409` | medium | `idna@2.9.0` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2023-30861` | high | `flask@2.0.1` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2023-32681` | medium | `requests@2.25.0` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2025-66471` | high | `urllib3@1.26.9` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2026-21441` | high | `urllib3@1.26.9` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2023-45803` | medium | `urllib3@1.26.9` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2023-43804` | high | `urllib3@1.26.9` | `testdata/fixtures/python/requirements.txt` |
| `CVE-2020-28500` | medium | `lodash@4.17.15` | `testdata/fixture-repo/package-lock.json` and `testdata/fixtures/js-ts/package-lock.json` |

The report preserved the original OSV-Scanner native severity (`warning` in this run), normalized policy severity, advisory rule, package/version message, locations, raw SARIF artifact references and raw indices. It also preserved scanner stderr diagnostics, including OSV-Scanner's warning that its Go source-processing packages were built with Go 1.26 while the available `go list` was Go 1.27.

## Uncovered checks

The full report contained no skipped, crashed or timed-out checks. It contained these unavailable checks:

| Tool | Reason |
|---|---|
| Semgrep | `semgrep executable missing on PATH; install semgrep or move it from adapters.required to adapters.optional, then rerun` |
| Trivy | `trivy executable missing on PATH; install trivy or move it from adapters.required to adapters.optional, then rerun` |

They were not silently dropped. They were not treated as passes.

## Residual risk

The report's `residual_risk` array was empty. The findings were unreviewed, so no risk acceptance or human challenge was inferred from the blocked result. A later review could reject a deliberate test fixture finding or accept a time-bounded risk, but that would create new evidence and must not be backdated into this run.

## Honest limitations surfaced by the run

- **Experimental:** Semgrep and Trivy were not available, so this run does not claim static-analysis or Trivy coverage.
- **Experimental:** OSV-Scanner emitted a Go toolchain compatibility warning; its dependency evidence is still recorded, but the warning is part of the evidence boundary.
- **Experimental:** Quick metadata is not equivalent to per-adapter changed-file execution; the self-scan used Full scope, but the same target-level scanner limitation remains relevant to the architecture.
- **Experimental:** required repository-command failures are visible but are not independently policy-gated in the current evaluator.
- **Unsupported:** the scan does not claim zero bugs, complete vulnerability coverage, proof that every private-key-shaped fixture is harmless, or proof that every OSV advisory is exploitable in this repository.
- **Planned for v1.0:** a published cross-platform release, private vulnerability reporting path and independent human documentation walkthrough are not complete.

## Post-documentation branch check

After the documentation edits, the same full command was rerun against the feature branch. The target was still commit `f2137fa6b704dcd34a9f76a8f8da7afa52ea2219`, but the working tree was dirty with 155 files because the documentation changes themselves were uncommitted. The complete result was:

- **Outcome:** `blocked`
- **Reason:** `working tree has uncommitted modifications and allow_dirty is false`
- **Findings:** the same 23 normalized findings: 2 critical, 9 high, 11 medium and 1 unknown
- **Runs:** Gitleaks `ok-findings` with 2 findings; OSV-Scanner `ok-findings` with 21 findings; Semgrep and Trivy `not-installed`
- **Uncovered:** Semgrep and Trivy unavailable; no skipped, crashed or timed-out checks
- **Residual risk:** none

This second run is included so the published result does not imply that the edited branch was clean. The first clean run above remains the result used for the clean-commit snapshot.

The result is publishable because it is a real blocked result with complete disclosure, not because the repository is safe.
