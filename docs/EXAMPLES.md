# Worked examples

**Status: Implemented and tested** for the fixture inputs, parser tests and the real scanner runs captured below. The examples use the real Code Clearance CLI and the installed Gitleaks v8.30.1 and OSV-Scanner v2.5.1 binaries. Semgrep and Trivy were unavailable, so their rows are included as disclosed non-passing runs rather than invented output.

The raw reports were generated on 2026-09-25 against commit `f2137fa6b704dcd34a9f76a8f8da7afa52ea2219` with a clean working tree. Advisory database contents can change, so the package and finding counts are a recorded observation, not a permanent benchmark or guarantee.

## Run the examples

From the repository root:

```bash
code-clearance scan --scope full --json testdata/fixtures/js-ts
code-clearance scan --scope full --json testdata/fixtures/python
code-clearance scan --scope full --json testdata/fixtures/go
```

A finding-producing run exits nonzero by design. Inspect the JSON report and its `outcome`, `runs`, `uncovered` and `residual_risk` fields rather than treating a nonzero exit code as a crash.

## JavaScript/TypeScript

Fixture: [`testdata/fixtures/js-ts`](../testdata/fixtures/js-ts)

The fixture contains a JavaScript entry point, a TypeScript source file and a lockfile pinning `lodash@4.17.15`. The lockfile is scanner evidence and is not intended to be installed with `npm ci`; the generated project command is not used for this example.

Real Code Clearance result:

```text
Outcome: blocked
Reason: 2 blocking finding(s) detected: 2b782ebb092719ba, f387c7df799cff10
```

Runs recorded in the JSON report:

| Tool | Version | Status | Findings |
|---|---:|---|---:|
| Gitleaks | v8.30.1 | `ok` | 0 |
| OSV-Scanner | v2.5.1 | `ok-findings` | 4 |
| Semgrep | v1.90.0 | `not-installed` | 0 |
| Trivy | v0.58.0 | `not-installed` | 0 |

The four normalized OSV-Scanner findings include two high and two medium findings for the pinned `lodash@4.17.15` dependency. The report keeps the rule ID, package/version message, source location, raw SARIF artifact and the original `warning` native severity. The full output, including the exact advisory IDs present at capture time, is the report produced by the command above; it is not replaced by a hand-written sample.

The missing Semgrep and Trivy binaries are listed under `uncovered.unavailable`; they are not reported as passes. The fixture does not have an npm test script, so this example does not claim a passing JavaScript test command.

## Python

Fixture: [`testdata/fixtures/python`](../testdata/fixtures/python)

The fixture contains `main.py` and a requirements file with historical direct dependencies `requests==2.25.0` and `flask==2.0.1`. The source does not import those packages, and the fixture does not include a pytest test, so this example demonstrates dependency evidence rather than a passing Python test suite.

Real Code Clearance result:

```text
Outcome: blocked
Reason: 7 blocking finding(s) detected: 758cda7a6353670e, 932d7765acb64e37, 9c119b0999e43575, bff307ec9fc11ed2, d85f1a7dccb425d7, db4b45dd725c4b3a, ee1e7c5106323da4
```

Runs recorded in the JSON report:

| Tool | Version | Status | Findings |
|---|---:|---|---:|
| Gitleaks | v8.30.1 | `ok` | 0 |
| OSV-Scanner | v2.5.1 | `ok-findings` | 16 |
| Semgrep | v1.90.0 | `not-installed` | 0 |
| Trivy | v0.58.0 | `not-installed` | 0 |

The 16 normalized findings were seven high and nine medium. The report names the affected requirements file and retains raw SARIF evidence. The exact advisory set is point-in-time scanner output and may grow or change as the database changes.

The report also discloses that no Python test command was established for this fixture. This is an honest limitation of the example, not a fabricated passing result.

## Go

Fixture: [`testdata/fixtures/go`](../testdata/fixtures/go)

The fixture is a small standard-library-only module. Its `go test ./...` command is runnable, and it has no third-party dependency in `go.mod`.

Real Code Clearance result:

```text
Outcome: cleared
Reason: all required checks passed with zero blocking findings
```

Runs recorded in the JSON report:

| Tool | Version | Status | Findings |
|---|---:|---|---:|
| Gitleaks | v8.30.1 | `ok` | 0 |
| OSV-Scanner | v2.5.1 | `ok` | 0 |
| Semgrep | v1.90.0 | `not-installed` | 0 |
| Trivy | v0.58.0 | `not-installed` | 0 |

The missing optional scanners remain under `uncovered.unavailable`. The cleared result is limited to the configured checks and the standard-library-only fixture. It does not prove that arbitrary Go code has no bugs or vulnerabilities.

The repository command evidence can be reproduced independently:

```bash
(cd testdata/fixtures/go && go test ./...)
```

## Reading the real evidence

For any example, start with:

```bash
code-clearance scan --scope full --json testdata/fixtures/<language> > report.json
```

Then inspect:

- `target.commit` and `target.dirty` to identify the scanned state;
- `runs[].tool`, `tool_version`, `status`, `command` and `raw_artifact` for execution truth;
- `findings[]` for normalized evidence and `native_severity` for source detail;
- `uncovered` for skipped, crashed, timed-out and unavailable checks;
- `residual_risk` for explicit accepted risk;
- `reason` for the policy outcome.

The checked-in parser fixtures under [`internal/normalize/testdata`](../internal/normalize/testdata) make the parser behavior reproducible without requiring live advisory data. A live scan is intentionally separate from parser fixture tests.
