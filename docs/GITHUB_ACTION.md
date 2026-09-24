# GitHub Action and pull-request annotations

**Status: Experimental.** The Action is implemented and locally tested, but it has not been run on a live hosted GitHub Actions runner.

The GitHub Action is the CI transport for Code Clearance. It is a thin wrapper
over the same application core the `code-clearance` CLI and the local MCP server
use: it calls `internal/app` to scan and `internal/policy` to decide the verdict,
then adds the two things CI needs and the other transports do not — annotations
scoped to changed lines and a SARIF report for code-scanning consumers. It never
reimplements scanning, normalization or policy evaluation, so the same recorded
evidence and configuration produce the same outcome through the CLI and through
the Action.

The Action is Docker-less and uploads no source code. It reads only the checkout
the calling workflow hands it and writes only the report paths it is configured
with.

## Usage

```yaml
name: Clearance

on:
  pull_request:

permissions:
  contents: read
  security-events: write # only needed to upload SARIF

jobs:
  code-clearance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # so the action can diff against the base ref

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      # The action builds its own entry point from this repository and runs it
      # against the checkout above.
      - uses: ./ # or your-org/code-clearance@<ref>
        id: clearance
        with:
          scope: full
          base-ref: ${{ github.event.pull_request.base.sha }}
          head-ref: ${{ github.sha }}
          changed-only: "true"

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.clearance.outputs.sarif-file }}
```

A required scanner that is unavailable on the runner produces `incomplete`, and
the step fails: a green badge earned by a missing tool is exactly the failure
this product exists to prevent. Move genuinely optional tools to
`adapters.optional` if they should not gate the check.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `target` | `.` | Checkout to analyse. |
| `scope` | `quick` | `quick`, `full` or `release`. |
| `config` | `""` | Explicit config path; otherwise discovered in the target. |
| `diff` | `""` | Unified diff file to scope annotations to (e.g. `gh pr diff`). |
| `base-ref` | `""` | Git base ref/sha to diff against when no diff file is given. |
| `head-ref` | `HEAD` | Git head ref/sha used with `base-ref`. |
| `changed-only` | `true` | Annotate only findings on changed lines when a diff is available. |
| `sarif-file` | `code-clearance.sarif` | SARIF output path. |
| `json-file` | `""` | Optional JSON report path. |
| `fail-on` | `blocked` | `blocked` (blocked and incomplete), `any` (also residual risk), or `never`. |
| `binary` | `""` | Prebuilt `code-clearance-action` binary; when empty the action builds one with Go. |

## Outputs

| Output | Meaning |
|---|---|
| `outcome` | `cleared`, `cleared-with-residual-risk`, `blocked` or `incomplete`. |
| `reason` | Why the outcome is what it is, naming missing required checks or blocking findings. |
| `sarif-file` | The SARIF file that was written. |
| `json-file` | The JSON report file that was written, if any. |
| `annotations` | Number of pull-request annotations emitted. |

## Annotations

Findings are emitted as GitHub workflow commands on the changed lines
(`::error file=...,line=...::...`), so a review sees the finding where the change
is. The check summary names the scope, the tools and versions that ran, the
coverage, the unavailable/crashed/timed-out checks and the residual risk, and
states how many findings were left unannotated because they fall outside the
change.

## Verify locally

Everything in this document is provable without a live GitHub Actions run:

```bash
go build ./...
go test ./internal/action/... ./cmd/... 
```

The named tests are:

- `TestCLIAndAction_ReachIdenticalPolicyOutcomeOnSameRecordedEvidence` — parity.
- `TestAction_AnnotationsScopedToChangedLines_UsingPRDiffFixture` — annotations.
- `TestAction_UnavailableRequiredScannerProducesIncompleteNotPass` — honesty.
- `TestAction_SARIFExportIsStructurallyValid` — SARIF output.
- `TestAction_RunOpensNoNetworkConnection` — no source upload.

To exercise the binary by hand against the fixture:

```bash
go build -o /tmp/code-clearance-action ./cmd/code-clearance-action
/tmp/code-clearance-action \
  --target . \
  --scope full \
  --diff testdata/action/pr.diff \
  --sarif-out /tmp/out.sarif
```

To verify the workflow itself on GitHub later, open a pull request that points
`uses:` at this repository and confirm the annotations appear on the changed
lines, the check summary is populated, and an unavailable required scanner makes
the step fail.
