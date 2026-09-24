# Code Clearance v1.0 release notes (draft)

**Status:** draft. Do not tag or publish until every box in
[`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) is ticked with named
evidence. This document describes what the code in this repository actually
does today; it does not claim the untested behaviour the product
specification still lists as planned.

## What this release is

Code Clearance is a local-first assurance layer for coding agents, developers
and CI. It orchestrates proven scanners as separate processes, normalizes and
correlates their findings, records a human or agent challenge verdict, verifies
fixes by rerunning the affected checks, and produces a commit-bound report that
states its own coverage and residual risk.

The one loop it implements end to end is:

```text
scan → normalize → correlate → challenge → fix → rescan/test → report
```

It is not a new scanner engine, and "cleared" never means "zero bugs."

## Platforms and artifacts

- macOS: `darwin/amd64`, `darwin/arm64`
- Linux: `linux/amd64`, `linux/arm64`
- Every artifact is published with a `checksums.txt` (sha256) and a GitHub
  build-provenance attestation.

Windows binaries are intentionally **not** part of this release tooling yet and
are listed as a pending checklist item. Do not describe this release as
cross-platform until that is done.

## Install and verify

Tagged binaries (once published) are the supported path:

```bash
# Download the artifact for your platform and checksums.txt, then:
sha256sum --check checksums.txt
gh attestation verify code-clearance_v1.0.0_linux_amd64 --repo aniklavida/code-clearance
install -m 0755 code-clearance_v1.0.0_linux_amd64 ~/.local/bin/code-clearance
```

`scripts/install.sh` automates the download and refuses to install a binary
whose sha256 does not match the published checksum. A Homebrew formula template
lives at `packaging/homebrew/code-clearance.rb`; it has not been published to
any tap.

If you build from source instead:

```bash
go install github.com/aniklavida/code-clearance/cmd/code-clearance@latest
```

A `go install` build carries no release version, checksum or signature, and
`code-clearance version` says so rather than implying otherwise.

## What v1.0 delivers

### One core, three entry points

- CLI: `init`, `doctor`, `mcp`, `run`, `report`, `scan`, `record-review`,
  `verify`, `fix-context`, `findings`, `serve`, `version`.
- Local stdio MCP server exposing `run_clearance_scan` / `clearance_scan`,
  `clearance_run`, `clearance_report`, `clearance_get_findings`,
  `clearance_record_review`, `clearance_get_fix_context` and `clearance_verify`.
- The same application core backs both; `TestEntryPoints_ReachIdenticalResultsThroughCore`
  and `TestTerminalAndJSONReportsAgreeOnOutcomeCoverageAndUncovered` assert the
  entry points agree.

### Modes

| Mode | Scope | Outcome behaviour |
|---|---|---|
| Quick | Changed files (dirty tree, base-commit diff, or `HEAD~1`) | Evaluated against the quick profile |
| Full | All tracked and untracked files | Evaluated against the full profile |
| Release | Full checks plus strict policy/provenance | Blocks configured confirmed findings and failed required commands |

Scope resolution is covered by `TestScopePlanner_QuickDirtyTree_RecordsExactFilesCommitFingerprint`
and `TestScopePlanner_FullScope_RecordsAllFiles`.

### Adapters

Four adapters run as separate processes. None of their code is compiled into
the binary:

| Adapter | Capability | Pinned version | Exercised end to end here |
|---|---|---|---|
| Gitleaks | secrets | v8.30.1 | yes |
| OSV-Scanner | dependency vulnerabilities | v2.5.1 | yes |
| Semgrep Community Edition | static patterns | v1.90.0 | not in this environment |
| Trivy | dependency, filesystem, container and IaC | v0.58.0 | not in this environment |

An unavailable required adapter produces `incomplete`, never a pass, and the
report names the missing check
(`TestConstraint1_UnavailableRequiredAdapterMustProduceIncompleteNeverPass`,
`TestEngine_MissingRequiredScannerProducesIncompleteNotSilence`).

### Challenge, fix, verification and policy

- Challenge states: `unreviewed`, `confirmed`, `rejected`, `accepted-risk`,
  `fixed`, `unresolved`.
- A finding can only become `fixed` through new recorded evidence from a
  verification rerun; asserting it fixed changes nothing
  (`TestEnforceFindingBecomesFixedOnlyThroughVerificationRunEvidence`,
  `TestEnforceCannotMarkFixedWithoutRerun_CLI`,
  `TestEnforceCannotMarkFixedWithoutRerun_MCP`).
- Fix context is limited to one finding's evidence and constraints
  (`TestGetFixContext_ReturnsOnlyRequestedFindingEvidenceAndConstraints`).
- Risk acceptance carries a reason, an owner and an expiry; expired acceptance
  reverts to blocking (`TestAcceptedRisk_MatchesAfterUnrelatedEdit`).
- `human_required_classes` prevents an agent or tool reviewer from clearing
  matching findings without a human (`TestConstraint4_HumanRequiredClassesCannotBeClearedByAgent`).

### Evidence and trust properties

- Raw scanner output is retained after normalization and referenced from every
  finding; redaction happens at the normalization boundary
  (`TestSecretRedaction_ScannerOutputReportAndMCPPayload`).
- Fingerprints are deterministic and stable across unrelated line edits
  (`TestFingerprint_DeterministicAcrossRuns`, `TestFingerprint_StableAcrossLineInsertion`).
- Identical evidence and configuration produce byte-identical verdicts,
  independent of run order
  (`TestConstraint3_IdenticalRecordedEvidenceEvaluatedRepeatedlyProducesIdenticalVerdict`,
  `TestConstraint3_UncoveredOrderingIsIndependentOfRunOrder`).
- Repository-defined commands must be on an allowlist and never reach a shell
  (`TestHostileClearanceConfig_CommandsNeverReachShell`,
  `TestCommands_UntrustedInput_HostileValuesRejectedOrInert`).
- No network access under default configuration
  (`TestDefaultScan_OpensNoNetworkConnection`).

## Demo

`scripts/demo.sh` runs the real loop against a throwaway copy of
`testdata/fixtures/go` and prints the four beats in the locked order:
a confirmed issue, a rejected false positive, a verified fix, then residual
risk. See [`docs/DEMO.md`](DEMO.md).

## Explicitly not in v1.0

- Windows binaries.
- GitHub Action and pull-request annotations.
- Local HTML reports (terminal, JSON and SARIF export exist today).
- Baselines (risk acceptance with expiry exists; named baselines do not).
- The optional OpenSSF Scorecard adapter.
- Real-process verification of the Semgrep and Trivy adapters in this
  environment (their adapter tests exist but skip where the binaries are
  absent).
- A published Homebrew tap or any other package-manager registry.
- A built or tested Docker image.

## Scope, coverage and residual risk

The product promise is that a clearance result discloses what it did and did
not check. This is not a claim of universal language or bug coverage, and it is
not a claim that no bugs remain. When a required check is unavailable, crashed
or times out, the result is `incomplete`; when findings are accepted as
residual risk, the result says so and names the accepting owner and expiry.

## Cutting the release

The tag is a human action. After every checklist box is ticked:

```bash
git tag -a v1.0.0 -m "Code Clearance v1.0.0"
git push origin v1.0.0
```

Pushing the tag triggers `.github/workflows/release.yml`, which verifies the
tagged commit, builds the four binaries, writes `checksums.txt`, attests build
provenance, and creates the GitHub Release. Nothing in this repository creates
the tag automatically.
