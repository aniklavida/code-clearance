# Version 1.0 release checklist

State of this checklist after the `v1-release-tooling` change (2026-09-24).
A box is ticked only where a named piece of evidence exists in this repository.
Unticked boxes state exactly what is missing. Nothing here was tagged,
published, or run through Docker in this change; see the notes on the boxes
that depend on that.

## Product

- [x] Quick, Full and Release modes behave as documented.
  Evidence: `TestScopePlanner_QuickDirtyTree_RecordsExactFilesCommitFingerprint`,
  `TestScopePlanner_FullScope_RecordsAllFiles`,
  `TestEngine_DirtyTreeWithAllowDirtyFalseProducesBlockedNeverPass`,
  `TestUnattendedAgentLoopReal` (release profile), all passing via `go test ./...`.

- [x] Known limitations and residual-risk semantics are explicit.
  Evidence: `docs/SPEC.md` ("Cleared never means zero bugs"),
  `docs/RELEASE_NOTES_v1.0.md` (Explicitly not in v1.0 / Scope, coverage and
  residual risk), `docs/DEMO.md` beat 4,
  `TestAcceptedRisk_MatchesAfterUnrelatedEdit`, `TestConstraint1_...`.

- [ ] Every item in `docs/SPEC.md` release acceptance passes.
  Missing: the GitHub Action is now implemented and its CLI/Action parity is
  locally proven, but it has never been run on a live GitHub Actions runner,
  and the cross-platform clean-install acceptance items remain unverified; see
  the specific boxes below. Not a statement about the implemented core, which
  is covered elsewhere.

## Verification

- [x] Unit, parser-fixture, integration and end-to-end tests pass.
  Evidence: `go build ./... && go vet ./... && go test ./...` pass on
  darwin/arm64 (2026-09-24) and are run for ubuntu/macos/windows by
  `.github/workflows/validate.yml`. Note: the Semgrep and Trivy real-process
  tests skip where those binaries are absent; they are not in the CI
  skipped-test guard, which covers Gitleaks and OSV-Scanner.

- [ ] Clean Linux, macOS and Windows installation walkthroughs pass.
  Missing: no release is published yet and no clean-machine walkthrough was
  performed. `scripts/install.sh` and the release workflow are prepared but
  unexercised.

- [x] CLI, MCP and GitHub Action policy parity is verified.
  Evidence: CLI/MCP parity is covered by
  `TestEntryPoints_ReachIdenticalResultsThroughCore`; CLI/Action parity is
  covered by
  `TestCLIAndAction_ReachIdenticalPolicyOutcomeOnSameRecordedEvidence`, which
  runs both transports against the same recorded evidence and configuration and
  asserts identical outcome, reason and finding set. The GitHub Action exists as
  `action.yml` backed by `cmd/code-clearance-action`, calling the same
  `internal/app` core. This parity is proven with local tests only: the Action
  has not been triggered on a live GitHub Actions runner in this change. Steps
  to verify live later are in `docs/GITHUB_ACTION.md`.

- [x] Code Clearance successfully evaluates its own repository.
  Evidence: `code-clearance scan --scope full --json .` was run on a clean
  build and its report validated against `schemas/report.schema.json`. The run
  returned `blocked` and named the test-fixture secrets and vulnerable
  fixtures it found in this repository — an honest result, not a clean pass.
  This dogfooding surfaced three schema-contract defects (null link arrays,
  null run findings, and the over-broad "any unavailable check is incomplete"
  rule); all are fixed and covered by
  `TestCorrelateReport_SingleFindingHasNonNilLinkArrays`,
  `TestConstraint1_UnavailableRequiredAdapterMustProduceIncompleteNeverPass`,
  and the corrected `schemas/COMPATIBILITY.md` invariant.

## Trust and legal

- [x] Public licence is approved and present.
  Evidence: `LICENSE` (MIT, Copyright (c) 2026 Md Habibur Rahman), referenced
  by `THIRD_PARTY_NOTICES.md`.

- [x] Every reused/adapted component has an exact source, commit and licence record.
  Evidence: `THIRD_PARTY_NOTICES.md` records each external scanner CLI and each
  compiled Go module at the exact version in `go.mod`/`go.sum`;
  `go mod verify` reports all modules verified; `go version -m` on a
  freshly built binary lists exactly those modules. No engine source is copied
  or adapted (adapters invoke external CLIs).

- [x] Third-party notices and required copyright text are published.
  Evidence: `THIRD_PARTY_NOTICES.md`, re-verified against the module set in
  this change.

- [ ] Security policy and private reporting path work.
  Missing: `SECURITY.md` exists but states the private reporting address or
  GitHub private vulnerability-reporting workflow "will be added before the
  first public release". That path does not work yet.

- [ ] Release binaries have checksums and provenance/signing where supported.
  Missing: `.github/workflows/release.yml` generates `checksums.txt` (sha256)
  and attests build provenance via `actions/attest-build-provenance`, but no
  tag was pushed, no binary was built by CI, and nothing was published. This
  is deliberate for this change.

## Launch readiness

- [ ] README five-minute quick start works from a clean machine.
  Missing: the steps and `TestOnboarding_CleanStateSequence_InitDoctorMCPScan`
  exist, but no clean-machine run was performed.

- [x] Demo shows confirmation, false-positive rejection, verified fix and residual risk.
  Evidence: `scripts/demo.sh` ran successfully (2026-09-24) and printed the four
  beats in the locked order; `docs/DEMO.md` documents it. Residual risk is
  shown as an accepted risk with owner and expiry.

- [x] Examples cover JavaScript/TypeScript, Python and Go.
  Evidence: `testdata/fixtures/js-ts/` (JavaScript/TypeScript),
  `testdata/fixtures/python/` (Python), `testdata/fixtures/go/` (Go). The demo
  seeds from the Go fixture; the others are used by discovery/adapter fixtures.

- [x] Changelog and release notes are complete.
  Evidence: `CHANGELOG.md` is brought up to date against `git log` through the
  `v1-release-tooling` change; `docs/RELEASE_NOTES_v1.0.md` describes the real,
  tested feature set and its gaps. The release notes are marked a draft until
  every remaining box here is ticked.

- [ ] Contributor starter issues are prepared.
  Missing: out of scope for this change; no starter issues were created.

- [x] Marketing claims match tested behavior.
  Evidence: `docs/RELEASE_NOTES_v1.0.md` states scope, untested adapters,
  unverified platforms and an explicit "not in v1.0" list, and makes no
  "zero bugs" claim. `README.md` continues to mark unpublished behaviour as
  planned.
