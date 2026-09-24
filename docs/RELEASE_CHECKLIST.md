# Version 1.0 release checklist

Status vocabulary is **Implemented and tested**, **Experimental**, **Planned for v1.0** and **Unsupported**. A box is checked only when named evidence exists in this repository. This checklist is not a release announcement.

## Product and evidence

- [x] **Implemented and tested:** core scan, normalization, raw artifact retention, correlation, deterministic policy, review, fix verification and report persistence.
  Evidence: `go test ./...`; `TestUnattendedAgentLoopReal`; schema, policy, store, report and redaction tests.

- [x] **Implemented and tested:** Gitleaks and OSV-Scanner real-process adapters and parser fixtures.
  Evidence: `TestGitleaks_RealProcess_FindsFixtureSecrets`, `TestOSVScanner_RealProcess_FindsVulnerableLockfile`, raw-artifact and timeout tests.

- [ ] **Experimental:** Semgrep and Trivy real-process verification.
  Missing: the binaries were unavailable in the recorded run. Their parser fixtures and adapter failure tests exist, but that is not the same as real-process evidence.

- [x] **Implemented and tested:** source-build five-minute quick start.
  Evidence: the README sequence was run against a clean disposable Git fixture; approved init, doctor and `run --preset individual` completed and printed `Outcome: cleared`.

- [x] **Implemented and tested:** public architecture, configuration, policy, adapter and report-schema documentation.
  Evidence: `docs/ARCHITECTURE.md`, `docs/CONFIGURATION.md`, `docs/POLICY.md`, `docs/ADAPTER_GUIDE.md` and `docs/REPORT_SCHEMA.md`.

- [x] **Implemented and tested:** JavaScript/TypeScript, Python and Go worked examples use checked-in fixtures and real scanner reports.
  Evidence: `docs/EXAMPLES.md` and the recorded fixture runs. Semgrep and Trivy unavailable states are disclosed.

- [x] **Implemented and tested:** Code Clearance scanned its own repository and the complete result is published.
  Evidence: `docs/DOGFOOD.md` records commit `f2137fa6b704dcd34a9f76a8f8da7afa52ea2219`, 149 files, `blocked`, 23 findings, 11 blocking findings, two unavailable scanners, empty residual risk and the OSV toolchain warning.

## Remaining acceptance work

- [ ] **Planned for v1.0:** all specification release acceptance criteria pass.
  Missing: clean Linux/macOS/Windows installation walkthroughs, live GitHub Action execution, published release evidence and a working private security-reporting path.

- [ ] **Planned for v1.0:** independent documentation walkthrough by a person who did not write the instructions.
  Pending: this requires an uninvolved human. The self-authored quick-start run is useful evidence but is not independent acceptance.

- [ ] **Experimental:** fully affected Quick execution.
  Missing: scope planning resolves changed files, but registered scanners still receive the repository directory. `TargetFiles` is not consumed by the production scan.

- [ ] **Experimental:** required repository-command policy gating.
  Missing: command crashes/timeouts are recorded as non-passing runs, but the evaluator's required-adapter check does not independently block a required command failure.

- [ ] **Experimental:** clean Linux, macOS and Windows release walkthroughs.
  Missing: no release is published and no clean-machine walkthrough was performed for all three platforms.

- [ ] **Experimental:** live GitHub Action verification.
  Missing: local Action tests pass, but the Action has not been triggered on a live hosted runner.

- [ ] **Unsupported:** runtime third-party scanner plugin loading.
  Missing by design: adapters are compiled into the binary. This is not a v1.0 acceptance gap.

## Trust and legal

- [x] **Implemented and tested:** public MIT licence is present.
  Evidence: `LICENSE`.

- [x] **Implemented and tested:** third-party notices and module verification exist.
  Evidence: `THIRD_PARTY_NOTICES.md`, `go mod verify` and `go version -m` on a fresh local build.

- [ ] **Planned for v1.0:** private security reporting works.
  Missing: `SECURITY.md` says the private path is planned; no working address or private vulnerability workflow is published.

- [ ] **Planned for v1.0:** release artifacts have published checksums and provenance.
  Missing: the workflow can generate checksums and build provenance, but no tag, CI release or downloadable artifact exists yet.

- [ ] **Unsupported:** artifact/report signing.
  Missing by design: no signing implementation is present. The release checklist does not treat build provenance as artifact signing.

## Launch readiness

- [x] **Implemented and tested:** README states what the product does not do and never promises zero bugs.
  Evidence: `README.md` status matrix and “What Code Clearance does not do”.

- [x] **Implemented and tested:** contribution gate remains closed while foundation/licence decisions are not recorded as open.
  Evidence: `CONTRIBUTING.md`; the current pass does not open implementation contributions without a recorded foundation/licence decision.

- [ ] **Experimental:** demo reaches the documented residual-risk outcome.
  Evidence: `bash scripts/demo.sh` exits zero, but the recorded final Release report is blocked by missing Git provenance. See `docs/DEMO.md`; do not use the script as release acceptance until fixed.

- [ ] **Planned for v1.0:** release notes, public distribution and security intake are published.
  Missing: draft release notes and release tooling exist, but no release exists and private security intake is not live.
