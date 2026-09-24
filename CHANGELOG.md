# Changelog

Public capability claims in this file use the repository status vocabulary: **Implemented and tested**, **Experimental**, **Planned for v1.0** or **Unsupported**.

All notable changes to Code Clearance will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Implemented and tested:** public README quick start, architecture, configuration, policy, adapter and report-schema documentation with explicit capability status and honest unsupported/planned boundaries.
- **Implemented and tested:** real JavaScript/TypeScript, Python and Go worked-example reports using checked-in fixtures and captured scanner output.
- **Implemented and tested:** a complete full-repository dogfood report, including all findings, unavailable scanners, toolchain warnings and residual limitations.
- **Experimental:** GitHub Action (`action.yml`) and a Docker-less `code-clearance-action` entry point that runs the exact same `internal/app` core as the CLI and MCP server, then adds the CI-specific projections: pull-request annotations scoped to changed lines and a SARIF report for code-scanning consumers. Local parity and behavior tests pass; no live hosted-runner verification is claimed.
- A shared `app.ScanWithEngine` and `app.LoadTargetConfig` path so the CLI, MCP server and GitHub Action resolve configuration and reach their verdict through one code path rather than three.
- CLI/Action parity test `TestCLIAndAction_ReachIdenticalPolicyOutcomeOnSameRecordedEvidence`, which runs both transports against the same recorded evidence and configuration and asserts an identical outcome, reason and finding set.
- Changed-line annotation, SARIF-export and no-network tests for the Action (`TestAction_AnnotationsScopedToChangedLines_UsingPRDiffFixture`, `TestAction_SARIFExportIsStructurallyValid`, `TestAction_RunOpensNoNetworkConnection`), plus `TestAction_UnavailableRequiredScannerProducesIncompleteNotPass` reusing the existing required-unavailable constraint.
- `docs/GITHUB_ACTION.md` documenting inputs, outputs, changed-line annotations, SARIF upload and local verification.
- Onboarding flow with `code-clearance init` detecting repository stack and available scanner tools to propose a versioned `clearance.yaml`, writing only upon explicit approval.
- Diagnostics and environment verification via `code-clearance doctor` confirming engine health, adapter minimal invocations, repository command execution, and MCP registration.
- Actionable failure remedies in doctor naming missing tools, broken commands, allowlist extensions, and safe next actions.
- Guided scanner installation in doctor displaying platform-specific install commands and requiring explicit approval before modifying the machine.
- MCP host registration management via `code-clearance mcp` (register, verify, unregister) verifying server connectivity via real protocol handshake over stdio.
- Documented update guidance and clean uninstall path for local files, registrations, and binaries.
- Unattended agent loop integration covering the complete scan -> challenge -> fix -> verify -> report workflow over MCP with lineage preservation.
- Rigorous determinism verification asserting identical recorded evidence and configuration produce identical verdicts across repeated evaluations.
- Requirement assertion ensuring missing or removed required adapters produce Incomplete and name the missing check by name in the report.
- Fix context handoff via `clearance_get_fix_context` (MCP) and `fix-context` (CLI) returning targeted evidence, remediation, and constraints for a single finding without whole-report exposure.
- Targeted rerun verification via `clearance_verify` (MCP) and `verify` (CLI) executing minimum affected checks and writing finding -> patch reference -> verification run lineage into the stored record.
- Invariant enforcement: findings cannot be marked fixed directly; findings transition to fixed solely through new recorded evidence from a successful verification rerun.
- Patch safety enforcement guarding against destructive fixes and broad mutations without explicit approval.
- Review workflow supporting challenge states: unreviewed, confirmed, rejected, accepted-risk, fixed and unresolved.
- Persistence for review decisions and accepted risks keyed by finding fingerprint across runs.
- `clearance_record_review` and `clearance_get_findings` tools available over MCP and CLI subcommands `record-review` and `findings`.
- `human_required_classes` configuration preventing agent/tool reviewers from clearing (rejecting, accepting risk, or marking fixed) specific high-value findings without human override.
- Public product specification, architecture and build-to-release roadmap.
- Contributor, security and community foundations.
- Versioned JSON Schemas for scan reports (`schemas/report.schema.json`) and clearance policy configuration (`schemas/clearance.schema.json`).
- Schema compatibility and migration specification (`schemas/COMPATIBILITY.md`).
- Formal `Adapter` Go interface declaring capability, required availability, version, input scope, command, exit semantics, raw output, and normalized findings.
- Native JSON ingestion for Semgrep Community Edition, Gitleaks, OSV-Scanner, and Trivy preserving original source details.
- Full evidence bundle on findings including command, tool version, rule, location, and raw artifact resolution.
- Secret redaction at the normalization boundary ensuring credentials never reach reports or agent context.
- Loud parser failure and tool version validation marking unparsed or unsupported checks as unavailable.
- Deterministic policy evaluation engine enforcing invariant outcomes.
- Bi-directional SARIF 2.1.0 export and documentation of assurance fields without SARIF counterparts (`docs/SARIF_MAPPING.md`).
- Hardening test suite covering timeout, crash, cancellation and dirty-tree boundaries end to end through the engine.
- Adapter-failure isolation test proving one panicking scanner cannot abort or corrupt sibling adapters' results.
- Hostile `clearance.yaml` fixture and permanent test proving shell wrappers, path traversal, newline injection, command substitution and unlisted binaries all fail safely.
- A required-check audit test enumerating every run status and asserting none converts an unavailable required check into a pass.
- Actionable failure diagnostics that name the failed command/tool and state the safe next action.
- Configuration schema migration: `policy.MigrateConfig` normalises version aliases and legacy scope shapes, and rejects unknown versions with an actionable error.
- Evidence engine core: a scope planner resolving Quick/Full/Release file sets, a parallel and cancellable adapter runner with explicit timeouts, and stack/tool discovery.
- Deterministic finding fingerprints, single-adapter deduplication and cross-tool correlation that preserve every constituent source record.
- Real process adapters for Gitleaks, OSV-Scanner, Semgrep and Trivy, each recording its tool version, exact command, exit semantics and raw output.
- `clearance_run` and `clearance_report` MCP tools with per-profile policy evaluation, backed by the `run` and `report` CLI subcommands through one core.
- Fingerprint baselines with `code-clearance baseline create`; suppressed findings remain disclosed in every report with baseline counts and source evidence.
- Expiring risk acceptance requiring reason, owner and RFC3339 expiry; expired or incomplete acceptance never renews and blocks on the next run.
- Named `individual`, `team` and `release` policy presets, with release mode enforcing full scope, strict policy and Git provenance.
- Offline local HTML reports via `code-clearance run --html-out` and `code-clearance report --html`, with inline styling and no network resources.
- Git and dirty-tree scoping that binds every report to repository identity, commit SHA and a working-tree fingerprint.
- CI that installs the real scanners and fails the build when a scanner-backed test silently skips.
- A tag-triggered release workflow (`.github/workflows/release.yml`) that cross-compiles macOS (amd64/arm64) and Linux (amd64/arm64), publishes `checksums.txt` (sha256), and records GitHub build provenance with `actions/attest-build-provenance`.
- `scripts/install.sh`, which downloads a tagged binary and refuses to install it unless its sha256 matches the published `checksums.txt`.
- A Homebrew formula template under `packaging/homebrew/` for users who prefer a package manager (not yet published to any tap).
- A `Dockerfile` for an isolated CLI run, with external scanners provided by the user (see `docs/DEMO.md`).
- A runnable `scripts/demo.sh` and `docs/DEMO.md` exercising the locked demo order: confirmed issue, rejected false positive, verified fix, residual risk.
- `docs/RELEASE_NOTES_v1.0.md` and a box-by-box `docs/RELEASE_CHECKLIST.md` recording exactly what is proven versus pending before v1.0.

### Security

- Repository-defined commands are now checked against a command allowlist (extendable per review via the optional `commands.allow` field); a refused command is recorded as a non-pass rather than skipped.
- Secret redaction is proven across three surfaces at once: the normalized finding derived from scanner output, the rendered report, and the MCP agent payload, while local raw evidence remains preserved.

### Changed

- Locked the technical foundation: Go, the official MCP Go SDK, and a lightweight core with external scanner adapters.
- Expanded version 1.0 platform scope to Linux, macOS and Windows.
- The report-schema guarantee "an unavailable required check is never a pass" is now expressed through the optional `uncovered.required_incomplete` boolean, so a missing *optional* scanner no longer forces an otherwise valid report to be `incomplete`. The invariant itself is unchanged and still enforced for required checks.

### Fixed

- Reports produced by a normal scan are now always valid against `schemas/report.schema.json`: correlation no longer emits `null` for `related_finding_ids`/`duplicate_finding_ids` on single-member findings, and runs with no findings emit `[]` rather than `null`.

[Unreleased]: https://github.com/aniklavida/code-clearance/commits/main
