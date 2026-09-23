# Changelog

All notable changes to Code Clearance will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Security

- Repository-defined commands are now checked against a command allowlist (extendable per review via the optional `commands.allow` field); a refused command is recorded as a non-pass rather than skipped.
- Secret redaction is proven across three surfaces at once: the normalized finding derived from scanner output, the rendered report, and the MCP agent payload, while local raw evidence remains preserved.

### Changed

- Locked the technical foundation: Go, the official MCP Go SDK, and a lightweight core with external scanner adapters.
- Expanded version 1.0 platform scope to Linux, macOS and Windows.

[Unreleased]: https://github.com/aniklavida/code-clearance/commits/main
