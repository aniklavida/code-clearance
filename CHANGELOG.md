# Changelog

All notable changes to Code Clearance will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Changed

- Locked the technical foundation: Go, the official MCP Go SDK, and a lightweight core with external scanner adapters.
- Expanded version 1.0 platform scope to Linux, macOS and Windows.

[Unreleased]: https://github.com/aniklavida/code-clearance/commits/main
