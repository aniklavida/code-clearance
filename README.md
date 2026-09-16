# Code Clearance

Evidence-based clearance for AI-generated code.

> **Pre-implementation:** Code Clearance has a version 1.0 product specification, a locked technical foundation (Go, the official MCP Go SDK, and a lightweight core with external scanner adapters) and a repository foundation, but no working release yet. Capabilities below are planned unless explicitly marked implemented.

Code Clearance will be a local-first assurance engine that coding agents, developers and CI workflows can invoke after meaningful code changes, on Linux, macOS and Windows. It will coordinate trusted scanners and repository checks, normalize and challenge findings, verify fixes by rerunning evidence, and produce a commit-bound report showing what passed, failed, remained unknown or was accepted as risk.

The intended workflow is:

```text
scan → normalize → correlate → challenge → fix → rescan/test → clearance report
```

Code Clearance will not promise zero bugs. A result must disclose its scope, tool versions, unavailable checks, coverage and residual risk.

## Planned interfaces

- One cross-platform `code-clearance` CLI core, for Linux, macOS and Windows
- Local MCP server for compatible coding-agent hosts
- GitHub Action and pull-request annotations
- Terminal, JSON, SARIF-compatible and local HTML reports

## Documents

- [Product specification](docs/SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Build-to-release roadmap](docs/ROADMAP.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)

## Current status

The product specification, the contribution foundation, and the first working slice of the engine are here. **No release has been published**, and most capabilities listed above remain planned.

What runs today: a bounded process runner with cancellation and captured exit state, SARIF 2.1.0 normalization, adapters for `gitleaks` and `osv-scanner`, one MCP tool over the official Go SDK, and a single binary exposing the same core through `scan` and `serve`. Scan results are bound to the repository, the commit and a dirty-tree fingerprint.

## Installation (planned)

Nothing is published yet, so neither path below works today. They are recorded so the shape is not a surprise later.

**Tagged release binaries** will be the supported way to install, for Linux, macOS and Windows, with checksums and signing where the platform supports it. A tool whose subject is supply-chain assurance should ship artifacts you can verify.

**`go install github.com/aniklavida/code-clearance/cmd/code-clearance@latest`** will also work, for people who already have a Go toolchain and prefer it. It builds on your machine, so it produces nothing signed — `code-clearance version` says so rather than leaving you to guess.

Package managers such as Homebrew are not planned for the first release. They would not cover Windows, so they solve none of the platform problem.

External scanners are invoked as separate processes and are never vendored: you install `gitleaks` and `osv-scanner` yourself, and Code Clearance reports honestly when a required one is missing.
