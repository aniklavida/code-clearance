# Code Clearance

Evidence-based clearance for AI-generated code.

> **Pre-implementation:** Code Clearance has a version 1.0 product specification and repository foundation, but no working release yet. Capabilities below are planned unless explicitly marked implemented.

Code Clearance will be a local-first assurance engine that coding agents, developers and CI workflows can invoke after meaningful code changes. It will coordinate trusted scanners and repository checks, normalize and challenge findings, verify fixes by rerunning evidence, and produce a commit-bound report showing what passed, failed, remained unknown or was accepted as risk.

The intended workflow is:

```text
scan → normalize → correlate → challenge → fix → rescan/test → clearance report
```

Code Clearance will not promise zero bugs. A result must disclose its scope, tool versions, unavailable checks, coverage and residual risk.

## Planned interfaces

- One cross-platform `code-clearance` CLI core
- Local MCP server for compatible coding-agent hosts
- GitHub Action and pull-request annotations
- Terminal, JSON, SARIF-compatible and local HTML reports

## Documents

- [Product specification](docs/SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Build-to-release roadmap](docs/ROADMAP.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)

## Current status

The public repository contains the product specification and contribution foundation. The engine has not been implemented and no release has been published.
