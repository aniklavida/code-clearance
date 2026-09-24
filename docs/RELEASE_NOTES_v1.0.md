# Version 1.0 release notes (draft)

**Status: Planned for v1.0.** Do not tag or publish until every box in [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) is checked with named evidence. The current source tree is a working pre-release, not a published release.

## What the current source provides

Code Clearance is a local-first assurance layer for coding agents, developers and CI. One Go application core serves CLI, local stdio MCP and an Action entry point. It invokes external scanners as bounded processes, preserves raw evidence, normalizes and correlates findings, records review state, verifies fixes with new evidence and produces a commit-bound report with coverage and residual-risk disclosure.

The target loop is:

```text
scan → normalize → correlate → challenge → fix → rescan/test → report
```

**Implemented and tested:** the core, Gitleaks and OSV-Scanner real-process adapters, SARIF/native fixtures, deterministic policy, review/fix/verification, local MCP, terminal/JSON/HTML output, baselines, risk acceptance, source-build onboarding and schema compatibility.

**Experimental:** Semgrep and Trivy real-process behavior in the recorded environment, the GitHub Action on a hosted runner, desktop MCP host GUIs, Quick changed-file adapter execution, required-command policy gating and release tooling execution.

**Unsupported:** a published release, runtime scanner plugins, signing, a hosted dashboard, copied scanner engines and any zero-bug guarantee.

## Current adapters

| Adapter | Recorded capability | Status |
|---|---|---|
| Gitleaks | repository secret scanning | **Implemented and tested** |
| OSV-Scanner | dependency vulnerabilities | **Implemented and tested** |
| Semgrep | native JSON static analysis | **Experimental** |
| Trivy | filesystem-mode dependency scanning | **Experimental** |

Scanner versions are detected and recorded from the host. The adapters validate supported major-version ranges; they do not pin the host binary to a fixed patch release.

## Interfaces

**Implemented and tested:**

- CLI: `init`, `doctor`, `mcp`, `run`, `report`, `scan`, `record-review`, `verify`, `fix-context`, `findings`, `baseline`, `serve`, `version`;
- local stdio MCP tools for scan, run, report, review, findings, fix context and verification;
- terminal, JSON and standalone offline HTML reports;
- local raw artifact and review persistence.

**Experimental:** the composite GitHub Action and its SARIF/annotation projection are locally tested but have not run on a hosted runner.

**Planned for v1.0:** tagged release artifacts, install commands and the final Action documentation are not a substitute for a published, verified release.

## Modes and policy

**Implemented and tested:** scope planning for Quick, Full and Release; repository/commit/dirty-tree binding; deterministic outcomes; required-adapter completeness; provenance for Release; critical/high/medium/low severity policy; human-required classes; expiring risk acceptance; and baseline disclosure.

**Experimental:** Quick records the changed-file set but currently passes the repository directory to registered scanners. Required repository-command failures are visible but do not independently force the evaluator to block. `outcomes.minimum_evidence` is schema-valid documentation rather than a fully dynamic switchboard.

## What is not included

- **Planned for v1.0:** published Linux/macOS/Windows binaries, a working private vulnerability-reporting path, live CI release evidence and independent human documentation acceptance.
- **Unsupported:** zero-bug claims, universal scanner coverage, runtime plugin loading, artifact/report signing and automatic mutation without approval.
- **Experimental:** Windows packaging, Semgrep/Trivy real-process verification and a fully affected-check Quick mode.

## Release evidence

The complete real self-scan is published in [`DOGFOOD.md`](DOGFOOD.md). It was `blocked` with 23 normalized findings, 11 blocking findings and two unavailable optional scanners. The demo is **Experimental** and currently ends with a provenance-blocked Release report; its output does not prove the claimed residual-risk outcome.

Do not cut a release until the checklist is accurate and every release artifact has checksum and provenance evidence.
