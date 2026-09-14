# Architecture

**Status:** Planned for v1.0. Nothing in this document is implemented yet.

## Foundation decision

Code Clearance is implemented in Go, using the official MCP Go SDK. One application core serves CLI, local stdio MCP and later GitHub Action entry points. The core is deliberately lightweight: it orchestrates external scanners as separate processes (for example Semgrep, Gitleaks and OSV-Scanner) rather than bundling or reimplementing their engines, and normalizes their output into one evidence model.

Version 1.0 targets Linux, macOS and Windows. Process orchestration uses a shared runner interface with a platform-specific process-tree termination strategy (POSIX process groups on Linux/macOS, job objects on Windows), so a hung or crashed scanner's entire process tree is reliably stopped everywhere, not only its immediate process.

## System flow

```text
CLI / MCP / CI
      │
request + policy resolution
      │
scope planner ── stack/tool discovery
      │
parallel adapter runner
      │
parser + normalizer ── raw artifact store
      │
fingerprint + dedupe + correlation
      │
challenge/disposition workflow
      │
fix coordination ── targeted rescan/tests
      │
deterministic policy evaluator
      │
terminal / JSON / SARIF / HTML / PR report
```

## Planned package boundaries

```text
cmd/code-clearance/       CLI entry point
internal/app/             shared use cases
internal/adapters/        scanner and command adapters
internal/discovery/       stack and tool detection
internal/evidence/        finding and run model
internal/normalize/       SARIF and native parsers
internal/correlate/       fingerprinting and deduplication
internal/policy/          deterministic profile evaluation
internal/report/          terminal, JSON, SARIF and HTML output
internal/store/           local run metadata and artifacts
internal/mcpserver/       MCP tools and transport
schemas/                  versioned config/report schemas
```

## Architectural invariants

- Interfaces contain transport logic only; business behavior lives in the core.
- Adapters expose capability, availability, version, command, scope, exit semantics, raw output and normalized findings.
- Raw output remains available after normalization.
- Identical evidence and policy produce the same outcome.
- AI reasoning may review a finding but cannot silently weaken release policy.
- A fix becomes verified only through new recorded evidence.
- Required unavailable checks cannot be downgraded to passing.

## Persistence

Local run metadata and raw artifacts live outside tracked source or in an ignored `.clearance/` directory. Every run is bound to repository identity, commit and a dirty-tree fingerprint. The report schema and configuration are versioned.

## Security boundaries

- Treat repository configuration and commands as untrusted until approved.
- Use explicit working directories, argument arrays, timeouts and cancellation.
- Redact likely secrets before exposing evidence to an agent/report.
- Record third-party binary versions and verify managed downloads.
- Never require source upload for default operation.
