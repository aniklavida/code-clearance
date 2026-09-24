# Architecture

**Status: Implemented and tested** for the shared Go core, external process runner, adapter registry, evidence model, local artifact store, policy evaluator, CLI, local stdio MCP server and Action entry point. Items marked **Experimental** or **Planned for v1.0** are called out where current execution differs from the target design.

## Foundation

Code Clearance is implemented in Go with the official MCP Go SDK. One application core serves the CLI, local stdio MCP and GitHub Action entry points. The core orchestrates external scanner processes; it does not embed scanner engines.

The process boundary uses explicit executables and argument arrays, caller cancellation, bounded timeouts and captured process state. Platform-specific process termination is implemented with POSIX process groups on Unix and Windows job-object support in the runner. Cross-platform clean-release verification remains **Planned for v1.0**.

## Implemented flow

```text
CLI / MCP / Action
      │
      ├─ load and validate clearance.yaml
      │
scope planner ── target binding and file list
      │
parallel task scheduler ── adapters + repository commands
      │
bounded process runner
      │
raw artifact store ── parser/normalizer
      │
redaction + fingerprint + correlation
      │
review and accepted-risk persistence
      │
targeted verification when a fix is proposed
      │
deterministic policy evaluator
      │
terminal / JSON / offline HTML / Action annotations + SARIF
```

CLI, MCP and Action call `app.ScanWithEngine`; the Action and MCP-specific code projects the common report rather than reimplementing policy evaluation. Configuration loading is shared through `app.LoadTargetConfig`. Tests cover local CLI/Action parity and entry-point behavior, but a live hosted Action run is **Planned for v1.0**.

## Package boundaries

```text
cmd/code-clearance/       CLI commands and onboarding
cmd/code-clearance-action/ Action entry point
internal/app/             shared use cases, process runner, scope, review and verification
internal/adapters/        scanner contract, built-in adapters and registration
internal/discovery/       language, manifest and adapter discovery
internal/evidence/        normalized finding, run and report model
internal/normalize/       SARIF/native parsers, redaction, fingerprints and export
internal/correlate/       deterministic fingerprints and cross-tool correlation
internal/policy/          configuration, migrations, presets and deterministic evaluation
internal/report/          terminal, JSON and offline HTML rendering
internal/store/           local run metadata, reviews and raw artifacts
internal/mcpserver/       local stdio MCP tools and host configuration
internal/action/          pull-request annotations and SARIF projection
internal/baseline/        fingerprint baseline loading and disclosure
internal/schema/          v1 configuration and report schema validation
schemas/                  versioned public contracts and compatibility rules
```

The packages named in the specification as planned now exist. The scanner adapter boundary is documented for contributors in [Adapter guide](ADAPTER_GUIDE.md); configuration, policy and report contracts have dedicated [configuration](CONFIGURATION.md), [policy](POLICY.md) and [report schema](REPORT_SCHEMA.md) documents.

## Architectural invariants

- **Implemented and tested:** one application core serves CLI, MCP and Action transports.
- **Implemented and tested:** raw scanner bytes remain locally retrievable after normalization.
- **Implemented and tested:** normalized text is redacted before report or MCP exposure.
- **Implemented and tested:** identical evidence, configuration and report timestamps produce the same policy verdict.
- **Implemented and tested:** a missing required adapter produces `incomplete` outside Release and `blocked` in Release.
- **Implemented and tested:** skipped, crashed, timed-out and unavailable checks remain visible and are not rendered as successful runs.
- **Implemented and tested:** a finding becomes fixed only through recorded verification evidence.
- **Implemented and tested:** repository commands use argument arrays, timeouts and an executable allowlist; they do not become arbitrary shell execution.
- **Implemented and tested:** Gitleaks and OSV-Scanner real-process adapters preserve raw evidence and honor findings-versus-failure exit semantics.
- **Experimental:** Semgrep and Trivy adapters have parser fixtures and failure boundaries but were not available for a real-process run in the recorded evidence.
- **Experimental:** GitHub Action behavior is locally tested but not verified on a hosted runner.

## Scope and execution boundary

The scope planner is **Implemented and tested** for:

- Quick dirty-tree, base-commit or `HEAD~1` file resolution;
- Full tracked and untracked non-ignored file enumeration;
- Release full-file coverage and provenance;
- profile resolution for adapters, commands, paths, policy, limits and outcomes.

The scanner execution boundary is **Experimental**. `TargetFiles`, scope adapter selection and scope command selection are represented in the plan, but the production scan currently runs every registered scanner against the target directory and schedules the resolved command list. This means `coverage.files_checked` describes the planned file set; it does not prove that each adapter limited itself to exactly that list.

## Adapter boundary

An adapter declares a stable name, capability, availability, version, input scope, command and exit semantics. `Run` returns one normalized `RunOutcome`, even for missing tools. The adapter preserves raw bytes and normalizes supported SARIF or native JSON through the shared evidence model.

Adapters are compiled into the Go binary and selected by exact policy name. Runtime plugin loading is **Unsupported**. Per-file or diff input beyond a repository directory is **Planned for v1.0**. See [Adapter guide](ADAPTER_GUIDE.md).

## Persistence

The local store writes run metadata and raw artifacts under the target's ignored `.clearance/` directory. A report is bound to repository identity, commit, dirty state and working-tree fingerprint. Review decisions, accepted risk, candidate patches and verification runs persist by finding fingerprint.

Raw artifacts are local evidence. Normalized report and MCP text is redacted, but the original scanner output remains available on disk for authorized inspection. Baseline suppression leaves findings and source evidence in the report.

## Security boundaries

- Repository configuration and commands are untrusted input.
- Commands are tokenized without shell evaluation, rejected when they attempt shell execution or path traversal, and limited to the command allowlist.
- External commands receive explicit scope, working directory, arguments, timeout, cancellation and captured exit state.
- Default operation does not upload source in the application core.
- Likely secrets are redacted at normalization before report or MCP exposure.
- Scanner versions and exact commands are recorded.
- Scanner availability and parser failures remain visible.
- Hosted runner behavior, network isolation for third-party scanner processes and cryptographic signing are not represented as stronger guarantees than the current evidence supports.

## Release gaps

The following remain outside the **Implemented and tested** boundary:

- **Planned for v1.0:** published tagged binaries, checksums, release notes and a verified private vulnerability-reporting path;
- **Planned for v1.0:** clean Linux, macOS and Windows release walkthroughs;
- **Planned for v1.0:** live GitHub Actions verification;
- **Experimental:** Windows release packaging, complete Quick affected-adapter execution and independent required-command policy gating;
- **Unsupported:** hosted dashboard, runtime scanner plugins, copied scanner engines, artifact/report signing and a zero-bug guarantee.
