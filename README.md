# Code Clearance

Code Clearance is a local-first assurance layer for code written by people or coding agents. It records what security and repository checks ran, what they found, which checks did not complete, and whether policy allows the result to clear. “Cleared” never means “zero bugs.”

## Status vocabulary

Public capability claims in this repository use one of four labels:

- **Implemented and tested** — present in this tree and covered by automated or recorded manual verification.
- **Experimental** — present, but not verified broadly enough to make a stronger claim.
- **Planned for v1.0** — specified but not available now.
- **Unsupported** — not part of the current contract and not treated as available.

## Current state

| Capability | Status | Boundary |
|---|---|---|
| Local CLI, `init`, `doctor`, `run`, `report`, reviews, fix context, verification, baselines and offline HTML | **Implemented and tested** | Source builds are supported; no release artifact is published. |
| Local stdio MCP server and host registration | **Implemented and tested** | The local registration path is tested. Desktop-host configuration formats are **Experimental** and were not exercised in their GUIs. |
| Git and working-tree report binding; Quick, Full and Release scope planning; deterministic outcomes | **Implemented and tested** | Quick records changed files, but all registered adapters currently receive the repository directory. Affected-file scanner execution is **Experimental**. |
| Gitleaks and OSV-Scanner adapters | **Implemented and tested** | Real-process tests and a real dogfood run cover both. |
| Semgrep and Trivy adapters | **Experimental** | Parser fixtures and adapter code exist, but the binaries were unavailable in the recorded run. Trivy currently invokes filesystem mode only. |
| GitHub Action, changed-line annotations and SARIF export | **Experimental** | Local parity and behavior tests pass; the Action has not run on a live hosted runner. |
| Tagged, checksummed release binaries and private security reporting | **Planned for v1.0** | Release tooling exists, but no supported release or working private reporting path is published. |
| Runtime-loaded scanner plugins, artifact/report signing and a Windows release binary | **Unsupported** | These are not current capabilities. |

The source tree is a working pre-release. The public interfaces, schema contracts and the remaining v1.0 gaps are listed below and in the [roadmap](docs/ROADMAP.md).

## Five-minute quick start

**Status: Implemented and tested.** This path was run literally from a clean checkout of the feature branch. It uses a disposable copy of the checked-in Go fixture, so the source checkout stays clean.

Prerequisites:

- Go 1.27.1;
- Git;
- Gitleaks 8.x on `PATH`;
- a POSIX shell for the commands below.

Install Gitleaks using your platform package manager if needed. For example, on macOS with Homebrew: `brew install gitleaks`.

```bash
git clone https://github.com/aniklavida/code-clearance.git
cd code-clearance
go build -o bin/code-clearance ./cmd/code-clearance
export PATH="$PWD/bin:$PATH"
export CODE_CLEARANCE_SCHEMAS_DIR="$PWD/schemas"

sample="$(mktemp -d)"
cp -R testdata/fixtures/go/. "$sample/"
git -C "$sample" init -q
git -C "$sample" add .
git -C "$sample" -c user.name="Quick Start" -c user.email="quick-start@example.invalid" commit -qm "Initial fixture"

code-clearance init --approve "$sample"
code-clearance doctor "$sample"
code-clearance run --preset individual "$sample"
```

The approved initialization writes a `clearance.yaml` file in the sample. Despite the filename, the current format is JSON-compatible YAML 1.2; handwritten YAML syntax is **Unsupported** until a YAML parser is added. `doctor` probes the configured scanners and commands, and the final command prints a terminal report. The verified fixture result is:

```text
Outcome: cleared
```

That result means the configured required Gitleaks check completed, the optional checks that were unavailable stayed visible, the Go test command passed, and no configured blocking finding remained. It is not a claim that the fixture has no bugs. If OSV-Scanner is installed, initialization makes it required for this dependency-bearing fixture; if Semgrep or Trivy is absent, those runs remain under `uncovered`.

To inspect machine-readable evidence:

```bash
code-clearance run --preset individual --json "$sample" > clearance-report.json
code-clearance report --json "$sample"
```

### Optional: register the local MCP server

**Status: Implemented and tested.** MCP servers are passive: registration does not schedule scans by itself.

```bash
code-clearance mcp register --host local --config "$sample/.mcp.json" \
  --command "$PWD/bin/code-clearance"
code-clearance mcp register --host local --config "$sample/.mcp.json" \
  --command "$PWD/bin/code-clearance" --approve
code-clearance mcp verify --config "$sample/.mcp.json"
```

The first registration command previews the file. The approved command writes it, and `verify` performs a real MCP initialization handshake over stdio.

## What Code Clearance does

**Implemented and tested:**

- binds reports to repository, commit and dirty-tree fingerprint;
- invokes bounded external scanner and repository commands and records process state;
- preserves raw scanner artifacts locally while redacting normalized report and MCP text;
- normalizes SARIF and supported native JSON, fingerprints and correlates findings;
- records review dispositions and expiring accepted risk;
- verifies a fix only after new evidence from a targeted rerun;
- renders terminal, JSON, offline HTML and Action SARIF projections;
- evaluates policy deterministically for identical evidence and configuration;
- exposes the same application core through CLI, MCP and the Action entry point.

## What Code Clearance does not do

- **Unsupported:** It does not promise zero bugs or universal language, vulnerability or bug coverage.
- **Unsupported:** It does not automatically install scanners, change configuration, register a host or mutate source without approval.
- **Unsupported:** It does not upload source by default or provide a hosted dashboard.
- **Unsupported:** It does not turn a finding into `fixed` merely because a reviewer asserts that it is fixed.
- **Experimental:** It does not yet pass a Quick plan's changed-file list to scanners; registered scanners receive the repository directory.
- **Planned for v1.0:** Published cross-platform artifacts, private vulnerability intake and the remaining release acceptance work do not exist yet.

## Daily use

```bash
# Preview a policy-aware run without choosing a preset.
code-clearance run --profile quick

# Use a stricter preset and write a standalone local HTML report.
code-clearance run --preset team --html-out clearance.html

# Adopt a known backlog without hiding it from the report.
code-clearance run --profile quick
code-clearance baseline create
code-clearance run --profile quick

# Record explicit, expiring risk acceptance.
code-clearance record-review --fingerprint <fingerprint> \
  --status accepted-risk --reason "temporary exception" \
  --identity alice --expires-at 2030-01-01T00:00:00Z
```

A full explanation of every field and current enforcement boundary is in [Configuration](docs/CONFIGURATION.md) and [Policy](docs/POLICY.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — implemented system flow, package boundaries and current gaps
- [Configuration](docs/CONFIGURATION.md) — file format, profiles, commands and schema fields
- [Policy](docs/POLICY.md) — deterministic outcomes, findings, risk acceptance and presets
- [Adapter guide](docs/ADAPTER_GUIDE.md) — add a scanner behind the existing core
- [Report schema](docs/REPORT_SCHEMA.md) — report fields, statuses, artifacts and compatibility
- [Worked examples](docs/EXAMPLES.md) — real JavaScript/TypeScript, Python and Go runs
- [Dogfood run](docs/DOGFOOD.md) — complete self-scan result and residual limitations
- [SARIF mapping](docs/SARIF_MAPPING.md) — evidence fields that SARIF can and cannot express
- [Product specification](docs/SPEC.md) and [roadmap](docs/ROADMAP.md)
- [Security policy](SECURITY.md) and [contribution policy](CONTRIBUTING.md)
- [Demo](docs/DEMO.md), [GitHub Action](docs/GITHUB_ACTION.md) and [release checklist](docs/RELEASE_CHECKLIST.md)

## Local state and removal

Runs and raw artifacts are stored under the target's ignored `.clearance/` directory. To remove local state and an approved workspace MCP registration:

```bash
code-clearance mcp unregister --host local --config .mcp.json --approve
rm -rf .clearance clearance.yaml clearance-report.json clearance.html
```

A Go-installed executable is under `$(go env GOPATH)/bin/code-clearance`; remove that executable separately if it is no longer needed.
