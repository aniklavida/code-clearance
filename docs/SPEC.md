# Code Clearance — public product specification

**Status:** Pre-implementation v1.0 specification
**Version target:** Complete public v1.0, supporting Linux, macOS and Windows

## Product

Code Clearance is a local-first assurance layer invoked by a coding agent, developer or CI workflow after meaningful code changes. It coordinates proven scanners and repository checks, normalizes and challenges their findings, helps prepare fixes, reruns the relevant evidence, and produces an honest clearance result tied to the exact commit and working-tree state.

It is not another monolithic scanner. Its value is one traceable:

```text
scan → normalize → correlate → challenge → fix → rescan/test → report
```

## Users

- Agent-heavy individual developers using an MCP-compatible coding harness.
- Maintainers who need evidence rather than an AI-generated “looks good.”
- Small teams that want a repeatable local and CI policy without a large hosted platform.

## Product promise

A clearance result states:

- which commit/diff, files and commands were checked;
- which tools, versions and rules ran;
- which findings were confirmed, rejected, fixed, accepted or unresolved;
- which checks passed, failed, timed out or were unavailable;
- what coverage and residual risk remain.

“Cleared” never means “zero bugs.”

## User flow

1. Install one `code-clearance` binary.
2. Run `code-clearance init` directly or through an agent.
3. Review the proposed `clearance.yaml` and detected capabilities.
4. Register the local MCP server for a supported host.
5. After a meaningful change, the agent invokes Quick, Full or Release clearance.
6. Code Clearance runs relevant adapters and repository commands.
7. It normalizes, fingerprints, correlates and deduplicates findings.
8. The agent or reviewer records a supported challenge verdict.
9. The agent proposes a fix; material mutation follows normal user approval.
10. Code Clearance reruns affected tests/scanners and produces the report.

MCP servers are passive. Automatic use is established through host instructions, hooks or CI calling Code Clearance.

## Modes

| Mode | Scope | Use |
|---|---|---|
| Quick | Changed files and affected checks | Every meaningful coding session |
| Full | Whole repository and configured checks | Pull request or milestone |
| Release | Full checks plus strict policy/provenance | Public release gate |

## Outcomes

| Outcome | Meaning |
|---|---|
| Cleared | Required checks completed and no blocking confirmed finding remains |
| Cleared with residual risk | Required checks passed, but declared limitations or accepted findings remain |
| Blocked | A confirmed finding or failed required check violates policy |
| Incomplete | Required evidence was unavailable, crashed, timed out or could not run |

## Complete v1.0 scope

- Git diff/commit scoping and stack/tool discovery.
- Parallel, cancellable adapter runner with explicit timeouts.
- Native JSON and SARIF ingestion with preserved raw evidence.
- Stable fingerprints, deduplication and cross-tool correlation.
- Challenge states: unreviewed, confirmed, rejected, accepted-risk, fixed and unresolved.
- Patch-context handoff and targeted rescan/test verification.
- Quick, Full and Release policy profiles.
- Shared CLI and local stdio MCP application core.
- Terminal, JSON, SARIF-compatible and local HTML reports.
- Local run history bound to repository, commit and dirty-tree fingerprint.
- GitHub Action and pull-request annotations.
- Guided setup/doctor flow for missing tools.
- Baselines and risk acceptance with reason, owner and expiry.
- Linux, macOS and Windows release binaries, checksums and release notes.
- Tested examples for JavaScript/TypeScript, Python and Go.
- Contributor, security, architecture, adapter and configuration documentation.

## Initial adapter families

- Semgrep Community Edition for static patterns.
- Gitleaks core CLI for secrets.
- OSV-Scanner for dependency vulnerabilities.
- Trivy for broader dependency, filesystem, container and IaC coverage.
- Repository-defined build, test, type-check and lint commands.
- Optional OpenSSF Scorecard for repository security posture.

Code Clearance ships adapters rather than copied scanner engines. An unavailable required adapter produces an Incomplete result, never a pass.

## Evidence requirements

Every finding records its source adapter, tool version, rule, original and normalized severity, location, commit scope, evidence, confidence rationale, challenge status, related findings, fix reference, verification runs, final disposition and raw-artifact reference.

## Safety and trust

- No destructive fix or broad mutation without approval.
- No source-code upload under default configuration.
- Secrets are redacted from reports and agent context where possible.
- Repository-defined commands cross a trust/approval boundary.
- Third-party binaries are version-recorded and downloads are verified.
- Skipped, unavailable and failed checks remain visible.

## Explicitly outside v1.0

- Hosted dashboard, billing or organization management.
- IDE extension.
- A new proprietary scanner engine.
- Built-in paid AI model or mandatory cloud account.
- Automatic mutation without approval.
- Claims of universal language or bug coverage.

## Release acceptance

- A fresh user can install, configure MCP, initialize a sample repo and obtain a report using only the quick start, on Linux, macOS or Windows.
- At least Semgrep, Gitleaks and one dependency scanner work through independent adapters.
- Duplicate findings are correlated without losing source evidence.
- The full scan → challenge → fix → verify → report flow works through MCP.
- CLI and GitHub Action return the same policy outcome for the same evidence.
- Missing required checks result in Incomplete.
- Release mode blocks configured confirmed findings and failed required commands.
- Public demo shows a confirmed issue, rejected false positive, verified fix and residual risk.
- Release binaries, checksums, changelog, security policy and third-party notices are published.
