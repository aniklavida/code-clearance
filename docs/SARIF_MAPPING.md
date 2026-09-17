# SARIF 2.1.0 Mapping and Omission Documentation

Code Clearance provides bi-directional interoperability with OASIS SARIF (Static Analysis Results Interchange Format) version 2.1.0. This document defines the exact field mappings when exporting a Code Clearance Report to SARIF, and catalogs the richer assurance fields that SARIF cannot natively express.

The list of unsupported fields is an intentional deliverable, capturing the design differences between a raw scanner interchange format and an end-to-end evidence assurance model.

---

## 1. Supported Field Mappings

When exporting via `normalize.Export(report)`, the following fields are mapped to standard SARIF 2.1.0 elements:

| Code Clearance Model | SARIF 2.1.0 Path | Notes |
|---|---|---|
| `run.Tool` | `runs[].tool.driver.name` | Scanner adapter name |
| `run.ToolVersion` | `runs[].tool.driver.semanticVersion` | Tool release version |
| `finding.RuleID` | `runs[].results[].ruleId` | Rule identifier |
| `finding.RuleID` | `runs[].tool.driver.rules[].id` | Rule definition in driver |
| `finding.Message` | `runs[].results[].message.text` | Primary finding message |
| `finding.NormalizedSeverity` | `runs[].results[].level` | Mapped to `error`, `warning`, `note`, or `none` |
| `location.URI` | `runs[].results[].locations[].physicalLocation.artifactLocation.uri` | Target file path |
| `location.StartLine` | `runs[].results[].locations[].physicalLocation.region.startLine` | 1-indexed start line |
| `location.StartColumn` | `runs[].results[].locations[].physicalLocation.region.startColumn` | 1-indexed column |
| `location.EndLine` | `runs[].results[].locations[].physicalLocation.region.endLine` | 1-indexed end line |
| `location.EndColumn` | `runs[].results[].locations[].physicalLocation.region.endColumn` | 1-indexed column |
| `location.Snippet` | `runs[].results[].locations[].physicalLocation.region.snippet.text` | Code fragment |

### Severity Mapping Table

| Normalized Severity | SARIF `level` |
|---|---|
| `critical` | `error` |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |
| `unknown` | `none` |

---

## 2. Richer Assurance Fields Without SARIF Representation

SARIF 2.1.0 is designed for point-in-time scanner diagnostic dumps. It does not model agentic review, fix verification loops, policy clearance outcomes, or dirty working-tree bindings.

The following Code Clearance fields have no standard counterpart in SARIF:

### 1. Original Native Tool Severity (`native_severity`)
SARIF collapses rule severity into a single 4-value enum (`error`, `warning`, `note`, `none`). Code Clearance requires preserving the exact native string reported by the scanner engine (e.g. CVSS numerical strings `"7.5"`, vendor severities `"CRITICAL"`, or unranked markers). Losing this destroys provenance.

### 2. Deterministic Cross-Tool Fingerprint (`id`, `fingerprint`)
SARIF includes optional `partialFingerprints` hashes, but defines no universal cross-tool identity algorithm. Code Clearance computes a deterministic 16-character cryptographic hash over invariant attributes (`tool`, `rule_id`, `primary_location`, `message`) to ensure duplicate collapsing across executions.

### 3. Structured Confidence with Rationale (`confidence`)
SARIF results lack a native mechanism to capture both a confidence level (`high`, `medium`, `low`, `unknown`) and a reasoned rationale explaining why the finding is considered actionable or a false positive.

### 4. Reviewer Identity and Classification (`reviewer`)
SARIF has no concept of an active reviewer. Code Clearance explicitly classifies reviewers into `tool`, `agent`, or `human`, and records the specific reviewer identity who evaluated the finding.

### 5. Challenge and Triage Lifecycle (`challenge_status`)
SARIF records suppression states (`suppressions[]`), but does not model the active clearance challenge lifecycle:
- `unreviewed`
- `confirmed`
- `rejected`
- `accepted-risk`
- `fixed`
- `unresolved`

### 6. Lineage and Deduplication Tracking (`duplicate_finding_ids`, `related_finding_ids`)
When multiple tools (or multiple rules within a tool) report the same underlying vulnerability (e.g. both Semgrep and Trivy reporting an identical hardcoded secret or CVE), Code Clearance collapses them while preserving explicit bi-directional IDs in `duplicate_finding_ids`. SARIF has no schema for cross-tool finding unification.

### 7. Patch and Fix Lineage (`fix_patch`)
Code Clearance binds a candidate or applied remediation patch directly to the finding (`path`, unified `diff`, and `commit`). SARIF has `fixes[]`, but does not link back to git commit lineage or branch diff scope.

### 8. Fix Verification History (`verification_runs`)
Clearance requires proving that a fix actually resolved the issue. Code Clearance logs each verification re-execution with run ID, timestamp, tool execution status, and verified outcome. SARIF provides no execution history container.

### 9. Raw Artifact Provenance Reference (`raw_artifact`)
Code Clearance findings must remain directly traceable to the raw tool output file, format, and result index (`raw_artifact.uri`, `raw_artifact.format`, `raw_artifact.index`).

### 10. Explicit Uncovered Categorization (`uncovered`)
SARIF `invocations[].executionSuccessful` provides a single boolean. Code Clearance strictly separates why a check was not covered:
- `skipped` (e.g., no matching language files)
- `crashed` (scanner failed with unexpected exit code or malformed output)
- `timed_out` (killed after exceeding execution bound)
- `unavailable` (missing binary on host)

### 11. Deterministic Clearance Verdict (`outcome`)
SARIF is a diagnostic report; it produces no policy verdict. Code Clearance synthesizes all evidence and policy rules into an immutable clearance outcome (`cleared`, `cleared-with-residual-risk`, `blocked`, `incomplete`).

### 12. Working-Tree Fingerprint (`target.fingerprint`, `target.dirty`)
SARIF `versionControlProvenance` records a repository URL and commit hash, but cannot represent the state of an uncommitted, dirty working tree. Code Clearance binds evidence to a deterministic SHA-256 hash computed over tracked file modifications.

### 13. Expiring Residual Risk Tracking (`residual_risk`)
When a finding is accepted rather than remediated, Code Clearance requires an explicit business justification, an owner, and a hard expiration timestamp (`expires_at`). Expired acceptances automatically revert to blocking findings.

---

## 3. Native JSON Ingestion and Boundary Sanitization

For scanners whose SARIF output is lossy or absent, Code Clearance ingests native JSON to preserve original source detail:

- **Semgrep Community Edition**: Ingests `semgrep scan --json` preserving native severities (`ERROR`, `WARNING`, `INFO`), precise AST check IDs, line ranges, and line snippets.
- **Gitleaks**: Ingests native JSON output containing rule IDs, commit/entropy details, and matched locations.
- **OSV-Scanner**: Ingests native JSON output preserving package ecosystems, exact dependency versions, and vulnerability alias arrays.
- **Trivy**: Ingests native JSON output (`trivy fs -f json`) preserving target files, vulnerability IDs, package names, installed/fixed versions, and upstream URLs.

### Secret Redaction Invariant
All text fields across findings (`message`, `details`, `snippet`, `match`, `context`) are scrubbed by the normalization boundary redactor before findings can reach a report or an agent's context. Live credential patterns (such as tokens and API keys) are replaced with `[REDACTED]`, ensuring sensitive material is never leaked to models or published reports while preserving cryptographic snippet hashes.

