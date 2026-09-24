# Report schema

**Status: Implemented and tested.** The versioned report contract is [`schemas/report.schema.json`](../schemas/report.schema.json); compatibility and migration rules are in [`schemas/COMPATIBILITY.md`](../schemas/COMPATIBILITY.md). `code-clearance run --json` and `code-clearance scan --json` emit this model. The Action exports a SARIF projection; it does not replace the Code Clearance report.

## Top-level shape

```json
{
  "schema_version": "v1",
  "target": {},
  "outcome": "blocked",
  "reason": "human-readable policy explanation",
  "runs": [],
  "findings": [],
  "uncovered": {},
  "coverage": {},
  "residual_risk": [],
  "timestamps": {}
}
```

`baseline` and `provenance` are optional. The schema rejects unknown top-level fields, so a consumer can rely on the shape below.

## `target`

| Field | Meaning |
|---|---|
| `repository` | Git remote or explicit `not-a-git-repository`. |
| `commit` | Commit SHA or `not-a-git-repository`. |
| `dirty` | Whether the target had uncommitted changes. |
| `fingerprint` | Deterministic working-tree fingerprint or `clean`. |

A report is evidence about this exact target state, not an abstract score for the project.

## `outcome` and `reason`

Allowed outcomes are `cleared`, `cleared-with-residual-risk`, `blocked` and `incomplete`. `reason` names the policy reason, such as a blocking count, required adapter failure or dirty-tree rule. See [Policy](POLICY.md) for the evaluator order and presets.

## `runs`

One entry records every scanner or repository-command attempt, including a tool that was not installed:

```json
{
  "tool": "gitleaks",
  "tool_version": "v8.30.1",
  "command": "gitleaks detect --no-git --source /repo --report-format sarif",
  "exit_code": 1,
  "duration": "1.78s",
  "status": "ok-findings",
  "findings": [],
  "raw_artifact": {
    "uri": ".clearance/runs/.../artifacts/gitleaks.sarif",
    "format": "sarif",
    "index": 0
  }
}
```

Run statuses are:

| Status | Meaning |
|---|---|
| `ok` | Process completed with no retained findings. |
| `ok-findings` | Process completed and findings were retained. |
| `crashed` | Unexpected exit, parse failure or adapter failure. |
| `timed-out` | Bounded execution elapsed. |
| `not-installed` | Executable was absent. |
| `skipped` | Check was not applicable or was explicitly skipped. |
| `unavailable` | Tool/output was unavailable, unsupported or cancelled. |

A clean run and a missing tool are different states. `uncovered` repeats non-passing checks with the reason, command and exit code.

## `findings`

A finding is the normalized, tool-independent evidence record. Required fields include:

- stable `id` and `fingerprint`;
- tool and tool version;
- original `native_severity` and normalized severity;
- rule ID, locations and snippet hash;
- message, evidence details and remediation recommendation;
- confidence level plus rationale;
- challenge state, reviewer and disposition;
- related and duplicate finding IDs;
- verification run lineage when present;
- raw artifact reference and raw result index.

Raw evidence is retained locally. Normalized text is redacted before it reaches a report or MCP payload; the raw artifact remains available for authorized local inspection.

## `uncovered`

```json
{
  "skipped": [],
  "crashed": [],
  "timed_out": [],
  "unavailable": [
    {
      "tool": "semgrep",
      "command": "semgrep scan --json --quiet /repo",
      "reason": "semgrep executable missing on PATH",
      "exit_code": -1
    }
  ],
  "required_incomplete": false
}
```

`required_incomplete` is present and true when required evidence did not complete. The schema then requires `outcome` to be `incomplete` or `blocked`. Optional missing tools remain visible without forcing a pass state to become incomplete.

## `coverage`

`coverage.scope` is `quick`, `full` or `release`. `files_checked` is the resolved scope file list. `adapters_ran` lists tools whose process produced a run, excluding not-installed and skipped tools. `summary` is human-readable and not a coverage percentage.

**Important boundary:** Quick currently resolves changed files for coverage, while registered scanners still receive the repository directory. Read `files_checked` as the planned scope, not proof that each adapter limited itself to those files.

## `residual_risk`

Accepted findings are listed with severity, reason, owner and expiry. Residual risk is a deliberate policy result, not a hidden pass. An expired or invalid acceptance remains blocking for a blocking-severity finding.

## `timestamps`

`started_at` and `completed_at` are RFC3339 timestamps. The evaluator uses the completed timestamp to test accepted-risk expiry, keeping repeated evaluation deterministic for the same report.

## SARIF projection

The Action and `internal/normalize` export a SARIF 2.1.0 projection. SARIF carries tool, version, rule, message, normalized severity, location and raw result relationships. Code Clearance fields such as reviewer identity, risk acceptance, dirty-tree binding, verification lineage and policy outcome have no native SARIF equivalent. See [SARIF mapping](SARIF_MAPPING.md).

## Versioning and validation

- **Implemented and tested:** `v1` schema compatibility tests and migration tests.
- **Implemented and tested:** report validation against `schemas/report.schema.json` in the test suite.
- **Implemented and tested:** `1.0.0` is accepted as a compatibility alias and normalized to `v1`.
- **Planned for v1.0:** a release workflow that publishes versioned schemas with binaries.
- **Unsupported:** silently accepting unknown schema versions or changing v1 field meanings without a versioned migration.
