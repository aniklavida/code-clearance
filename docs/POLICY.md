# Policy and outcomes

**Status: Implemented and tested** for the deterministic evaluator, presets, normalized severities, review persistence, human-required classes and expiring risk acceptance. The limitations section records policy fields or execution paths that are not yet enforced as their names might suggest.

## Inputs

The evaluator receives:

1. a v1 configuration resolved for the report scope;
2. the target repository, commit, dirty state and working-tree fingerprint;
3. every tool and repository-command outcome;
4. normalized, correlated findings and their current review state;
5. optional baseline, provenance and accepted-risk evidence.

Identical evidence, configuration and report timestamps produce the same outcome, blocking-finding list, residual-risk list and uncovered-check ordering. The evaluator does not query the wall clock; it uses the report completion timestamp to evaluate expiry.

## Outcomes

| Outcome | Current meaning |
|---|---|
| `cleared` | Every required adapter completed; the target is permitted to be dirty for the selected profile; no configured blocking finding remains; no accepted residual risk remains. |
| `cleared-with-residual-risk` | No blocking finding remains, but one or more findings have a valid accepted-risk record with reason, owner and future expiry. |
| `blocked` | A blocking finding remains, a dirty tree is disallowed, or Release provenance is not verified. In Release, missing required adapter evidence is also reported as blocked. |
| `incomplete` | A required adapter is missing, skipped, unavailable, crashed or timed out in Quick/Full. Optional unavailable checks remain visible but do not force this outcome. |

`cleared` is not a zero-bug guarantee. It is a statement about the configured evidence and policy only.

## Evaluation order

The evaluator applies these rules deterministically:

1. categorize every non-passing run under skipped, crashed, timed out or unavailable;
2. verify every required adapter by exact tool name;
3. in Release, require verified Git provenance;
4. enforce the selected profile's dirty-tree rule;
5. apply baseline suppression;
6. apply human-required review constraints;
7. apply valid accepted-risk records;
8. block findings whose normalized severity is configured as blocking;
9. report accepted residual risk or clear when no blocking finding remains.

Required-adapter incompleteness returns before finding evaluation. An unavailable required check therefore cannot be hidden by a later rejection or acceptance decision.

## Severity

Code Clearance keeps the scanner's native severity and maps it to one normalized policy band:

| Native examples | Normalized band |
|---|---|
| critical, CRITICAL, high CVSS bands | `critical` or `high` according to the adapter rule |
| warning, moderate CVSS bands | `medium` |
| low/info | `low` or `unknown` according to the adapter rule |

The exact mapping is adapter-specific. `native_severity` remains in the report so policy evaluation does not erase source evidence.

## Review states

**Implemented and tested.** A finding can be stored with one of:

- `unreviewed`
- `confirmed`
- `rejected`
- `accepted-risk`
- `fixed`
- `unresolved`

`record-review` persists reviewer type, identity, rationale and optional expiry. A finding cannot be set to `fixed` directly. The fix workflow accepts a candidate patch, runs the affected checks, and records verification evidence. The scanner loop remains the source of truth.

The CLI validates the documented states in normal review persistence, but the CLI argument layer does not reject every arbitrary status string before storage. Automation should use only the six values above.

## Rejected findings

**Implemented and tested.** A human, agent or tool rejection removes a finding from blocking consideration while retaining the finding, reason and reviewer in the report. For a finding matched by `human_required_classes`, only a human reviewer can clear it.

## Accepted risk

**Implemented and tested.** Acceptance may be stored on the finding through `record-review` or configured by finding ID, fingerprint or rule ID. A valid acceptance requires:

- a non-empty reason;
- a non-empty owner;
- a valid RFC3339 expiry later than the report completion time.

An accepted finding becomes residual risk rather than a pass hidden from the reader. Invalid or expired acceptance remains blocking when the finding's severity is blocking.

## Human-required classes

**Implemented and tested.** A class can match by `rule_id`, `tool`, `severity` or a combination. An agent/tool reviewer cannot reject, accept or verify away a matching finding. A human reviewer can do so, and the human identity is retained.

This is a policy constraint on a recorded reviewer type; it is not cryptographic identity verification.

## Baselines

**Implemented and tested.** `code-clearance baseline create` records fingerprints from the latest report. On later runs, matching findings are marked `suppressed_by_baseline` and excluded from blocking evaluation, but remain present in the report. The baseline section discloses its source, fingerprint count, suppressed count and active state.

A baseline is not risk acceptance. It has no reason, owner or expiry and does not remove evidence.

## Presets

**Implemented and tested.** Presets are policy overlays, not separate scanner engines.

| Preset | Preset behavior |
|---|---|
| `individual` | Blocks critical/high; allows dirty Quick; requires clean Full/Release. |
| `team` | Blocks critical/high/medium; rejects dirty targets. |
| `release` | Blocks all severities including low; rejects dirty targets; forces Release scope and provenance. |

## Provenance

**Implemented and tested.** Release scope adds a provenance report tied to repository, commit and dirty state. Release cannot clear when provenance verification fails. Full and Quick record target binding but do not require Release provenance.

## Known policy limitations

- **Experimental:** `outcomes.minimum_evidence` is part of the schema and configuration model, but the evaluator does not dynamically branch on every boolean in that object.
- **Experimental:** `paths` and per-scope adapter/command selections are resolved, but current execution does not narrow all registered adapters to those selections.
- **Experimental:** required repository-command failures are visible non-pass outcomes but are not independently used by the evaluator to force `incomplete` or `blocked`.
- **Experimental:** `ScanOptions.AllowNetwork` is not wired to external scanner process environments. Do not claim that the field prevents a third-party scanner from using its own network behavior.
- **Experimental:** `ScopeDiff` and `ScopeFile` are declared adapter metadata, but the application engine currently supplies a repository directory rather than a file list or diff.
- **Experimental:** desktop MCP host configuration paths and snippets are documented; GUI integration is not tested here.
- **Unsupported:** runtime third-party plugin loading. Adapters are compiled into the Go binary.
- **Unsupported:** cryptographic identity verification for human reviewers, artifact signing or report signing.
