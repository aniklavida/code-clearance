# Configuration

**Status: Implemented and tested** for the v1 configuration schema, loading, profile resolution and policy evaluation described below. Fields that are parsed but do not yet constrain execution are called out explicitly.

## File discovery and format

Code Clearance looks for `clearance.yaml`, then `clearance.json`, in the target directory. The current loader and generator use JSON encoding. Generated files are indented JSON, which is valid YAML 1.2, but ordinary YAML syntax such as unquoted keys, lists or comments is **Unsupported** until the loader accepts it.

The authoritative contract is [`schemas/clearance.schema.json`](../schemas/clearance.schema.json). Compatibility rules are in [`schemas/COMPATIBILITY.md`](../schemas/COMPATIBILITY.md). Code Clearance validates a configuration before loading it; unknown versions and schema violations fail with an actionable error.

Create a proposal without writing it:

```bash
code-clearance init
```

Write the proposal after review:

```bash
code-clearance init --approve
```

Replace an existing generated file only with explicit approval:

```bash
code-clearance init --approve --force
```

`init` detects languages, manifests and lockfiles, probes built-in adapters and proposes repository commands. It does not install tools.

## Complete v1 example

```json
{
  "version": "v1",
  "adapters": {
    "required": ["gitleaks", "osv-scanner"],
    "optional": ["semgrep", "trivy"]
  },
  "paths": {
    "include": ["**/*"],
    "exclude": [".git/**", "vendor/**", "node_modules/**"]
  },
  "scopes": {
    "quick": {
      "allow_dirty": true
    },
    "full": {
      "allow_dirty": false
    },
    "release": {
      "allow_dirty": false
    }
  },
  "policy": {
    "blocking_severities": ["critical", "high"],
    "allow_dirty": false,
    "accepted_risks": [
      {
        "fingerprint": "<finding-fingerprint>",
        "reason": "Temporary, reviewed exception",
        "expires_at": "2030-01-01T00:00:00Z",
        "owner": "security-owner"
      }
    ],
    "human_required_classes": [
      {
        "tool": "gitleaks",
        "severity": "critical"
      }
    ]
  },
  "commands": {
    "required": [
      {
        "name": "test",
        "run": "go test ./...",
        "timeout_seconds": 120
      }
    ],
    "optional": [
      {
        "name": "build",
        "run": "go build ./...",
        "timeout_seconds": 60
      }
    ],
    "allow": []
  },
  "limits": {
    "timeout_seconds": 30,
    "max_concurrency": 4
  },
  "outcomes": {
    "minimum_evidence": {
      "cleared": {
        "required_adapters_must_pass": true,
        "zero_blocking_findings": true,
        "clean_tree_required": true
      },
      "cleared_with_residual_risk": {
        "accepted_risks_unexpired": true
      },
      "blocked": {
        "blocking_finding_present": true
      },
      "incomplete": {
        "missing_required_adapter": true,
        "crashed_or_timed_out": true
      }
    }
  }
}
```

## Fields

### `version`

**Implemented and tested.** `v1` is canonical. `1.0.0` is accepted and migrated to `v1`. Unknown versions are rejected.

### `adapters`

**Implemented and tested.** `required` names adapters that must complete for the selected profile. A missing, skipped, unavailable, crashed or timed-out required adapter produces `incomplete` in Quick/Full and `blocked` in Release. `optional` names adapters whose unavailability remains visible under `uncovered` but does not by itself prevent a pass.

Configuration controls policy requirements. It does not dynamically instantiate an adapter. A configured name with no registered adapter is reported as a missing required check; built-in adapters are registered by the CLI binary.

Built-in names are:

| Name | Capability | Recorded status |
|---|---|---|
| `gitleaks` | Secret scanning | **Implemented and tested** |
| `osv-scanner` | Dependency vulnerabilities | **Implemented and tested** |
| `semgrep` | Static analysis | **Experimental** |
| `trivy` | Filesystem dependency scanning | **Experimental** |

A proposed configuration makes Gitleaks available on the host required. It makes OSV-Scanner required when the detected stack has a manifest or lockfile, and Semgrep required when code and an installed Semgrep binary are detected. Trivy remains optional in generated configuration.

### `paths`

**Experimental.** `include` and `exclude` are validated, stored and resolved into a profile, but the current scan path does not apply them to adapter targets. File enumeration excludes `.git`, `.clearance`, `node_modules` and `vendor` for non-Git targets. Treat narrower include/exclude rules as configuration evidence, not proof of narrower scanner execution.

### `scopes`

**Implemented and tested** for scope selection, profile override resolution and dirty-tree policy. Each scope may override `adapters`, `commands`, `allow_dirty`, `paths`, `policy`, `limits` and `outcomes`.

Current execution boundaries:

- **Implemented and tested:** Quick resolves dirty-tree files, a supplied base-commit diff, or `HEAD~1` into report coverage.
- **Implemented and tested:** Full enumerates tracked and untracked non-ignored files.
- **Implemented and tested:** Release uses the full file set and requires verified Git provenance.
- **Experimental:** registered scanners receive the repository directory in every scope; the resolved changed-file list is not yet passed to them.
- **Experimental:** per-scope adapter and command lists are resolved, but scan execution currently schedules all registered adapters and all resolved commands.

### `policy`

**Implemented and tested.** `blocking_severities` selects normalized severity bands. `allow_dirty` controls whether a dirty target can clear. `accepted_risks` matches by finding ID, fingerprint or rule ID and requires a reason and expiry. `human_required_classes` matches by rule ID, tool and/or severity; agent/tool dispositions do not clear a matching finding, but a human disposition can.

Risk acceptance also requires an owner at evaluation time. A missing owner, invalid expiry or expired acceptance remains blocking for a blocking-severity finding. The `Tool` field is stored in accepted-risk evidence but is not currently an acceptance selector.

### `commands`

**Implemented and tested** for command parsing, allowlisting, bounded execution and status capture. Each rule has `name`, `run` and optional `timeout_seconds`.

Commands are tokenized into an executable and argument array. Code Clearance does not invoke `sh -c`. Newlines, shell command forms, repository-external executable paths and executable names not on the allowlist are rejected. `commands.allow` additively permits another bare executable name after review; it does not permit a path or shell wrapper.

**Experimental:** a failed required repository command is visible as `crashed`, `timed-out` or `unavailable`, but current policy evaluation gates required adapters, not command names. Do not treat required-command failures as independently blocking until that behavior is implemented and tested.

### `limits`

**Implemented and tested.** `max_concurrency` bounds simultaneous adapter and command tasks. `timeout_seconds` is the default scanner/command bound exposed by configuration. Built-in scanner adapters currently use their own 20-second adapter timeout; repository commands use their rule timeout or 20 seconds by default.

### `outcomes`

**Experimental.** The object is schema-validated and documents minimum evidence, but the current evaluator does not dynamically switch every branch on these booleans. The hard-coded behavior is documented in [Policy](POLICY.md).

## Presets

**Implemented and tested.** `code-clearance run --preset <name>` applies deterministic policy overrides:

| Preset | Blocking severities | Dirty working tree |
|---|---|---|
| `individual` | critical, high | allowed in Quick; blocked in Full/Release |
| `team` | critical, high, medium | blocked |
| `release` | critical, high, medium, low | blocked and forces Release scope |

An empty preset preserves repository policy. Release scope applies the release preset when no explicit preset is supplied.

## Security-sensitive configuration rules

- **Implemented and tested:** commands never become arbitrary shell execution.
- **Implemented and tested:** source upload is not part of the application core.
- **Implemented and tested:** normalized finding text is redacted before reports or MCP payloads; raw scanner bytes remain local.
- **Implemented and tested:** a missing required adapter cannot be represented as cleared.
- **Experimental:** the `allow_network` scan option exists in Go but does not currently control external scanner network behavior.
