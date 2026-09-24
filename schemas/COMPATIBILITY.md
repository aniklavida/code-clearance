# Schema Compatibility and Migration Rules

This document specifies the compatibility and evolution guarantees for the Code Clearance schema contracts:
- `schemas/report.schema.json` (the evidence and clearance report contract)
- `schemas/clearance.schema.json` (the repository policy configuration contract)

These contracts define public promises. Once published in a major version, consumers (CLI, MCP agents, and CI automations) rely on them for deterministic interpretation of security clearance evidence.

---

## 1. Versioning Model

All schemas follow Semantic Versioning (SemVer) with major version identifiers rooted in schema URI identifiers:

- `https://codeclearance.dev/schemas/v1/report.schema.json`
- `https://codeclearance.dev/schemas/v1/clearance.schema.json`

The top-level `schema_version` (in reports) and `version` (in configurations) declare the active schema generation. Within major version `v1`:
- Patch and minor additions must remain backwards-compatible for all existing consumers.
- Any breaking change requires incrementing to `v2` and providing an automated migration path.

---

## 2. Invariant Safety Guarantees

The following invariants are hard-locked across all versions and may never be loosened:

1. **Unavailable Required Checks Never Pass:**
   If a required scanner or command is missing from PATH, fails to execute, crashes, times out, or is skipped, the clearance outcome must be `incomplete`. It is structurally impossible to represent an unavailable required check as a pass.
   The report schema enforces this through the optional `uncovered.required_incomplete` boolean: when it is `true`, `outcome` must be `incomplete`. An **optional** check being unavailable does not force `incomplete` — it stays visible under `uncovered.unavailable` so coverage is not hidden. (This made the earlier schema, which forced `incomplete` for *any* unavailable check, reject valid reports produced by the engine whenever an optional scanner was absent; the invariant was narrowed to the required checks it was always meant to protect, which is not a loosening of that invariant.)
2. **Preservation of Raw Evidence:**
   Normalization must never discard source evidence. `native_severity` and `raw_artifact` references are mandatory fields on every finding. Removing or making them optional is prohibited.
3. **Deterministic Verdicts:**
   Identical evidence and configuration must produce an identical outcome. Verdict computation must never query wall-clock time or depend on process execution order.

---

## 3. What May Change Within a Major Version (Non-Breaking)

The following changes are permitted in minor or patch revisions of the `v1` schemas:

- **Adding new optional fields** to the report or configuration models, provided:
  - Existing parsers that ignore unknown fields continue to operate.
  - Omitting the new field preserves prior behavior.
- **Adding new non-blocking status or category values** to open enumerations, provided existing tooling handles unknown values gracefully.
- **Adding new optional adapters** or analysis capabilities.
- **Relaxing path or format restrictions** where documents valid under prior revisions remain valid.
- **Clarifying descriptions, titles, examples, and documentation** within the schemas.

---

## 4. What May NOT Change Within a Major Version (Breaking)

The following changes are strictly prohibited within major version `v1` and require a major version bump (`v2`):

- **Removing or renaming any existing field** in `report.schema.json` or `clearance.schema.json`.
- **Changing the type of an existing field** (e.g., changing a string to an object, or an integer to a float).
- **Making an existing optional field required.**
- **Making any required field optional** (specifically `native_severity`, `raw_artifact`, `fingerprint`, `id`, `locations`, `outcome`, `target`).
- **Altering the deterministic fingerprint derivation algorithm** for existing finding signatures, which would invalidate historical tracking and baseline matching.
- **Modifying the semantic meaning of outcome values** (`cleared`, `cleared-with-residual-risk`, `blocked`, `incomplete`).
- **Permitting an unavailable required check to evaluate to `cleared` or any pass state.**
- **Changing the exit-code semantics** of existing adapters without an adapter version update.

---

## 5. Migration and Deprecation Policy

**The version-bump rule.** Within major version `v1`, a change that can break an
existing consumer — renaming or removing a field, tightening a type, or making
an optional field required — is prohibited. If such a change is unavoidable it
must (a) bump the schema version (`v2`), (b) add a migration note here, and
(c) land a migration entry point. Purely optional additions (a new optional
field whose absence preserves prior behavior) do not require a bump; adding
`commands.allow` to the configuration schema was one such addition.

The rule is mirrored in code so it is visible where schema types are defined:
`policy.Config` and `evidence.Report` both carry comments pointing at this
document, and `policy.CurrentConfigVersion` states the canonical generation.

**Migration entry point.** `policy.MigrateConfig` upgrades a configuration
document to the current generation before it is loaded; `policy.Load` calls it
automatically. Two migrations are implemented end to end and covered by named
tests:

- Version normalisation: an unversioned document or the `"1.0.0"` alias is
  rewritten to `v1`.
- Legacy scope shape: a scope whose `adapters` is a bare array of names, or
  whose `commands` is a bare array of command strings, is rewritten to the
  object form the current schema defines.

An unknown (usually newer) version is rejected with an actionable error naming
the version and the supported generation, rather than being guessed at, because
silently ignoring configuration fields would change the security verdict.

When a feature or field is superseded:
1. The old field will be marked `deprecated: true` in the schema documentation for at least one minor release cycle.
2. Runtime tools will continue to accept and emit the deprecated field alongside any replacement.
3. Automated conversion utilities will be provided before removing deprecated fields in the next major version release.
