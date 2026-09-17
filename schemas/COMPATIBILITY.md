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

When a feature or field is superseded:
1. The old field will be marked `deprecated: true` in the schema documentation for at least one minor release cycle.
2. Runtime tools will continue to accept and emit the deprecated field alongside any replacement.
3. Automated conversion utilities will be provided before removing deprecated fields in the next major version release.
