package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CurrentConfigVersion is the configuration schema generation this build
// reads and writes:
//
//	https://codeclearance.dev/schemas/v1/clearance.schema.json
//
// Compatibility rule: after v1 was published, a change that breaks an
// existing consumer (renaming/removing a field, tightening a type, making an
// optional field required) requires a schema version bump AND a migration
// entry here. See schemas/COMPATIBILITY.md, which is the durable home of the
// rule. Adding a purely optional field does not bump the version.
const CurrentConfigVersion = "v1"

// supportedConfigVersions maps every accepted version alias to the canonical
// generation. "1.0.0" is the pre-1.0 spelling of "v1"; it is normalised
// rather than rejected so that configs written before the version string was
// standardised keep working.
var supportedConfigVersions = map[string]string{
	"v1":    "v1",
	"1.0.0": "v1",
}

// MigrateConfig upgrades a clearance configuration document to the current
// schema generation and returns canonical JSON. Callers then validate and
// load it exactly as before.
//
// Two migrations are demonstrated end to end here:
//
//  1. Version normalisation: an unversioned or "1.0.0" document is rewritten
//     to CurrentConfigVersion.
//  2. Legacy scope shape: a scope whose `adapters` is a bare array of names,
//     or whose `commands` is a bare array of command strings, is rewritten to
//     the object form the current schema defines. The old array form is
//     accepted by the schema but cannot express required-vs-optional.
//
// An unknown (usually newer) version is rejected with an actionable error
// instead of being guessed at. Silently ignoring configuration fields would
// change the security verdict, which this product must never do.
func MigrateConfig(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("clearance configuration is not valid JSON: %w; supply a clearance.json matching schemas/clearance.schema.json", err)
	}

	version, _ := doc["version"].(string)
	canonical, ok := supportedConfigVersions[version]
	if !ok {
		if version != "" {
			return nil, fmt.Errorf("unsupported clearance configuration version %q; this build supports %s; migrate the configuration to a supported version or upgrade code-clearance, then rerun", version, CurrentConfigVersion)
		}
		// Pre-versioned documents predate the version field; they are the
		// same shape as v1, so treat them as v1 rather than refusing them.
		canonical = CurrentConfigVersion
	}
	doc["version"] = canonical

	if scopes, ok := doc["scopes"].(map[string]any); ok {
		for _, name := range []string{"quick", "full", "release"} {
			scope, ok := scopes[name].(map[string]any)
			if !ok {
				continue
			}
			normalizeLegacyScope(scope)
		}
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode migrated clearance configuration: %w", err)
	}
	return out, nil
}

// normalizeLegacyScope rewrites the legacy bare-array scope shapes in place.
func normalizeLegacyScope(scope map[string]any) {
	if arr, ok := scope["adapters"].([]any); ok {
		scope["adapters"] = map[string]any{
			"required": arr,
			"optional": []any{},
		}
	}
	if arr, ok := scope["commands"].([]any); ok {
		rules := make([]any, 0, len(arr))
		for _, item := range arr {
			switch v := item.(type) {
			case string:
				rules = append(rules, map[string]any{"name": v, "run": v})
			case map[string]any:
				rules = append(rules, v)
			}
		}
		scope["commands"] = map[string]any{
			"required": rules,
			"optional": []any{},
		}
	}
}
