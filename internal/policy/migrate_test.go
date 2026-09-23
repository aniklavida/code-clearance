package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/schema"
)

// Done-when: a real migration is demonstrated end to end. The old-shaped
// config is accepted by the current schema (it was a valid v1 document), then
// MigrateConfig normalises its version and legacy scope arrays, and Load reads
// the migrated result into a working configuration.
func TestMigrateConfig_OldVersionAndLegacyShapesUpgradeEndToEnd(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "migration", "clearance-v1.0.0.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read old config fixture: %v", err)
	}

	// The pre-standardisation document is still a valid v1 shape.
	if err := schema.ValidateClearance(original); err != nil {
		t.Fatalf("old config should validate under v1: %v", err)
	}

	migrated, err := MigrateConfig(original)
	if err != nil {
		t.Fatalf("MigrateConfig: %v", err)
	}
	if !strings.Contains(string(migrated), `"v1"`) {
		t.Fatalf("migrated config does not carry the canonical version:\n%s", migrated)
	}
	if err := schema.ValidateClearance(migrated); err != nil {
		t.Fatalf("migrated config must still validate: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load migrated config: %v", err)
	}
	if cfg.Version != CurrentConfigVersion {
		t.Fatalf("loaded version = %q, want %q", cfg.Version, CurrentConfigVersion)
	}

	// The legacy bare-array scope shapes were expanded to the object form, and
	// the resulting profile still resolves the same adapters and commands.
	prof := cfg.ActiveProfile("quick")
	if !reflect.DeepEqual(prof.Adapters.Required, []string{"gitleaks", "osv-scanner"}) {
		t.Fatalf("legacy scope adapters did not migrate: %v", prof.Adapters.Required)
	}
	if len(prof.Commands.Required) != 1 || prof.Commands.Required[0].Run != "go test ./..." {
		t.Fatalf("legacy scope commands did not migrate: %+v", prof.Commands.Required)
	}
}

// An unknown (usually newer) version is rejected with an actionable message
// rather than being guessed at.
func TestMigrateConfig_UnknownVersionRejectedWithActionableMessage(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "migration", "clearance-v9-unknown.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read unknown-version fixture: %v", err)
	}

	if _, err := MigrateConfig(data); err == nil {
		t.Fatal("MigrateConfig accepted an unsupported configuration version")
	}

	_, err = Load(path)
	if err == nil {
		t.Fatal("Load accepted an unsupported configuration version")
	}
	msg := err.Error()
	for _, want := range []string{"v9", CurrentConfigVersion, "rerun"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("migration error %q does not contain %q", msg, want)
		}
	}
}

// A pre-versioned document predates the version field but is otherwise the v1
// shape, so it is treated as v1 rather than refused.
func TestMigrateConfig_UnversionedDocumentTreatedAsV1(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "migration", "clearance-v1.0.0.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "version")
	unversioned, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	migrated, err := MigrateConfig(unversioned)
	if err != nil {
		t.Fatalf("MigrateConfig on unversioned document: %v", err)
	}
	if !strings.Contains(string(migrated), `"v1"`) {
		t.Fatalf("unversioned document was not stamped with %q", CurrentConfigVersion)
	}
	if err := schema.ValidateClearance(migrated); err != nil {
		t.Fatalf("migrated unversioned document must validate: %v", err)
	}
}

// Reports written under the pre-standardisation version alias remain readable.
func TestReportSchema_OldVersionAliasStillReads(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "sample-report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["schema_version"] = "1.0.0"
	old, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateReport(old); err != nil {
		t.Fatalf("a report using the old version alias must still validate: %v", err)
	}
}
