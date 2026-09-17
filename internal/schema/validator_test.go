package schema

import (
	"os"
	"testing"
)

func TestValidator_ValidatesReportSchema(t *testing.T) {
	p, err := FindSchemaPath("report.schema.json")
	if err != nil {
		t.Fatalf("FindSchemaPath: %v", err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	s, err := LoadSchema(p)
	if err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}

	if s.ID == "" {
		t.Error("report schema missing $id")
	}
	if len(s.Required) == 0 {
		t.Error("report schema missing required fields")
	}

	// Schema file itself is valid JSON
	if len(data) == 0 {
		t.Fatal("empty schema file")
	}
}

func TestValidator_ValidatesClearanceSchema(t *testing.T) {
	p, err := FindSchemaPath("clearance.schema.json")
	if err != nil {
		t.Fatalf("FindSchemaPath: %v", err)
	}

	s, err := LoadSchema(p)
	if err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}

	if s.ID == "" {
		t.Error("clearance schema missing $id")
	}
	if len(s.Required) == 0 {
		t.Error("clearance schema missing required fields")
	}
}

func TestValidator_RejectsMissingRequiredField(t *testing.T) {
	badJSON := []byte(`{
		"schema_version": "v1",
		"target": {
			"repository": "repo",
			"commit": "sha",
			"dirty": false,
			"fingerprint": "clean"
		}
	}`)

	err := ValidateReport(badJSON)
	if err == nil {
		t.Fatal("expected validation error for missing required fields")
	}
}

func TestValidator_ValidatesSampleClearanceConfig(t *testing.T) {
	candidates := []string{
		"../../testdata/sample-clearance.json",
		"testdata/sample-clearance.json",
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Fatal("sample-clearance.json not found")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample-clearance.json: %v", err)
	}

	if err := ValidateClearance(data); err != nil {
		t.Fatalf("sample-clearance.json failed clearance schema validation: %v", err)
	}
}
