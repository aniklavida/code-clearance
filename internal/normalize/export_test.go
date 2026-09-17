package normalize

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/schema"
)

func sampleReportPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "testdata", "sample-report.json"),
		filepath.Join("testdata", "sample-report.json"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatal("sample-report.json not found")
	return ""
}

func TestSampleReport_ValidatesAgainstSchema(t *testing.T) {
	p := sampleReportPath(t)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}

	if err := schema.ValidateReport(data); err != nil {
		t.Fatalf("sample report failed schema validation: %v", err)
	}
}

func TestSampleReport_RoundTripsThroughGoTypesWithoutLoss(t *testing.T) {
	p := sampleReportPath(t)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}

	var rep1 evidence.Report
	if err := json.Unmarshal(data, &rep1); err != nil {
		t.Fatalf("unmarshal rep1: %v", err)
	}

	// Marshal back to JSON
	encoded, err := json.Marshal(rep1)
	if err != nil {
		t.Fatalf("marshal rep1: %v", err)
	}

	// Unmarshal into rep2
	var rep2 evidence.Report
	if err := json.Unmarshal(encoded, &rep2); err != nil {
		t.Fatalf("unmarshal rep2: %v", err)
	}

	// Compare rep1 and rep2 for exact equality
	if !reflect.DeepEqual(rep1, rep2) {
		t.Fatal("round-trip through Go types produced differences; data was lost during marshal/unmarshal")
	}

	// Check core fields are populated
	if rep1.SchemaVersion != "v1" {
		t.Errorf("schema version = %q, want v1", rep1.SchemaVersion)
	}
	if len(rep1.Findings) == 0 {
		t.Fatal("expected findings in sample report")
	}
	f := rep1.Findings[0]
	if f.NativeSeverity == "" {
		t.Error("expected non-empty native severity")
	}
	if f.RawArtifact.URI == "" {
		t.Error("expected non-empty raw artifact URI")
	}
}

func TestSampleReport_ExportsToValidSARIF(t *testing.T) {
	p := sampleReportPath(t)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}

	var rep evidence.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	sarifLog, err := Export(rep)
	if err != nil {
		t.Fatalf("Export to SARIF failed: %v", err)
	}

	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("marshal SARIF log: %v", err)
	}

	// Verify SARIF parses back through our SARIF parser
	parsed, err := Parse(sarifBytes)
	if err != nil {
		t.Fatalf("exported SARIF failed Parse: %v", err)
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", parsed.Version)
	}
	if len(parsed.Runs) == 0 {
		t.Fatal("expected runs in exported SARIF")
	}

	// Verify results match finding count
	totalResults := 0
	for _, run := range parsed.Runs {
		totalResults += len(run.Results)
	}
	if totalResults != len(rep.Findings) {
		t.Errorf("SARIF results count = %d, want %d", totalResults, len(rep.Findings))
	}
}
