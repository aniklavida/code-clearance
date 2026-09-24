package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/action"
	"github.com/aniklavida/code-clearance/internal/evidence"
)

func TestShouldFail_IncompleteNeverPasses(t *testing.T) {
	cases := []struct {
		outcome evidence.ClearanceOutcome
		failOn  string
		want    bool
	}{
		{evidence.OutcomeBlocked, "blocked", true},
		{evidence.OutcomeBlocked, "never", false},
		{evidence.OutcomeIncomplete, "blocked", true},
		{evidence.OutcomeIncomplete, "never", false},
		{evidence.OutcomeClearedWithResidualRisk, "blocked", false},
		{evidence.OutcomeClearedWithResidualRisk, "any", true},
		{evidence.OutcomeCleared, "any", false},
	}
	for _, tc := range cases {
		if got := shouldFail(tc.outcome, tc.failOn); got != tc.want {
			t.Errorf("shouldFail(%q, %q) = %v, want %v", tc.outcome, tc.failOn, got, tc.want)
		}
	}
}

func TestRun_WritesSARIFAndSummary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	sarifPath := filepath.Join(out, "out.sarif")
	jsonPath := filepath.Join(out, "report.json")
	summaryPath := filepath.Join(out, "summary.md")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--target", dir,
		"--scope", "quick",
		"--changed-only=false",
		"--sarif-out", sarifPath,
		"--json-out", jsonPath,
		"--summary-out", summaryPath,
		"--fail-on", "never",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exited %d, stderr: %s", code, stderr.String())
	}

	sarifData, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("SARIF not written: %v", err)
	}
	if err := action.ValidateSARIF(sarifData); err != nil {
		t.Fatalf("written SARIF failed structural validation: %v", err)
	}
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("JSON report not written: %v", err)
	}
	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("summary not written: %v", err)
	}
	if !strings.Contains(string(summary), "Code Clearance") {
		t.Fatalf("summary is not the expected markdown:\n%s", summary)
	}
}
