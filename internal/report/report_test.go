package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/report"
)

// minimalValidReport returns a Report that satisfies the report schema so
// ValidateJSON tests have a clean baseline to work from.
func minimalValidReport() evidence.Report {
	now := time.Now().UTC().Format(time.RFC3339)
	return evidence.Report{
		SchemaVersion: "v1",
		Target: evidence.TargetBinding{
			Repository:  "example.com/repo",
			Commit:      "abc1234",
			Dirty:       false,
			Fingerprint: evidence.CleanTreeFingerprint,
		},
		Outcome:  evidence.OutcomeCleared,
		Runs:     []evidence.RunOutcome{},
		Findings: []evidence.Finding{},
		Uncovered: evidence.UncoveredChecks{
			Skipped:     []evidence.UncoveredCheck{},
			Crashed:     []evidence.UncoveredCheck{},
			TimedOut:    []evidence.UncoveredCheck{},
			Unavailable: []evidence.UncoveredCheck{},
		},
		Coverage: evidence.CoverageReport{
			Scope:        "quick",
			FilesChecked: []string{},
			AdaptersRan:  []string{},
			Summary:      "0 files checked",
		},
		ResidualRisk: []evidence.ResidualRiskItem{},
		Timestamps: evidence.ReportTimestamps{
			StartedAt:   now,
			CompletedAt: now,
		},
	}
}

// TestUncoveredCheckAppearsDistinctlyInBothReports verifies that a tool with
// StatusNotInstalled appears in the uncovered section of the terminal output
// and in uncovered.unavailable in the JSON output, and is NOT shown as a pass.
// We test all four categories: Skipped, Crashed, TimedOut, Unavailable.
func TestUncoveredCheckAppearsDistinctlyInBothReports(t *testing.T) {
	categories := []struct {
		name    string
		jsonKey string
		setup   func(*evidence.Report)
	}{
		{
			name:    "Skipped",
			jsonKey: "skipped",
			setup: func(r *evidence.Report) {
				r.Uncovered.Skipped = []evidence.UncoveredCheck{{Tool: "missing-tool", Reason: "skipped by config"}}
				r.Runs = append(r.Runs, evidence.RunOutcome{Tool: "missing-tool", Status: evidence.StatusSkipped})
			},
		},
		{
			name:    "Crashed",
			jsonKey: "crashed",
			setup: func(r *evidence.Report) {
				r.Uncovered.Crashed = []evidence.UncoveredCheck{{Tool: "missing-tool", Reason: "segfault"}}
				r.Runs = append(r.Runs, evidence.RunOutcome{Tool: "missing-tool", Status: evidence.StatusCrashed})
			},
		},
		{
			name:    "Timed out",
			jsonKey: "timed_out",
			setup: func(r *evidence.Report) {
				r.Uncovered.TimedOut = []evidence.UncoveredCheck{{Tool: "missing-tool", Reason: "exceeded 5m"}}
				r.Runs = append(r.Runs, evidence.RunOutcome{Tool: "missing-tool", Status: evidence.StatusTimedOut})
			},
		},
		{
			name:    "Unavailable",
			jsonKey: "unavailable",
			setup: func(r *evidence.Report) {
				r.Uncovered.Unavailable = []evidence.UncoveredCheck{{Tool: "missing-tool", Reason: "not on PATH"}}
				r.Runs = append(r.Runs, evidence.RunOutcome{Tool: "missing-tool", Status: evidence.StatusNotInstalled})
			},
		},
	}

	for _, tc := range categories {
		t.Run(tc.name, func(t *testing.T) {
			r := minimalValidReport()
			tc.setup(&r)
			r.Outcome = evidence.OutcomeIncomplete
			r.Reason = "required adapter missing-tool was not installed"

			var termBuf bytes.Buffer
			if err := report.WriteTerminal(r, &termBuf); err != nil {
				t.Fatalf("WriteTerminal: %v", err)
			}
			termOut := termBuf.String()

			var jsonBuf bytes.Buffer
			if err := report.WriteJSON(r, &jsonBuf); err != nil {
				t.Fatalf("WriteJSON: %v", err)
			}

			// Terminal output must have 'Uncovered' header
			uncovIdx := strings.Index(termOut, "── Uncovered ──")
			if uncovIdx == -1 {
				t.Fatal("terminal output missing '── Uncovered ──' section header")
			}

			// Bound the check to the Uncovered section
			uncovBlock := termOut[uncovIdx:]
			if nextIdx := strings.Index(uncovBlock[15:], "── "); nextIdx != -1 {
				uncovBlock = uncovBlock[:15+nextIdx]
			}

			if !strings.Contains(uncovBlock, "missing-tool") {
				t.Errorf("missing-tool does not appear in the Uncovered block for category %s. Block content:\n%s", tc.name, uncovBlock)
			}

			if !strings.Contains(uncovBlock, tc.name+":") {
				t.Errorf("Uncovered block missing category label %q", tc.name+":")
			}

			// Check that the tool is not labelled as "ok" in the tools section before the Uncovered block.
			toolsIdx := strings.Index(termOut, "── Tools ──")
			if toolsIdx != -1 {
				toolsSection := termOut[toolsIdx:uncovIdx]
				if strings.Contains(toolsSection, "status=ok") && strings.Contains(toolsSection, "missing-tool") {
					t.Error("missing-tool appears with status=ok in the Tools section — it must not be shown as a pass")
				}
			}

			// JSON assertion
			var parsed map[string]any
			if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
				t.Fatalf("JSON parse: %v", err)
			}
			uncov, _ := parsed["uncovered"].(map[string]any)
			catList, _ := uncov[tc.jsonKey].([]any)
			found := false
			for _, item := range catList {
				m, _ := item.(map[string]any)
				if m != nil && m["tool"] == "missing-tool" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("missing-tool not found in JSON uncovered.%s", tc.jsonKey)
			}
		})
	}
}

// TestJSONReportValidatesAgainstSchema confirms that a well-formed report
// passes ValidateJSON, and that a broken report (missing schema_version) fails.
func TestJSONReportValidatesAgainstSchema(t *testing.T) {
	t.Run("valid report passes", func(t *testing.T) {
		r := minimalValidReport()

		var buf bytes.Buffer
		if err := report.WriteJSON(r, &buf); err != nil {
			t.Fatalf("WriteJSON: %v", err)
		}
		if err := report.ValidateJSON(buf.Bytes()); err != nil {
			t.Fatalf("ValidateJSON rejected a valid report: %v", err)
		}
	})

	t.Run("broken report rejected", func(t *testing.T) {
		// A report without schema_version must fail validation.
		broken := map[string]any{
			// schema_version intentionally omitted
			"target": map[string]any{
				"repository":  "example.com/repo",
				"commit":      "abc1234",
				"dirty":       false,
				"fingerprint": "clean",
			},
			"outcome":       "cleared",
			"runs":          []any{},
			"findings":      []any{},
			"uncovered":     map[string]any{"skipped": []any{}, "crashed": []any{}, "timed_out": []any{}, "unavailable": []any{}},
			"coverage":      map[string]any{"scope": "quick", "files_checked": []any{}, "adapters_ran": []any{}, "summary": "0 files"},
			"residual_risk": []any{},
			"timestamps":    map[string]any{"started_at": "2024-01-01T00:00:00Z", "completed_at": "2024-01-01T00:00:01Z"},
		}
		data, _ := json.Marshal(broken)
		if err := report.ValidateJSON(data); err == nil {
			t.Fatal("ValidateJSON accepted a report missing schema_version — expected an error")
		}
	})
}

// TestTerminalAndJSONReportsAgreeOnOutcomeCoverageAndUncovered builds a report
// with one passing tool and one unavailable tool and verifies that both report
// formats agree on outcome, coverage, and uncovered checks.
func TestTerminalAndJSONReportsAgreeOnOutcomeCoverageAndUncovered(t *testing.T) {
	r := minimalValidReport()

	// tool-a ran successfully
	r.Runs = append(r.Runs, evidence.RunOutcome{
		Tool:        "tool-a",
		ToolVersion: "v1.2.3",
		Command:     "tool-a scan .",
		ExitCode:    0,
		Duration:    "1.2s",
		Status:      evidence.StatusOK,
		Findings:    []evidence.Finding{},
	})
	// tool-b was not installed
	r.Runs = append(r.Runs, evidence.RunOutcome{
		Tool:        "tool-b",
		ToolVersion: "unknown",
		Command:     "tool-b scan .",
		ExitCode:    -1,
		Duration:    "0s",
		Status:      evidence.StatusNotInstalled,
		Findings:    []evidence.Finding{},
	})

	r.Coverage.AdaptersRan = []string{"tool-a"}
	r.Uncovered.Unavailable = []evidence.UncoveredCheck{
		{Tool: "tool-b", Reason: "not installed"},
	}
	r.Outcome = evidence.OutcomeIncomplete
	r.Reason = "tool-b was not installed"

	// Terminal
	var termBuf bytes.Buffer
	if err := report.WriteTerminal(r, &termBuf); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	termOut := termBuf.String()

	// JSON
	var jsonBuf bytes.Buffer
	if err := report.WriteJSON(r, &jsonBuf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}

	// JSON uncovered.unavailable must contain tool-b
	uncov, _ := parsed["uncovered"].(map[string]any)
	unavail, _ := uncov["unavailable"].([]any)
	foundToolB := false
	for _, item := range unavail {
		m, _ := item.(map[string]any)
		if m != nil && m["tool"] == "tool-b" {
			foundToolB = true
			break
		}
	}
	if !foundToolB {
		t.Error("JSON uncovered.unavailable does not contain tool-b")
	}

	// Terminal must contain tool-b in uncovered section
	if !strings.Contains(termOut, "tool-b") {
		t.Error("terminal output does not mention tool-b")
	}
	uncovIdx := strings.Index(termOut, "Uncovered")
	if uncovIdx == -1 {
		t.Fatal("terminal output missing Uncovered section")
	}
	if !strings.Contains(termOut[uncovIdx:], "tool-b") {
		t.Error("tool-b not found in the Uncovered section of terminal output")
	}

	// JSON outcome must match what the terminal says
	jsonOutcome, _ := parsed["outcome"].(string)
	if jsonOutcome == "" {
		t.Fatal("JSON outcome missing")
	}
	if !strings.Contains(termOut, string(jsonOutcome)) {
		t.Errorf("terminal output does not contain JSON outcome %q", jsonOutcome)
	}

	// JSON coverage.adapters_ran must contain tool-a but NOT tool-b
	coverage, _ := parsed["coverage"].(map[string]any)
	adaptersRan, _ := coverage["adapters_ran"].([]any)
	hasToolA, hasToolB := false, false
	for _, a := range adaptersRan {
		if a == "tool-a" {
			hasToolA = true
		}
		if a == "tool-b" {
			hasToolB = true
		}
	}
	if !hasToolA {
		t.Error("JSON coverage.adapters_ran does not contain tool-a")
	}
	if hasToolB {
		t.Error("JSON coverage.adapters_ran incorrectly contains tool-b (unavailable tool)")
	}

	// Terminal must mention tool-a's status as ok
	if !strings.Contains(termOut, "tool-a") {
		t.Error("terminal output does not mention tool-a")
	}
	if !strings.Contains(termOut, "status=ok") {
		t.Error("terminal output does not show tool-a's status as ok")
	}
}
