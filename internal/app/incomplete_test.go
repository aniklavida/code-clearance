package app

import (
	"context"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// The product's central claim is that a required scanner which is missing
// produces Incomplete and never a pass. The schema makes the dishonest
// alternative unrepresentable and the policy layer enforces it — but both were
// tested in isolation, and neither could see the failure that actually existed:
//
// an unavailable scanner produced no RunOutcome at all, so it did not appear in
// the report as unavailable. It was not recorded as passed; it was not recorded.
// The policy layer never saw an unavailable adapter because absence produced
// nothing to see, and the required set was derived from whichever adapters had
// run, which made the requirement circular.
//
// These tests assert the claim end to end, through the engine, which is where a
// user meets it.

func unavailableAdapter(tool string) ScannerAdapter {
	return func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{{
			Tool:        tool,
			ToolVersion: "unknown",
			Command:     tool,
			Status:      evidence.StatusNotInstalled,
		}}
	}
}

func TestEngine_MissingRequiredScannerProducesIncompleteNotSilence(t *testing.T) {
	dir := initTestGitRepo(t)

	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"absent-scanner"}

	engine := NewEngine(unavailableAdapter("absent-scanner"))
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Config: &cfg})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if report.Outcome != evidence.OutcomeIncomplete {
		t.Fatalf("a missing required scanner must produce %q, got %q",
			evidence.OutcomeIncomplete, report.Outcome)
	}

	// Incomplete is not enough on its own: the report must say which tool.
	var named bool
	for _, u := range report.Uncovered.Unavailable {
		if u.Tool == "absent-scanner" {
			named = true
		}
	}
	if !named {
		t.Fatal("the report must name the unavailable tool, not merely report Incomplete")
	}
}

func TestEngine_AnUnavailableScannerAppearsInTheReport(t *testing.T) {
	dir := initTestGitRepo(t)

	engine := NewEngine(unavailableAdapter("ghost-scanner"))
	report, err := engine.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// The specific regression: returning nil for an unavailable scanner made it
	// disappear. A report that does not mention a tool cannot be distinguished
	// from one where the tool was never configured.
	var found bool
	for _, r := range report.Runs {
		if r.Tool == "ghost-scanner" {
			found = true
			if r.Status == evidence.StatusOK {
				t.Fatal("an unavailable scanner reported StatusOK")
			}
		}
	}
	if !found {
		t.Fatal("an unavailable scanner produced no run outcome; absence must be recorded, not silent")
	}
}

func TestEngine_DeclaredRequirementIsNotOverwrittenByWhatHappenedToRun(t *testing.T) {
	dir := initTestGitRepo(t)

	// The caller requires a scanner that is not among the adapters supplied.
	// If the engine rewrites Required from the runs that occurred, this passes
	// as Cleared and the requirement means nothing.
	cfg := policy.DefaultConfig()
	cfg.Scopes.Quick.AdaptersLegacy = nil
	cfg.Adapters.Required = []string{"never-supplied"}

	engine := NewEngine(func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{{
			Tool:        "something-else",
			ToolVersion: "v1",
			Command:     "something-else",
			Status:      evidence.StatusOK,
		}}
	})
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Config: &cfg})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if report.Outcome == evidence.OutcomeCleared {
		t.Fatal("a requirement the caller declared was overwritten by whatever ran; the requirement is circular")
	}
	if !strings.Contains(report.Reason, "never-supplied") && !reportMentions(report, "never-supplied") {
		t.Fatalf("the report must name the missing requirement; outcome=%q reason=%q", report.Outcome, report.Reason)
	}
}

// reportMentions reports whether a tool name appears anywhere the report
// records an uncovered check, which is where a missing requirement lands.
func reportMentions(r evidence.Report, tool string) bool {
	for _, group := range [][]evidence.UncoveredCheck{
		r.Uncovered.Unavailable, r.Uncovered.Skipped,
		r.Uncovered.Crashed, r.Uncovered.TimedOut,
	} {
		for _, u := range group {
			if strings.Contains(u.Tool, tool) || strings.Contains(u.Reason, tool) {
				return true
			}
		}
	}
	return false
}
