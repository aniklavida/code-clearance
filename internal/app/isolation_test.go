package app

import (
	"context"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// Done-when: one optional/non-required scanner crashing mid-run must leave
// every other adapter's results intact. The engine runs adapters concurrently;
// a panic in one goroutine must be contained and recorded, not allowed to take
// down the process or discard the work the other goroutines completed.
func TestEngine_OnePanickingAdapterDoesNotAbortOrCorruptOthers(t *testing.T) {
	dir := initTestGitRepo(t)

	findingFor := func(tool, id string) evidence.Finding {
		return evidence.Finding{
			ID:                 id,
			Fingerprint:        "fp-" + id,
			Tool:               tool,
			RuleID:             "rule-" + id,
			NativeSeverity:     "LOW",
			NormalizedSeverity: evidence.SeverityLow,
			Locations:          []evidence.Location{{URI: tool + ".go"}},
			Evidence:           evidence.FindingEvidence{Details: tool + " detail"},
		}
	}

	okAdapter := func(tool, id string) ScannerAdapter {
		return func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			return []evidence.RunOutcome{{
				Tool:        tool,
				ToolVersion: "v1",
				Command:     tool + " scan",
				ExitCode:    0,
				Status:      evidence.StatusOK,
				Findings:    []evidence.Finding{findingFor(tool, id)},
			}}
		}
	}

	panickingAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		panic("simulated optional scanner adapter crash")
	}

	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"good-alpha", "good-gamma"}

	engine := NewEngine(okAdapter("good-alpha", "F-ALPHA"), panickingAdapter, okAdapter("good-gamma", "F-GAMMA"))

	// If the panic escapes the adapter goroutine the test process dies here.
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Config: &cfg})
	if err != nil {
		t.Fatalf("one adapter panicking must not fail the whole scan: %v", err)
	}

	runs := make(map[string]evidence.RunOutcome)
	for _, r := range report.Runs {
		runs[r.Tool] = r
	}

	for _, tool := range []string{"good-alpha", "good-gamma"} {
		r, ok := runs[tool]
		if !ok {
			t.Fatalf("adapter %q produced no run outcome; a sibling adapter's panic corrupted it", tool)
		}
		if r.Status != evidence.StatusOK {
			t.Fatalf("adapter %q status = %s, want ok; a sibling adapter's panic changed it", tool, r.Status)
		}
	}

	found := make(map[string]bool)
	for _, f := range report.Findings {
		found[f.ID] = true
	}
	if !found["F-ALPHA"] || !found["F-GAMMA"] {
		t.Fatalf("findings from surviving adapters were lost: got %v", found)
	}

	var crashedRecorded bool
	for _, r := range report.Runs {
		if strings.Contains(r.StderrTail, "panicked") {
			crashedRecorded = true
			if r.Status == evidence.StatusOK || r.Status == evidence.StatusFindings {
				t.Fatalf("a panicking adapter was reported as a pass (status=%s)", r.Status)
			}
		}
	}
	if !crashedRecorded {
		t.Fatal("the panicking adapter was not recorded as a crashed check; its failure is invisible")
	}

	// The verdict is still computed from the surviving evidence, and required
	// adapters that completed allow a pass.
	if report.Outcome != evidence.OutcomeCleared {
		t.Fatalf("expected surviving required adapters to clear, got %s (reason: %s)", report.Outcome, report.Reason)
	}
}
