package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// Done-when: a scanner that exits with an unexpected code is recorded as a
// crash, and a required check that crashed forces Incomplete — never a pass.
func TestEngine_CrashingAdapterProducesIncompleteNeverPass(t *testing.T) {
	cmdName, args := shellExit(3)

	crashAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		res := Run(ctx, Spec{
			Name:    "crashing-tool",
			Command: cmdName,
			Args:    args,
			Dir:     targetDir,
			Timeout: 5 * time.Second,
		})
		status := evidence.StatusOK
		switch {
		case res.Err != nil:
			status = evidence.StatusNotInstalled
		case res.TimedOut:
			status = evidence.StatusTimedOut
		case res.ExitCode != 0 && res.ExitCode != 1:
			status = evidence.StatusCrashed
		}
		return []evidence.RunOutcome{{
			Tool:        "crashing-tool",
			ToolVersion: "v1",
			Command:     "crashing-tool --scan",
			ExitCode:    res.ExitCode,
			Status:      status,
			StderrTail:  res.Diagnostic(),
		}}
	}

	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"crashing-tool"}

	engine := NewEngine(crashAdapter)
	report, err := engine.ScanWithOptions(context.Background(), initTestGitRepo(t), ScanOptions{Config: &cfg})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if report.Outcome == evidence.OutcomeCleared || report.Outcome == evidence.OutcomeClearedWithResidualRisk {
		t.Fatalf("a crashing required scanner produced a passing verdict: %s", report.Outcome)
	}
	if report.Outcome != evidence.OutcomeIncomplete {
		t.Fatalf("outcome = %s, want %s", report.Outcome, evidence.OutcomeIncomplete)
	}

	var named bool
	for _, u := range report.Uncovered.Crashed {
		if u.Tool == "crashing-tool" {
			named = true
		}
	}
	if !named {
		t.Fatal("the crashed required check must be named in report.Uncovered.Crashed")
	}
}

// Done-when: a dirty working tree is recorded honestly, and when the active
// policy does not allow a dirty tree the outcome is Blocked, never a pass.
func TestEngine_DirtyTreeWithAllowDirtyFalseProducesBlockedNeverPass(t *testing.T) {
	dir := initTestGitRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("uncommitted change\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cleanAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{{
			Tool:        "clean-tool",
			ToolVersion: "v1",
			Command:     "clean-tool scan",
			ExitCode:    0,
			Status:      evidence.StatusOK,
			Findings:    []evidence.Finding{},
		}}
	}

	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"clean-tool"}

	engine := NewEngine(cleanAdapter)
	// full scope carries allow_dirty=false in the default config.
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Scope: "full", Config: &cfg})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if !report.Target.Dirty {
		t.Fatal("the report must record that the working tree was dirty")
	}
	if report.Outcome == evidence.OutcomeCleared || report.Outcome == evidence.OutcomeClearedWithResidualRisk {
		t.Fatalf("a dirty tree with allow_dirty=false produced a passing verdict: %s", report.Outcome)
	}
	if report.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("outcome = %s, want %s", report.Outcome, evidence.OutcomeBlocked)
	}
}
