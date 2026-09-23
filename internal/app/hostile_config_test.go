package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/schema"
)

// A clearance configuration from an untrusted repository must never become
// arbitrary shell execution. These tests plant a deliberately hostile
// configuration and prove it fails safely: the shell forms are refused, the
// executable allowlist refuses unknown binaries, and the argument-vector
// parser keeps metacharacters inert instead of evaluating them.
//
// The fixture named clearance.yaml is the exact shape an attacker-controlled
// repository would ship. Because Code Clearance's configuration contract is
// JSON, the YAML document is rejected outright; the JSON twin
// (clearance-hostile.json) is schema-valid so that the test can drive the real
// executor rather than stopping at the parser.

func TestHostileClearanceYAML_FailsSafely(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "hostile", "clearance.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hostile fixture: %v", err)
	}

	// 1. The schema contract is JSON; a YAML document is rejected rather than
	//    guessed at.
	if err := schema.ValidateClearance(data); err == nil {
		t.Fatal("SECURITY VIOLATION: a hostile clearance.yaml was accepted by the clearance schema")
	}

	// 2. Loading it directly is refused too, and names the problem.
	//    This deliberately reuses the hostile YAML as an opaque byte stream.
	if _, err := policy.Load(path); err == nil {
		t.Fatal("SECURITY VIOLATION: policy.Load accepted a hostile clearance.yaml")
	}
}

func TestHostileClearanceConfig_CommandsNeverReachShell(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "hostile", "clearance-hostile.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hostile fixture: %v", err)
	}

	// The fixture must be a real, schema-valid configuration so the test
	// exercises the executor, not a parser rejection that would mask a gap.
	if err := schema.ValidateClearance(data); err != nil {
		t.Fatalf("hostile fixture must be schema-valid so the executor is exercised: %v", err)
	}

	cfg, err := policy.Load(path)
	if err != nil {
		t.Fatalf("load hostile fixture: %v", err)
	}

	dir := initTestGitRepo(t)
	engine := NewEngine()
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Scope: "quick", Config: &cfg})
	if err != nil {
		t.Fatalf("scan with hostile config: %v", err)
	}

	runs := make(map[string]evidence.RunOutcome)
	for _, r := range report.Runs {
		runs[r.Tool] = r
	}

	// Every dangerous rule must be recorded, refused, and explained.
	rejected := map[string]string{
		"shell-wrapper":     "arbitrary shell execution forbidden",
		"absolute-shell":    "arbitrary shell execution forbidden",
		"path-traversal":    "traverses outside repository",
		"newline-injection": "newline injection",
		"unlisted-binary":   "not on the command allowlist",
		"repo-local-binary": "not on the command allowlist",
	}
	for name, wantReason := range rejected {
		r, ok := runs["command:"+name]
		if !ok {
			t.Fatalf("hostile command %q produced no run outcome; a refused check must be recorded, not skipped", name)
		}
		if r.Status == evidence.StatusOK || r.Status == evidence.StatusFindings {
			t.Fatalf("SECURITY VIOLATION: hostile command %q was reported as a pass (status=%s)", name, r.Status)
		}
		if !strings.Contains(r.StderrTail, wantReason) {
			t.Fatalf("hostile command %q: stderr %q does not explain the refusal (%q)", name, r.StderrTail, wantReason)
		}
		if !strings.Contains(strings.ToLower(r.StderrTail), "rerun") {
			t.Fatalf("hostile command %q: message %q does not state the safe next action", name, r.StderrTail)
		}
	}

	// Metacharacters that reach an allowlisted binary must stay inert.
	for _, canary := range []string{"CANARY_SEMICOLON", "CANARY_SUBST", "CANARY_BACKTICK"} {
		if _, statErr := os.Stat(filepath.Join(dir, canary)); statErr == nil {
			t.Fatalf("SECURITY VIOLATION: canary %s was created; a shell metacharacter was evaluated", canary)
		}
	}

	// The hostile config cannot produce a passing verdict.
	if report.Outcome == evidence.OutcomeCleared || report.Outcome == evidence.OutcomeClearedWithResidualRisk {
		t.Fatalf("hostile configuration produced a passing verdict: %s", report.Outcome)
	}
}
