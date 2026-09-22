package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/schema"
	"github.com/aniklavida/code-clearance/internal/store"
)

func requireTool(t *testing.T, tool string) {
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("skipping test because %s is not installed", tool)
	}
}

func TestUnattendedAgentLoopReal(t *testing.T) {
	requireTool(t, "gitleaks")

	ctx := context.Background()

	tmpDir := t.TempDir()

	fixtureRepo := "../../testdata/fixtures/go"
	entries, err := os.ReadDir(fixtureRepo)
	if err != nil {
		t.Fatalf("read fixture repo: %v", err)
	}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(fixtureRepo, e.Name()))
		os.WriteFile(filepath.Join(tmpDir, e.Name()), data, 0644)
	}

	configJSON := `{
		"version": "v1",
		"adapters": {
			"required": ["gitleaks"],
			"optional": []
		},
		"paths": { "include": ["**/*"], "exclude": ["**/.clearance/**"] },
		"scopes": { "quick": { "adapters": [], "commands": [], "allow_dirty": true }, "full": { "adapters": [], "commands": [], "allow_dirty": true }, 
			"release": { 
			    "adapters": ["gitleaks"], 
			    "commands": [], 
			    "allow_dirty": true,
			    "policy": {
			        "blocking_severities": ["critical", "high", "medium"],
			        "allow_dirty": true,
			        "accepted_risks": []
			    }
			}
		},
		"policy": {
			"blocking_severities": ["critical", "high", "medium"],
			"allow_dirty": true,
			"accepted_risks": []
		},
		"commands": { "required": [], "optional": [] },
		"limits": { "timeout_seconds": 30, "max_concurrency": 4 },
		"outcomes": {
			"minimum_evidence": {
				"cleared": { "required_adapters_must_pass": true, "zero_blocking_findings": true, "clean_tree_required": false },
				"cleared_with_residual_risk": { "accepted_risks_unexpired": true },
				"blocked": { "blocking_finding_present": true },
				"incomplete": { "missing_required_adapter": true, "crashed_or_timed_out": true }
			}
		}
	}`
	os.WriteFile(filepath.Join(tmpDir, "clearance.json"), []byte(configJSON), 0644)

	os.WriteFile(filepath.Join(tmpDir, ".gitleaksignore"), []byte(".clearance/"), 0644)

	dummyKey := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAr7ULYO1SLKbXGQpPed/j8GagMnAKymjiN83gyteEOsAAAAKAERs/DBEbP
wwAAAAtzc2gtZWQyNTUxOQAAACAr7ULYO1SLKbXGQpPed/j8GagMnAKymjiN83gyteEOsA
AAAEAx5v50Hayo1sFv5+40AX4g7gAEGUAWsHbx2EPJwB73LCvtQtg7VIsptcZCk953+PwZ
qAycArKaOI3zeDK14Q6wAAAAF2FuaWtATWRzLU1hYy1taW5pLmxvY2FsAQIDBAUG
-----END OPENSSH PRIVATE KEY-----`
	os.WriteFile(filepath.Join(tmpDir, "secret.go"), []byte("package main\n\nconst token = `\n"+dummyKey+"\n`\n"), 0644)

	// 1. Scan: clearance_run detects the hardcoded credential and produces OutcomeBlocked
	_, rep1, err := ClearanceRun(ctx, nil, ClearanceRunArgs{
		TargetDir: tmpDir,
		Profile:   "release",
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if rep1.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("Expected Blocked, got %s. Reason: %s", rep1.Outcome, rep1.Reason)
	}

	if len(rep1.Findings) == 0 {
		t.Fatalf("Expected findings from gitleaks")
	}
	fp := rep1.Findings[0].Fingerprint
	findingID := rep1.Findings[0].ID

	// 2. Challenge: agent confirms the finding via clearance_record_review
	_, _, err = RecordReview(ctx, nil, app.RecordReviewArgs{
		TargetDir:       tmpDir,
		Fingerprint:     fp,
		ChallengeStatus: string(evidence.ChallengeConfirmed),
		Reason:          "I confirmed the leaked private key token",
		ReviewerType:    "human", // Note: RecordReview enforces agent reviewer type unconditionally
	})
	if err != nil {
		t.Fatalf("record review error: %v", err)
	}

	// Regression probe: The agent MUST NOT launder its reviewer type.
	// RecordReview forces it to be agent. Let's verify it actually wrote agent.
	st, err := store.New(filepath.Join(tmpDir, ".clearance"))
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	reviews, err := st.GetReviews()
	if err != nil {
		t.Fatalf("get reviews: %v", err)
	}
	rev, ok := reviews[fp]
	if !ok {
		t.Fatalf("Review missing for %s", fp)
	}
	if string(rev.ReviewerType) != "agent" {
		t.Fatalf("ReviewerType was %s, expected agent - laundering occurred!", rev.ReviewerType)
	}

	// 3. Fix: agent retrieves fix context for the confirmed finding and applies the patch
	_, fixCtx, err := GetFixContext(ctx, nil, app.FixContextArgs{
		TargetDir:   tmpDir,
		FindingID:   findingID,
		Fingerprint: fp,
	})
	if err != nil {
		t.Fatalf("get fix context error: %v", err)
	}
	if fixCtx == nil {
		t.Fatal("expected non-nil fix context")
	}
	if fixCtx.FindingID != findingID {
		t.Fatalf("expected finding ID %s, got %s", findingID, fixCtx.FindingID)
	}
	if fixCtx.Fingerprint != fp {
		t.Fatalf("expected fingerprint %s, got %s", fp, fixCtx.Fingerprint)
	}
	if fixCtx.Tool != "gitleaks" {
		t.Fatalf("expected tool gitleaks, got %s", fixCtx.Tool)
	}
	if fixCtx.ChallengeStatus != evidence.ChallengeConfirmed {
		t.Fatalf("expected confirmed challenge status, got %s", fixCtx.ChallengeStatus)
	}
	if len(fixCtx.Constraints) == 0 {
		t.Fatal("expected constraints in fix context")
	}

	patchDiff := "--- a/secret.go\n+++ b/secret.go\n@@ -3,7 +3,1 @@\n-const token = `\n" + dummyKey + "\n`\n+const token = \"\"\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "secret.go"), []byte("package main\n\nconst token = \"\"\n"), 0644); err != nil {
		t.Fatalf("failed to apply patch to secret.go: %v", err)
	}

	// 4. Verify: agent runs targeted verification rerun via clearance_verify
	_, repVerify, err := ClearanceVerify(ctx, nil, app.VerifyArgs{
		TargetDir:   tmpDir,
		FindingID:   findingID,
		Fingerprint: fp,
		PatchDiff:   patchDiff,
		Approved:    true,
	})
	if err != nil {
		t.Fatalf("clearance_verify error: %v", err)
	}
	if repVerify.Outcome != evidence.OutcomeCleared {
		t.Fatalf("expected verify outcome Cleared, got %s (reason: %s)", repVerify.Outcome, repVerify.Reason)
	}

	// 5. Report: agent re-renders the final report via clearance_report
	_, repFinal, err := ClearanceReport(ctx, nil, ClearanceReportArgs{TargetDir: tmpDir})
	if err != nil {
		t.Fatalf("clearance_report error: %v", err)
	}
	if repFinal.Outcome != evidence.OutcomeCleared {
		t.Fatalf("Expected reported outcome Cleared, got %s (reason: %s)", repFinal.Outcome, repFinal.Reason)
	}

	// Assert that the final report shows the finding resolved with its lineage intact
	if len(repFinal.Findings) != 1 {
		t.Fatalf("expected 1 finding in final report, got %d", len(repFinal.Findings))
	}
	f := repFinal.Findings[0]
	if f.ID != findingID {
		t.Fatalf("expected finding ID %s, got %s", findingID, f.ID)
	}
	if f.Fingerprint != fp {
		t.Fatalf("expected fingerprint %s, got %s", fp, f.Fingerprint)
	}
	if f.Disposition != "fixed" {
		t.Fatalf("expected disposition 'fixed', got %s", f.Disposition)
	}
	if f.ChallengeStatus != evidence.ChallengeFixed {
		t.Fatalf("expected challenge status 'fixed', got %s", f.ChallengeStatus)
	}
	if f.FixPatch == nil || f.FixPatch.Diff != patchDiff {
		t.Fatalf("expected fix patch diff linked in finding lineage, got %+v", f.FixPatch)
	}
	if len(f.VerificationRuns) != 1 {
		t.Fatalf("expected 1 verification run in finding lineage, got %d", len(f.VerificationRuns))
	}
	vRun := f.VerificationRuns[0]
	if vRun.Status != evidence.StatusOK || vRun.Outcome != "cleared" {
		t.Fatalf("expected verification run status ok and outcome cleared, got status=%s outcome=%s", vRun.Status, vRun.Outcome)
	}

	// Validate report schema
	repBytes, err := json.Marshal(repFinal)
	if err != nil {
		t.Fatalf("marshal final report: %v", err)
	}
	if err := schema.ValidateReport(repBytes); err != nil {
		t.Fatalf("final report failed schema validation: %v", err)
	}
}
