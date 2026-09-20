package app

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/schema"
	"github.com/aniklavida/code-clearance/internal/store"
)

// TestVerificationFlow_LinksFindingPatchAndRun verifies Done When #1:
// On a fixture repository, a confirmed finding is patched, the targeted rerun executes,
// and the report links old finding -> patch -> verification run.
func TestVerificationFlow_LinksFindingPatchAndRun(t *testing.T) {
	ctx := context.Background()
	repoDir := t.TempDir()

	// Initialize git repository fixture
	initGitRepo(t, repoDir)

	// Step 1: Create an issue in the fixture repo
	vulnerableFile := filepath.Join(repoDir, "app.go")
	if err := os.WriteFile(vulnerableFile, []byte("package main\n\nconst ApiKey = \"vulnerable-token-12345\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCommitAll(t, repoDir, "Add app with token")

	// Set up engine with mock adapter that detects the token
	eng := &Engine{}
	findingID := "F-KEY-001"
	fingerprint := "fp-token-12345"

	eng.AddNamedAdapter("secrets-scanner", func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		content, err := os.ReadFile(filepath.Join(targetDir, "app.go"))
		if err != nil {
			return []evidence.RunOutcome{{Tool: "secrets-scanner", Status: evidence.StatusCrashed}}
		}
		var findings []evidence.Finding
		if string(content) != "" && string(content) != "package main\n\nconst ApiKey = \"\"\n" {
			findings = append(findings, evidence.Finding{
				ID:                 findingID,
				Fingerprint:        fingerprint,
				Tool:               "secrets-scanner",
				RuleID:             "token-detected",
				Message:            "Token found in code",
				NormalizedSeverity: evidence.SeverityHigh,
				NativeSeverity:     "high",
				Locations:          []evidence.Location{{URI: "app.go"}},
				Evidence:        evidence.FindingEvidence{Match: "vulnerable-token-12345"},
				Confidence:      evidence.Confidence{Level: evidence.ConfidenceHigh, Rationale: "direct pattern match"},
				Timestamps:      evidence.FindingTimestamps{DetectedAt: time.Now().UTC().Format(time.RFC3339)},
				ChallengeStatus: evidence.ChallengeUnreviewed,
			})
			return []evidence.RunOutcome{{
				Tool:     "secrets-scanner",
				Status:   evidence.StatusFindings,
				Findings: findings,
				RawData:  []byte("findings detected"),
			}}
		}
		return []evidence.RunOutcome{{
			Tool:     "secrets-scanner",
			Status:   evidence.StatusOK,
			Findings: []evidence.Finding{},
			RawData:  []byte("clean"),
		}}
	})

	// Initial scan detects the finding
	initialReport, err := eng.ScanWithOptions(ctx, repoDir, ScanOptions{Scope: "quick"})
	if err != nil {
		t.Fatalf("initial scan failed: %v", err)
	}
	if len(initialReport.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(initialReport.Findings))
	}
	if initialReport.Findings[0].ID != findingID {
		t.Fatalf("expected finding ID %s, got %s", findingID, initialReport.Findings[0].ID)
	}

	// Step 2: Confirm the finding
	err = RecordReview(ctx, RecordReviewArgs{
		TargetDir:        repoDir,
		Fingerprint:      fingerprint,
		ChallengeStatus:  string(evidence.ChallengeConfirmed),
		Reason:           "Confirmed hardcoded credential",
		ReviewerType:     string(evidence.ReviewerHuman),
		ReviewerIdentity: "reviewer",
	})
	if err != nil {
		t.Fatalf("RecordReview failed: %v", err)
	}

	// Step 3: Apply the patch to resolve the issue
	patchDiff := `diff --git a/app.go b/app.go
--- a/app.go
+++ b/app.go
@@ -3,1 +3,1 @@
-const ApiKey = "vulnerable-token-12345"
+const ApiKey = ""`
	if err := os.WriteFile(vulnerableFile, []byte("package main\n\nconst ApiKey = \"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCommitAll(t, repoDir, "Remove token")

	patchRef := &evidence.PatchReference{
		Diff:   patchDiff,
		Path:   "app.go",
		Commit: "commit-patch-001",
	}

	// Step 4: Execute targeted verification rerun
	verifyReport, err := eng.Verify(ctx, VerifyArgs{
		TargetDir: repoDir,
		FindingID: findingID,
		Patch:     patchRef,
		Approved:  true,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Step 5: Assert outcome and lineage
	if verifyReport.Outcome != evidence.OutcomeCleared {
		t.Fatalf("expected outcome cleared, got %s (reason: %s)", verifyReport.Outcome, verifyReport.Reason)
	}

	if len(verifyReport.Findings) != 1 {
		t.Fatalf("expected 1 finding in verify report, got %d", len(verifyReport.Findings))
	}

	f := verifyReport.Findings[0]

	// Proves old finding is preserved
	if f.ID != findingID {
		t.Fatalf("expected old finding ID %s, got %s", findingID, f.ID)
	}
	if f.Fingerprint != fingerprint {
		t.Fatalf("expected fingerprint %s, got %s", fingerprint, f.Fingerprint)
	}

	// Proves patch reference is linked
	if f.FixPatch == nil || f.FixPatch.Diff != patchDiff || f.FixPatch.Commit != "commit-patch-001" {
		t.Fatalf("expected patch reference linked to finding, got %+v", f.FixPatch)
	}

	// Proves verification run is linked
	if len(f.VerificationRuns) != 1 {
		t.Fatalf("expected 1 verification run, got %d", len(f.VerificationRuns))
	}
	vRun := f.VerificationRuns[0]
	if vRun.Status != evidence.StatusOK || vRun.Outcome != "cleared" {
		t.Fatalf("expected verification run status ok / cleared, got status=%s outcome=%s", vRun.Status, vRun.Outcome)
	}

	// Proves disposition and challenge status are fixed
	if f.ChallengeStatus != evidence.ChallengeFixed {
		t.Fatalf("expected challenge status fixed, got %s", f.ChallengeStatus)
	}
	if f.Disposition != "fixed" {
		t.Fatalf("expected disposition fixed, got %s", f.Disposition)
	}

	// Step 6: Validate generated report against schema
	st, err := store.New(filepath.Join(repoDir, ".clearance"))
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	latestRep, err := st.GetLatestReport()
	if err != nil {
		t.Fatalf("failed to retrieve latest report: %v", err)
	}
	if latestRep.Outcome != evidence.OutcomeCleared {
		t.Fatalf("stored report outcome mismatch: %s", latestRep.Outcome)
	}

	repBytes, err := json.Marshal(verifyReport)
	if err != nil {
		t.Fatalf("marshal report to json: %v", err)
	}
	if err := schema.ValidateReport(repBytes); err != nil {
		t.Fatalf("report failed schema validation: %v", err)
	}
}

// TestVerificationTimeout_LeavesFindingUnresolvedAndRunIncomplete verifies Done When #3:
// A verification run that times out leaves the finding unresolved and the run Incomplete.
func TestVerificationTimeout_LeavesFindingUnresolvedAndRunIncomplete(t *testing.T) {
	ctx := context.Background()
	repoDir := t.TempDir()

	findingID := "F-TIMEOUT-001"
	fingerprint := "fp-timeout-001"

	eng := &Engine{}
	eng.AddNamedAdapter("slow-scanner", func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		select {
		case <-ctx.Done():
			return []evidence.RunOutcome{
				{
					Tool:       "slow-scanner",
					Status:     evidence.StatusTimedOut,
					StderrTail: "timeout exceeded",
				},
			}
		case <-time.After(2 * time.Second):
			return []evidence.RunOutcome{
				{Tool: "slow-scanner", Status: evidence.StatusOK},
			}
		}
	})

	// Pre-populate finding in store
	st, err := store.New(filepath.Join(repoDir, ".clearance"))
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	initialFinding := evidence.Finding{
		ID:                 findingID,
		Fingerprint:        fingerprint,
		Tool:               "slow-scanner",
		RuleID:             "slow-rule",
		Message:            "Slow finding",
		NormalizedSeverity: evidence.SeverityHigh,
		ChallengeStatus:    evidence.ChallengeConfirmed,
		Locations:          []evidence.Location{{URI: "slow.go"}},
	}
	initialRep := evidence.Report{
		SchemaVersion: "v1",
		Outcome:       evidence.OutcomeBlocked,
		Findings:      []evidence.Finding{initialFinding},
		Runs:          []evidence.RunOutcome{{Tool: "slow-scanner", Status: evidence.StatusFindings}},
	}
	session, _ := st.CreateRun("run-initial")
	_ = st.SaveLatestReport(session, initialRep)

	// Execute verify with a very short timeout (1 millisecond)
	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
	defer cancel()

	verifyReport, err := eng.Verify(timeoutCtx, VerifyArgs{
		TargetDir: repoDir,
		FindingID: findingID,
		Approved:  true,
	})
	if err != nil {
		t.Fatalf("Verify unexpectedly returned error: %v", err)
	}

	// Invariant: Outcome MUST be Incomplete
	if verifyReport.Outcome != evidence.OutcomeIncomplete {
		t.Fatalf("expected OutcomeIncomplete, got %s (reason: %s)", verifyReport.Outcome, verifyReport.Reason)
	}

	if len(verifyReport.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(verifyReport.Findings))
	}

	f := verifyReport.Findings[0]

	// Invariant: Finding MUST be left unresolved
	if f.ChallengeStatus != evidence.ChallengeUnresolved {
		t.Fatalf("expected ChallengeStatus unresolved, got %s", f.ChallengeStatus)
	}
	if f.Disposition != "unresolved" {
		t.Fatalf("expected Disposition unresolved, got %s", f.Disposition)
	}

	// Invariant: Verification run is recorded with StatusTimedOut and incomplete outcome
	if len(f.VerificationRuns) != 1 {
		t.Fatalf("expected 1 verification run, got %d", len(f.VerificationRuns))
	}
	vRun := f.VerificationRuns[0]
	if vRun.Status != evidence.StatusTimedOut {
		t.Fatalf("expected verification run status timed-out, got %s", vRun.Status)
	}
	if vRun.Outcome != "incomplete" {
		t.Fatalf("expected verification run outcome incomplete, got %s", vRun.Outcome)
	}

	// Invariant: Stored review has finding unresolved
	reviews, err := st.GetReviews()
	if err != nil {
		t.Fatalf("GetReviews failed: %v", err)
	}
	rec, ok := reviews[fingerprint]
	if !ok {
		t.Fatalf("review record for %s not found", fingerprint)
	}
	if rec.ChallengeStatus != evidence.ChallengeUnresolved {
		t.Fatalf("expected review challenge status unresolved, got %s", rec.ChallengeStatus)
	}
}

// TestVerification_ToolUnavailable_LeavesFindingUnresolvedAndRunIncomplete tests that
// missing, crashed or unavailable tools return finding to unresolved and run to Incomplete.
func TestVerification_ToolUnavailable_LeavesFindingUnresolvedAndRunIncomplete(t *testing.T) {
	ctx := context.Background()
	repoDir := t.TempDir()

	findingID := "F-UNAVAIL-001"
	fingerprint := "fp-unavail-001"

	eng := &Engine{}
	eng.AddNamedAdapter("missing-scanner", func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{
			{
				Tool:       "missing-scanner",
				Status:     evidence.StatusUnavailable,
				StderrTail: "binary not found",
			},
		}
	})

	st, _ := store.New(filepath.Join(repoDir, ".clearance"))
	initialRep := evidence.Report{
		SchemaVersion: "v1",
		Outcome:       evidence.OutcomeBlocked,
		Findings: []evidence.Finding{
			{
				ID:                 findingID,
				Fingerprint:        fingerprint,
				Tool:               "missing-scanner",
				RuleID:             "unavail-rule",
				NormalizedSeverity: evidence.SeverityHigh,
				ChallengeStatus:    evidence.ChallengeConfirmed,
			},
		},
		Runs: []evidence.RunOutcome{{Tool: "missing-scanner", Status: evidence.StatusFindings}},
	}
	session, _ := st.CreateRun("run-initial")
	_ = st.SaveLatestReport(session, initialRep)

	verifyReport, err := eng.Verify(ctx, VerifyArgs{
		TargetDir: repoDir,
		FindingID: findingID,
		Approved:  true,
	})
	if err != nil {
		t.Fatalf("Verify unexpectedly returned error: %v", err)
	}

	if verifyReport.Outcome != evidence.OutcomeIncomplete {
		t.Fatalf("expected OutcomeIncomplete, got %s", verifyReport.Outcome)
	}

	f := verifyReport.Findings[0]
	if f.ChallengeStatus != evidence.ChallengeUnresolved {
		t.Fatalf("expected ChallengeUnresolved, got %s", f.ChallengeStatus)
	}
	if f.Disposition != "unresolved" {
		t.Fatalf("expected Disposition unresolved, got %s", f.Disposition)
	}
	if len(f.VerificationRuns) != 1 || f.VerificationRuns[0].Status != evidence.StatusUnavailable {
		t.Fatalf("expected verification run status unavailable, got %+v", f.VerificationRuns)
	}
}

// TestEnforceFindingBecomesFixedOnlyThroughVerificationRunEvidence tests that an agent or
// caller asserting it fixed something changes nothing about the finding's state.
func TestEnforceFindingBecomesFixedOnlyThroughVerificationRunEvidence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// 1. Direct RecordReview attempt with fixed status MUST be rejected
	err := RecordReview(ctx, RecordReviewArgs{
		TargetDir:        dir,
		Fingerprint:      "fp-agent-assertion",
		ChallengeStatus:  "fixed",
		Reason:           "I fixed it myself",
		ReviewerType:     "agent",
		ReviewerIdentity: "ai-bot",
	})
	if err == nil {
		t.Fatal("expected RecordReview with status fixed to be rejected with error")
	}

	// 2. If someone manually wrote a review file claiming fixed with NO verification runs:
	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatal(err)
	}
	// Bypass RecordReview and write directly to disk without verification evidence
	_ = st.SaveReview("fp-unverified", store.ReviewRecord{
		ChallengeStatus:  evidence.ChallengeFixed,
		ReviewerType:     evidence.ReviewerAgent,
		ReviewerIdentity: "rogue-agent",
		Reason:           "unverified claim",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		VerificationRuns: []evidence.VerificationRun{}, // No verification runs!
	})

	eng := &Engine{}
	eng.AddAdapter(func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{
			{
				Tool:   "scanner",
				Status: evidence.StatusOK,
				Findings: []evidence.Finding{
					{
						ID:                 "F-unverified",
						Fingerprint:        "fp-unverified",
						Tool:               "scanner",
						NormalizedSeverity: evidence.SeverityHigh,
						ChallengeStatus:    evidence.ChallengeUnreviewed,
					},
				},
			},
		}
	})

	report, err := eng.ScanWithOptions(ctx, dir, ScanOptions{Scope: "quick"})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Invariant: Finding MUST NOT become fixed without verification runs
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].ChallengeStatus == evidence.ChallengeFixed {
		t.Fatalf("SECURITY VIOLATION: finding was marked fixed without recorded verification evidence!")
	}
	if report.Outcome == evidence.OutcomeCleared {
		t.Fatalf("SECURITY VIOLATION: report cleared on unverified fixed finding!")
	}
}

// TestVerification_RerunsMinimumAffectedChecks tests that verification executes
// ONLY the affected check and not unrelated scanners.
func TestVerification_RerunsMinimumAffectedChecks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	gitleaksRan := false
	semgrepRan := false
	trivyRan := false

	eng := &Engine{}
	eng.AddNamedAdapter("gitleaks", func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		gitleaksRan = true
		return []evidence.RunOutcome{{Tool: "gitleaks", Status: evidence.StatusOK}}
	})
	eng.AddNamedAdapter("semgrep", func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		semgrepRan = true
		return []evidence.RunOutcome{{Tool: "semgrep", Status: evidence.StatusOK}}
	})
	eng.AddNamedAdapter("trivy", func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		trivyRan = true
		return []evidence.RunOutcome{{Tool: "trivy", Status: evidence.StatusOK}}
	})

	st, _ := store.New(filepath.Join(dir, ".clearance"))
	initialRep := evidence.Report{
		SchemaVersion: "v1",
		Outcome:       evidence.OutcomeBlocked,
		Findings: []evidence.Finding{
			{
				ID:                 "F-semgrep-01",
				Fingerprint:        "fp-semgrep-01",
				Tool:               "semgrep",
				RuleID:             "rule-sast",
				NormalizedSeverity: evidence.SeverityHigh,
				ChallengeStatus:    evidence.ChallengeConfirmed,
				Locations:          []evidence.Location{{URI: "service.go"}},
			},
		},
		Runs: []evidence.RunOutcome{
			{Tool: "gitleaks", Status: evidence.StatusOK},
			{Tool: "semgrep", Status: evidence.StatusFindings},
			{Tool: "trivy", Status: evidence.StatusOK},
		},
	}
	session, _ := st.CreateRun("run-initial")
	_ = st.SaveLatestReport(session, initialRep)

	// Verify the semgrep finding
	_, err := eng.Verify(ctx, VerifyArgs{
		TargetDir: dir,
		FindingID: "F-semgrep-01",
		Approved:  true,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Assert ONLY semgrep executed in the verification rerun
	if !semgrepRan {
		t.Fatal("expected affected check 'semgrep' to run")
	}
	if gitleaksRan {
		t.Fatal("unaffected check 'gitleaks' ran during verification (expected minimum affected checks)")
	}
	if trivyRan {
		t.Fatal("unaffected check 'trivy' ran during verification (expected minimum affected checks)")
	}
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	runCmd(t, dir, "git", "init")
	runCmd(t, dir, "git", "config", "user.name", "Test User")
	runCmd(t, dir, "git", "config", "user.email", "test@example.com")
}

func gitCommitAll(t *testing.T, dir, msg string) {
	t.Helper()
	runCmd(t, dir, "git", "add", "-A")
	runCmd(t, dir, "git", "commit", "-m", msg)
}

func runCmd(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command %s %v failed: %v\noutput: %s", name, args, err, out)
	}
}
