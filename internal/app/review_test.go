package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/store"
)

func TestConstraint_RationaleAndIdentityAlwaysRecorded(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	err := RecordReview(ctx, RecordReviewArgs{
		TargetDir:        dir,
		Fingerprint:      "fp-123",
		ChallengeStatus:  "rejected",
		Reason:           "false positive",
		ReviewerType:     "agent",
		ReviewerIdentity: "ai-1",
	})
	if err != nil {
		t.Fatalf("RecordReview failed: %v", err)
	}

	st, _ := store.New(filepath.Join(dir, ".clearance"))
	reviews, err := st.GetReviews()
	if err != nil {
		t.Fatalf("GetReviews failed: %v", err)
	}

	rec, ok := reviews["fp-123"]
	if !ok {
		t.Fatalf("Review for fp-123 not found")
	}

	if rec.Reason != "false positive" || rec.ReviewerIdentity != "ai-1" || rec.ReviewerType != evidence.ReviewerAgent {
		t.Fatalf("Identity and rationale not recorded properly: %+v", rec)
	}
}

func TestConstraint_EvidenceStaysVisibleAfterVerdict(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Simulate scan loading
	eng := &Engine{}
	eng.AddAdapter(func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{
			{
				Tool:    "dummy",
				Status:  evidence.StatusOK,
				RawData: []byte("raw output"),
				Findings: []evidence.Finding{
					{
						ID:                 "F1",
						Fingerprint:        "fp-evidence",
						Tool:               "dummy",
						NativeSeverity:     "high",
						NormalizedSeverity: evidence.SeverityHigh,
						Evidence: evidence.FindingEvidence{
							Match: "some bad code",
						},
						RawArtifact: evidence.ArtifactReference{
							URI: "raw.json",
						},
					},
				},
			},
		}
	})

	// Record a review that modifies the state
	_ = RecordReview(ctx, RecordReviewArgs{
		TargetDir:        dir,
		Fingerprint:      "fp-evidence",
		ChallengeStatus:  "rejected",
		Reason:           "not applicable",
		ReviewerType:     "human",
		ReviewerIdentity: "alice",
	})

	report, err := eng.ScanWithOptions(ctx, dir, ScanOptions{Scope: "quick"})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	if f.ChallengeStatus != evidence.ChallengeRejected {
		t.Fatalf("expected rejected, got %v", f.ChallengeStatus)
	}

	// Constraint: Original evidence stays authoritative and visible
	if f.Evidence.Match != "some bad code" {
		t.Fatalf("evidence match lost, got %q", f.Evidence.Match)
	}
	if f.NativeSeverity != "high" {
		t.Fatalf("native severity lost, got %q", f.NativeSeverity)
	}
	if f.RawArtifact.URI == "" {
		t.Fatalf("raw artifact lost, got empty URI")
	}
	if f.ChallengeRationale != "not applicable" {
		t.Fatalf("rationale not applied, got %q", f.ChallengeRationale)
	}
}

func TestConstraint_AgentCannotClearHumanRequiredClass(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	eng := &Engine{}
	eng.AddAdapter(func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{
			{
				Tool:   "dummy",
				Status: evidence.StatusOK,
				Findings: []evidence.Finding{
					{
						ID:                 "F1",
						Fingerprint:        "fp-human-req",
						Tool:               "dummy",
						NormalizedSeverity: evidence.SeverityHigh,
					},
				},
			},
		}
	})

	// Add human required class config
	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"dummy"}
	cfg.Scopes.Quick.AdaptersLegacy = []string{"dummy"}
	cfg.Policy.HumanRequiredClasses = []policy.HumanRequiredClass{
		{Tool: "dummy", Severity: evidence.SeverityHigh},
	}

	// Agent tries to fix it
	_ = RecordReview(ctx, RecordReviewArgs{
		TargetDir:        dir,
		Fingerprint:      "fp-human-req",
		ChallengeStatus:  "fixed",
		Reason:           "I fixed it",
		ReviewerType:     "agent",
		ReviewerIdentity: "ai-1",
	})

	report, err := eng.ScanWithOptions(ctx, dir, ScanOptions{Config: &cfg})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if report.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("expected blocked, got %v", report.Outcome)
	}

	// Human fixes it
	_ = RecordReview(ctx, RecordReviewArgs{
		TargetDir:        dir,
		Fingerprint:      "fp-human-req",
		ChallengeStatus:  "fixed",
		Reason:           "I fixed it for real",
		ReviewerType:     "human",
		ReviewerIdentity: "alice",
	})

	report2, err := eng.ScanWithOptions(ctx, dir, ScanOptions{Config: &cfg})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if report2.Outcome != evidence.OutcomeCleared {
		t.Fatalf("expected cleared, got %v", report2.Outcome)
	}
}
