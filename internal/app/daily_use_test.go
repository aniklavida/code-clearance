package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aniklavida/code-clearance/internal/baseline"
	"github.com/aniklavida/code-clearance/internal/correlate"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/schema"
)

func TestEngine_BaselineDisclosesSuppressedFinding(t *testing.T) {
	dir := initTestGitRepo(t)
	finding := evidence.Finding{
		ID:                  "F-1",
		Tool:                "fixture",
		ToolVersion:         "1",
		RuleID:              "legacy-rule",
		NativeSeverity:      "HIGH",
		NormalizedSeverity:  evidence.SeverityHigh,
		Locations:           []evidence.Location{{URI: "file.txt"}},
		Scope:               evidence.FindingScope{Commit: "HEAD", Path: "file.txt"},
		Message:             "legacy backlog",
		Evidence:            evidence.FindingEvidence{Details: "fixture evidence"},
		Remediation:         evidence.Remediation{Recommendation: "review the legacy finding"},
		Confidence:          evidence.Confidence{Level: evidence.ConfidenceHigh, Rationale: "fixture"},
		ChallengeStatus:     evidence.ChallengeUnreviewed,
		Reviewer:            evidence.Reviewer{Type: evidence.ReviewerTool, Identity: "fixture"},
		Timestamps:          evidence.FindingTimestamps{DetectedAt: "2026-01-01T00:00:00Z"},
		RawArtifact:         evidence.ArtifactReference{URI: "fixture.sarif", Format: "sarif", Index: 0},
		RelatedFindingIDs:   []string{},
		DuplicateFindingIDs: []string{},
		VerificationRuns:    []evidence.VerificationRun{},
	}
	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"fixture"}
	finding.Fingerprint = correlate.Fingerprint(finding)
	if err := baseline.Save(baseline.DefaultPath(dir), []string{finding.Fingerprint}, time.Now()); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(func(context.Context, string) []evidence.RunOutcome {
		return []evidence.RunOutcome{{Tool: "fixture", Status: evidence.StatusFindings, Findings: []evidence.Finding{finding}}}
	})
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Scope: "quick", Config: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != evidence.OutcomeCleared {
		t.Fatalf("baseline-suppressed finding should not block quick run, got %s", report.Outcome)
	}
	if len(report.Findings) != 1 || !report.Findings[0].SuppressedByBaseline {
		t.Fatalf("suppressed finding was not retained in report: %+v", report.Findings)
	}
	if report.Baseline == nil || !report.Baseline.Active || report.Baseline.SuppressedCount != 1 {
		t.Fatalf("baseline disclosure missing or incorrect: %+v", report.Baseline)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateReport(data); err != nil {
		t.Fatalf("baseline report failed schema validation: %v", err)
	}
}

func TestEngine_ExpiredRiskAcceptanceBlocksNextRun(t *testing.T) {
	dir := initTestGitRepo(t)
	finding := evidence.Finding{
		ID:                 "F-1",
		Fingerprint:        "fp-expiring",
		Tool:               "fixture",
		ToolVersion:        "1",
		RuleID:             "accepted-rule",
		NativeSeverity:     "HIGH",
		NormalizedSeverity: evidence.SeverityHigh,
		Message:            "accepted once",
		Evidence:           evidence.FindingEvidence{Details: "fixture evidence"},
	}
	if err := RecordReview(context.Background(), RecordReviewArgs{
		TargetDir:        dir,
		Fingerprint:      finding.Fingerprint,
		ChallengeStatus:  string(evidence.ChallengeAcceptedRisk),
		Reason:           "temporary exception",
		ReviewerType:     string(evidence.ReviewerHuman),
		ReviewerIdentity: "alice",
		ExpiresAt:        time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"fixture"}
	engine := NewEngine(func(context.Context, string) []evidence.RunOutcome {
		return []evidence.RunOutcome{{Tool: "fixture", Status: evidence.StatusFindings, Findings: []evidence.Finding{finding}}}
	})
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Scope: "quick", Config: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("expired acceptance must block the next run, got %s", report.Outcome)
	}
	if len(report.ResidualRisk) != 0 {
		t.Fatalf("expired acceptance leaked into residual risk: %+v", report.ResidualRisk)
	}
}

func TestEngine_ReleaseIncompleteIsBlocked(t *testing.T) {
	dir := initTestGitRepo(t)
	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"fixture"}
	if err := baseline.Save(baseline.DefaultPath(dir), []string{"legacy-fingerprint"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(unavailableAdapter("fixture"))
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Scope: "release", Config: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("release mode must block incomplete evidence, got %s", report.Outcome)
	}
	if report.Provenance == nil {
		t.Fatal("release report must include provenance checks")
	}
}

func TestEngine_ReleaseProvenanceRejectsDirtyTree(t *testing.T) {
	dir := initTestGitRepo(t)
	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"fixture"}
	if err := os.WriteFile(filepath.Join(dir, "dirty.txt"), []byte("uncommitted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(func(context.Context, string) []evidence.RunOutcome {
		return []evidence.RunOutcome{{Tool: "fixture", Status: evidence.StatusOK}}
	})
	report, err := engine.ScanWithOptions(context.Background(), dir, ScanOptions{Scope: "release", Config: &cfg, TargetFiles: []string{filepath.Join(dir, "file.txt")}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome == evidence.OutcomeCleared {
		t.Fatal("dirty release target must not clear")
	}
}
