package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/store"
)

func TestGetFixContext_ReturnsOnlyRequestedFindingEvidenceAndConstraints(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	finding1 := evidence.Finding{
		ID:                 "F-target",
		Fingerprint:        "fp-target",
		Tool:               "gitleaks",
		ToolVersion:        "v8.18.0",
		RuleID:             "generic-api-key",
		Message:            "Generic API Key detected",
		NormalizedSeverity: evidence.SeverityHigh,
		NativeSeverity:     "high",
		Locations: []evidence.Location{
			{URI: "secrets.go"},
		},
		Evidence: evidence.FindingEvidence{
			Match:   "api_key = \"secret\"",
			Details: "Found secret literal in secrets.go",
		},
		Remediation: evidence.Remediation{
			Recommendation: "Move secret to environment variable or secret manager",
		},
		ChallengeStatus: evidence.ChallengeConfirmed,
	}

	finding2 := evidence.Finding{
		ID:                 "F-other",
		Fingerprint:        "fp-other",
		Tool:               "semgrep",
		RuleID:             "sql-injection",
		Message:            "SQL injection vulnerability",
		NormalizedSeverity: evidence.SeverityCritical,
		Locations: []evidence.Location{
			{URI: "db.go"},
		},
	}

	rep := evidence.Report{
		SchemaVersion: "v1",
		Target:        evidence.TargetBinding{Repository: "test/repo"},
		Outcome:       evidence.OutcomeBlocked,
		Runs: []evidence.RunOutcome{
			{Tool: "gitleaks", Status: evidence.StatusOK},
			{Tool: "semgrep", Status: evidence.StatusOK},
		},
		Findings: []evidence.Finding{finding1, finding2},
		Coverage: evidence.CoverageReport{Scope: "quick"},
	}

	session, err := st.CreateRun("run-initial")
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := st.SaveLatestReport(session, rep); err != nil {
		t.Fatalf("save latest report: %v", err)
	}

	// Request fix context for finding 1
	fixCtx, err := GetFixContext(ctx, FixContextArgs{
		TargetDir: dir,
		FindingID: "F-target",
	})
	if err != nil {
		t.Fatalf("GetFixContext failed: %v", err)
	}

	// Verify it returned ONLY the target finding's evidence and constraints
	if fixCtx.FindingID != "F-target" {
		t.Fatalf("expected finding ID F-target, got %s", fixCtx.FindingID)
	}
	if fixCtx.Fingerprint != "fp-target" {
		t.Fatalf("expected fingerprint fp-target, got %s", fixCtx.Fingerprint)
	}
	if fixCtx.Evidence.Match != "api_key = \"secret\"" {
		t.Fatalf("expected evidence match from target finding, got %q", fixCtx.Evidence.Match)
	}
	if fixCtx.Remediation.Recommendation != "Move secret to environment variable or secret manager" {
		t.Fatalf("expected recommendation from target finding, got %q", fixCtx.Remediation.Recommendation)
	}

	// Verify constraints are present
	if len(fixCtx.Constraints) == 0 {
		t.Fatalf("expected non-empty constraints")
	}

	// Verify affected checks contains only gitleaks
	if len(fixCtx.AffectedChecks) != 1 || fixCtx.AffectedChecks[0] != "gitleaks" {
		t.Fatalf("expected affected checks to contain only gitleaks, got %v", fixCtx.AffectedChecks)
	}
}

func TestGetFixContext_HumanRequiredClassIdentified(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfgData := []byte(`{
		"adapters": { "required": [] },
		"policy": {
			"blocking_severities": ["critical", "high"],
			"human_required_classes": [
				{ "tool": "gitleaks", "severity": "critical" }
			]
		}
	}`)
	cfgPath := filepath.Join(dir, "clearance.json")
	if err := os.WriteFile(cfgPath, cfgData, 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	finding := evidence.Finding{
		ID:                 "F-human",
		Fingerprint:        "fp-human",
		Tool:               "gitleaks",
		NormalizedSeverity: evidence.SeverityCritical,
		RuleID:             "root-password",
		Locations:          []evidence.Location{{URI: "config.yaml"}},
	}

	rep := evidence.Report{
		SchemaVersion: "v1",
		Findings:      []evidence.Finding{finding},
		Runs:          []evidence.RunOutcome{{Tool: "gitleaks", Status: evidence.StatusOK}},
	}

	session, _ := st.CreateRun("run-test")
	_ = st.SaveLatestReport(session, rep)

	fixCtx, err := GetFixContext(ctx, FixContextArgs{
		TargetDir: dir,
		FindingID: "F-human",
	})
	if err != nil {
		t.Fatalf("GetFixContext failed: %v", err)
	}

	if !fixCtx.HumanRequired {
		t.Fatalf("expected HumanRequired to be true for human-required finding class")
	}

	foundHumanConstraint := false
	for _, c := range fixCtx.Constraints {
		if c == "Human approval required: finding belongs to a human-required policy class and cannot be cleared by an agent alone." {
			foundHumanConstraint = true
			break
		}
	}
	if !foundHumanConstraint {
		t.Fatalf("expected human approval constraint in fix context constraints, got: %v", fixCtx.Constraints)
	}
}

func TestGetFixContext_NotFound(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	_, err := GetFixContext(ctx, FixContextArgs{
		TargetDir: dir,
		FindingID: "non-existent-finding",
	})
	if err == nil {
		t.Fatal("expected error for non-existent finding, got nil")
	}
	if !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("expected ErrFindingNotFound, got %v", err)
	}
}

func TestEnforceNoDestructiveFixWithoutApproval(t *testing.T) {
	finding := evidence.Finding{
		ID:        "F1",
		Locations: []evidence.Location{{URI: "main.go"}},
	}

	destructivePatch := &evidence.PatchReference{
		Diff: `diff --git a/main.go b/dev/null
deleted file mode 100644
--- a/main.go
+++ /dev/null
@@ -1,5 +0,0 @@
-func main() {}`,
	}

	// Unapproved: MUST fail
	err := ValidatePatchSafety(finding, destructivePatch, false)
	if err == nil {
		t.Fatal("expected destructive fix to be rejected without approval")
	}
	if !errors.Is(err, ErrDestructiveFixForbidden) {
		t.Fatalf("expected ErrDestructiveFixForbidden, got %v", err)
	}

	// Approved: allowed
	err = ValidatePatchSafety(finding, destructivePatch, true)
	if err != nil {
		t.Fatalf("expected approved destructive fix to pass validation, got %v", err)
	}
}

func TestEnforceNoBroadMutationWithoutApproval(t *testing.T) {
	finding := evidence.Finding{
		ID:        "F1",
		Locations: []evidence.Location{{URI: "internal/auth/token.go"}},
	}

	// Patch touches an unrelated file (e.g. database.go, payment.go)
	broadPatch := &evidence.PatchReference{
		Diff: `diff --git a/internal/auth/token.go b/internal/auth/token.go
--- a/internal/auth/token.go
+++ b/internal/auth/token.go
@@ -1,2 +1,2 @@
diff --git a/internal/db/database.go b/internal/db/database.go
--- a/internal/db/database.go
+++ b/internal/db/database.go
@@ -1,2 +1,2 @@`,
	}

	// Unapproved: MUST fail
	err := ValidatePatchSafety(finding, broadPatch, false)
	if err == nil {
		t.Fatal("expected broad mutation to be rejected without approval")
	}
	if !errors.Is(err, ErrBroadMutationForbidden) {
		t.Fatalf("expected ErrBroadMutationForbidden, got %v", err)
	}

	// Approved: allowed
	err = ValidatePatchSafety(finding, broadPatch, true)
	if err != nil {
		t.Fatalf("expected approved broad mutation to pass validation, got %v", err)
	}
}

func TestEnforceNoAutomaticMutationWithoutApproval(t *testing.T) {
	// Unapproved: MUST fail
	err := EnforceNoAutomaticMutationWithoutApproval(false)
	if err == nil {
		t.Fatal("expected automatic mutation without approval to be forbidden")
	}
	if !errors.Is(err, ErrAutomaticMutationForbidden) {
		t.Fatalf("expected ErrAutomaticMutationForbidden, got %v", err)
	}

	// Approved: allowed
	err = EnforceNoAutomaticMutationWithoutApproval(true)
	if err != nil {
		t.Fatalf("expected approved mutation to pass, got %v", err)
	}
}
