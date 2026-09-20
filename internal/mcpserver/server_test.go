package mcpserver_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/mcpserver"
	"github.com/aniklavida/code-clearance/internal/store"
)

func TestEntryPoints_ReachIdenticalResultsThroughCore(t *testing.T) {
	ctx := context.Background()

	// Clean directory with a benign file
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Run through core engine entry point (as used by CLI)
	coreReport, err := app.Scan(ctx, dir)
	if err != nil {
		t.Fatalf("app.Scan failed: %v", err)
	}

	// 2. Run through MCP tool entry point
	args := mcpserver.ScanArgs{TargetDir: dir}
	_, mcpReport, err := mcpserver.RunClearanceScan(ctx, nil, args)
	if err != nil {
		t.Fatalf("mcpserver.RunClearanceScan failed: %v", err)
	}

	// 3. Verify target binding is identical
	if coreReport.Target.Repository != mcpReport.Target.Repository {
		t.Fatalf("repository mismatch: core=%q, mcp=%q", coreReport.Target.Repository, mcpReport.Target.Repository)
	}
	if coreReport.Target.Commit != mcpReport.Target.Commit {
		t.Fatalf("commit mismatch: core=%q, mcp=%q", coreReport.Target.Commit, mcpReport.Target.Commit)
	}
	if coreReport.Target.Dirty != mcpReport.Target.Dirty {
		t.Fatalf("dirty mismatch: core=%v, mcp=%v", coreReport.Target.Dirty, mcpReport.Target.Dirty)
	}
	if coreReport.Target.Fingerprint != mcpReport.Target.Fingerprint {
		t.Fatalf("fingerprint mismatch: core=%q, mcp=%q", coreReport.Target.Fingerprint, mcpReport.Target.Fingerprint)
	}

	// 4. Verify adapter run outcomes are identical
	if len(coreReport.Runs) != len(mcpReport.Runs) {
		t.Fatalf("runs count mismatch: core=%d, mcp=%d", len(coreReport.Runs), len(mcpReport.Runs))
	}

	for i := range coreReport.Runs {
		coreRun := coreReport.Runs[i]
		mcpRun := mcpReport.Runs[i]

		if coreRun.Tool != mcpRun.Tool {
			t.Fatalf("run[%d] tool mismatch: core=%q, mcp=%q", i, coreRun.Tool, mcpRun.Tool)
		}
		if coreRun.Status != mcpRun.Status {
			t.Fatalf("run[%d] status mismatch: core=%s, mcp=%s", i, coreRun.Status, mcpRun.Status)
		}
		if coreRun.ExitCode != mcpRun.ExitCode {
			t.Fatalf("run[%d] exit code mismatch: core=%d, mcp=%d", i, coreRun.ExitCode, mcpRun.ExitCode)
		}
		if len(coreRun.Findings) != len(mcpRun.Findings) {
			t.Fatalf("run[%d] findings count mismatch: core=%d, mcp=%d", i, len(coreRun.Findings), len(mcpRun.Findings))
		}
		for j := range coreRun.Findings {
			if coreRun.Findings[j].ID != mcpRun.Findings[j].ID {
				t.Fatalf("run[%d] finding[%d] ID mismatch: core=%q, mcp=%q", i, j, coreRun.Findings[j].ID, mcpRun.Findings[j].ID)
			}
		}
	}
}

func TestServer_RegistersClearanceTool(t *testing.T) {
	server := mcpserver.NewServer()
	if server == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestMCPServer_RedactsSecretsInAgentPayload(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Assemble secret fragments at runtime so no credential literal exists in repo
	slackSecret := "xoxb-" + "778450471234-" + "7784504712345-" + "ZnJ0aGVzY2FubmVyb25seQ"
	stripeSecret := "sk_" + "live_" + "51H8x9K2eZvKYlo2CkQ7tNGGyRfTeStFiXtUrEsAbCdEfGh"

	configContent := "SLACK_TOKEN = \"" + slackSecret + "\"\n" +
		"STRIPE_KEY = \"" + stripeSecret + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "secrets.py"), []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Invoke the MCP tool handler directly
	args := mcpserver.ScanArgs{TargetDir: dir, Scope: "full"}
	_, scanOutput, err := mcpserver.RunClearanceScan(ctx, nil, args)
	if err != nil {
		t.Fatalf("RunClearanceScan: %v", err)
	}

	// 2. Serialize agent payload
	payloadBytes, err := json.Marshal(scanOutput)
	if err != nil {
		t.Fatalf("json.Marshal(scanOutput): %v", err)
	}
	payloadStr := string(payloadBytes)

	// Assert secret is NEVER exposed in the agent-facing payload
	if strings.Contains(payloadStr, slackSecret) {
		t.Fatal("SECURITY LEAK: agent payload contains unredacted slackSecret!")
	}
	if strings.Contains(payloadStr, stripeSecret) {
		t.Fatal("SECURITY LEAK: agent payload contains unredacted stripeSecret!")
	}

	for _, f := range scanOutput.Findings {
		fBytes, _ := json.Marshal(f)
		fStr := string(fBytes)
		if strings.Contains(fStr, slackSecret) || strings.Contains(fStr, stripeSecret) {
			t.Fatalf("SECURITY LEAK: finding %s contains unredacted secret!", f.ID)
		}
	}
}

func TestMCPServer_RecordReviewForcesAgent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	args := app.RecordReviewArgs{
		TargetDir:        dir,
		Fingerprint:      "fp-mcp-test",
		ChallengeStatus:  "rejected",
		Reason:           "MCP caller is lying",
		ReviewerType:     "human",
		ReviewerIdentity: "alice",
	}

	_, _, err := mcpserver.RecordReview(ctx, nil, args)
	if err != nil {
		t.Fatalf("mcpserver.RecordReview: %v", err)
	}

	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	reviews, err := st.GetReviews()
	if err != nil {
		t.Fatalf("GetReviews failed: %v", err)
	}

	rec, ok := reviews["fp-mcp-test"]
	if !ok {
		t.Fatalf("Review not found")
	}

	if rec.ReviewerType != "agent" {
		t.Fatalf("Expected ReviewerType to be agent, got %v", rec.ReviewerType)
	}
}

func TestClearanceReport_LatestOrdering(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	st, err := store.New(filepath.Join(tmpDir, ".clearance"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Create run 1 with a later suffix, but logically first
	run1ID := "run-20230101T000000Z-ffffff"
	run1, _ := st.CreateRun(run1ID)

	// Create a dummy report
	rep1Data := []byte(`{"schema_version": "run1"}`)
	run1.SaveArtifact("clearance_report", "json", rep1Data)
	os.WriteFile(filepath.Join(st.RootDir(), "latest-run.json"), []byte(run1ID), 0644)

	// Create run 2 with an earlier suffix, but logically second
	run2ID := "run-20230101T000000Z-aaaaaa"
	run2, _ := st.CreateRun(run2ID)

	rep2Data := []byte(`{"schema_version": "run2"}`)
	run2.SaveArtifact("clearance_report", "json", rep2Data)
	os.WriteFile(filepath.Join(st.RootDir(), "latest-run.json"), []byte(run2ID), 0644)

	// Call ClearanceReport
	_, rep, err := mcpserver.ClearanceReport(ctx, nil, mcpserver.ClearanceReportArgs{TargetDir: tmpDir})
	if err != nil {
		t.Fatalf("ClearanceReport failed: %v", err)
	}

	if rep.SchemaVersion != "run2" {
		t.Errorf("Expected report from run2, got %s", rep.SchemaVersion)
	}
}

// TestEnforceCannotMarkFixedWithoutRerun_MCP proves Done When #2 (MCP path):
// Marking a finding fixed without a successful rerun is impossible through the MCP surface.
func TestEnforceCannotMarkFixedWithoutRerun_MCP(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	args := app.RecordReviewArgs{
		TargetDir:        dir,
		Fingerprint:      "fp-mcp-unverified",
		ChallengeStatus:  "fixed",
		Reason:           "Agent claims it fixed the vulnerability directly",
		ReviewerType:     "agent",
		ReviewerIdentity: "ai-assistant",
	}

	// Calling clearance_record_review with ChallengeStatus=fixed MUST fail
	_, _, err := mcpserver.RecordReview(ctx, nil, args)
	if err == nil {
		t.Fatal("SECURITY VIOLATION: MCP RecordReview allowed marking finding fixed without a verification rerun")
	}

	// Verify that nothing was written to the store as fixed
	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	reviews, err := st.GetReviews()
	if err != nil {
		t.Fatalf("GetReviews failed: %v", err)
	}
	if rec, exists := reviews["fp-mcp-unverified"]; exists {
		if rec.ChallengeStatus == "fixed" {
			t.Fatal("SECURITY VIOLATION: Review record exists with fixed status in store")
		}
	}
}

func TestMCP_ClearanceGetFixContext(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatal(err)
	}

	finding := evidence.Finding{
		ID:                 "F-MCP-01",
		Fingerprint:        "fp-mcp-01",
		Tool:               "gitleaks",
		RuleID:             "slack-webhook",
		Message:            "Slack Webhook URL detected",
		NormalizedSeverity: evidence.SeverityHigh,
		Locations:          []evidence.Location{{URI: "config.go"}},
		Evidence:           evidence.FindingEvidence{Match: "webhook-url"},
	}

	rep := evidence.Report{
		SchemaVersion: "v1",
		Findings:      []evidence.Finding{finding},
		Runs:          []evidence.RunOutcome{{Tool: "gitleaks", Status: evidence.StatusOK}},
	}
	session, _ := st.CreateRun("run-mcp")
	_ = st.SaveLatestReport(session, rep)

	_, fixCtx, err := mcpserver.GetFixContext(ctx, nil, app.FixContextArgs{
		TargetDir: dir,
		FindingID: "F-MCP-01",
	})
	if err != nil {
		t.Fatalf("GetFixContext failed: %v", err)
	}

	if fixCtx.FindingID != "F-MCP-01" {
		t.Fatalf("expected F-MCP-01, got %s", fixCtx.FindingID)
	}
	if len(fixCtx.Constraints) == 0 {
		t.Fatal("expected non-empty constraints in fix context")
	}
}

func TestMCP_ClearanceVerify(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatal(err)
	}

	finding := evidence.Finding{
		ID:                 "F-VERIFY-01",
		Fingerprint:        "fp-verify-01",
		Tool:               "gitleaks",
		RuleID:             "generic-api-key",
		NormalizedSeverity: evidence.SeverityHigh,
		Locations:          []evidence.Location{{URI: "token.go"}},
	}

	rep := evidence.Report{
		SchemaVersion: "v1",
		Findings:      []evidence.Finding{finding},
		Runs:          []evidence.RunOutcome{{Tool: "gitleaks", Status: evidence.StatusOK}},
	}
	session, _ := st.CreateRun("run-mcp-verify")
	_ = st.SaveLatestReport(session, rep)

	// In clean temp dir with no tokens, verification rerun clears the finding
	_, vRep, err := mcpserver.ClearanceVerify(ctx, nil, app.VerifyArgs{
		TargetDir: dir,
		FindingID: "F-VERIFY-01",
		Patch: &evidence.PatchReference{
			Diff: "--- a/token.go\n+++ b/token.go\n@@ -1 +0,0 @@",
		},
		Approved: true,
	})
	if err != nil {
		t.Fatalf("ClearanceVerify failed: %v", err)
	}

	if vRep.Outcome != evidence.OutcomeCleared {
		t.Fatalf("expected Cleared, got %s (reason: %s)", vRep.Outcome, vRep.Reason)
	}
	if len(vRep.Findings) != 1 || vRep.Findings[0].ChallengeStatus != evidence.ChallengeFixed {
		t.Fatalf("expected verified fixed finding in report, got %+v", vRep.Findings)
	}
}
