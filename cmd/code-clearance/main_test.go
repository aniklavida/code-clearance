package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/store"
)

func TestCLI_ScanJSONOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runScan(context.Background(), []string{"--json", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 on clean target, got %d, stderr: %s", code, stderr.String())
	}

	var report evidence.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v\noutput: %s", err, stdout.String())
	}

	if report.Target.Commit != evidence.NotAGitRepository {
		t.Fatalf("expected non-git target commit, got %q", report.Target.Commit)
	}
}

func TestCLI_ScanHumanOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runScan(context.Background(), []string{dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 on clean target, got %d, stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Repository:") {
		t.Fatalf("expected output to contain 'Repository:', got: %s", out)
	}
	if !strings.Contains(out, "Commit:") {
		t.Fatalf("expected output to contain 'Commit:', got: %s", out)
	}
	if !strings.Contains(out, "Outcome:") {
		t.Fatalf("expected output to contain 'Outcome:', got: %s", out)
	}
}

func TestCLI_Usage(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	if !strings.Contains(buf.String(), "code-clearance <command>") {
		t.Fatalf("unexpected usage output: %s", buf.String())
	}
}

// The two supported install paths produce binaries with different provenance,
// and the version output must not blur them: a release binary carries an
// injected version and is signed; `go install` and local builds are neither.
// Claiming otherwise in a supply-chain tool would be the exact dishonesty the
// product exists to catch.
func TestVersion_UnsignedBuildSaysSo(t *testing.T) {
	var buf bytes.Buffer
	reportVersion(&buf)
	out := buf.String()

	if !strings.Contains(out, "unsigned") {
		t.Fatalf("a build with no injected version must say it is unsigned; got:\n%s", out)
	}
	for _, want := range []string{"code-clearance", "go:", "platform:"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output is missing %q; got:\n%s", want, out)
		}
	}
}

func TestVersion_ReleaseBuildReportsItsVersion(t *testing.T) {
	t.Cleanup(func() { version = "" })
	version = "v1.2.3"

	var buf bytes.Buffer
	reportVersion(&buf)
	out := buf.String()

	if !strings.Contains(out, "v1.2.3") {
		t.Fatalf("an injected version must be reported; got:\n%s", out)
	}
	if strings.Contains(out, "unsigned") {
		t.Fatalf("a release build must not be labelled unsigned; got:\n%s", out)
	}
}

// TestEnforceCannotMarkFixedWithoutRerun_CLI proves Done When #2 (CLI path):
// Marking a finding fixed without a successful rerun is impossible through the CLI.
func TestEnforceCannotMarkFixedWithoutRerun_CLI(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := runRecordReview(ctx, []string{
		"--dir", dir,
		"--fingerprint", "fp-cli-fixed-attempt",
		"--status", "fixed",
		"--reason", "CLI user claims issue is fixed directly",
	}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("SECURITY VIOLATION: CLI record-review exited with 0 when attempting to mark finding fixed")
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "cannot be marked fixed directly") {
		t.Fatalf("expected error message stating finding cannot be marked fixed directly, got:\n%s", errOutput)
	}

	// Verify no fixed record exists on disk
	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	reviews, err := st.GetReviews()
	if err != nil {
		t.Fatalf("GetReviews failed: %v", err)
	}
	if rec, exists := reviews["fp-cli-fixed-attempt"]; exists {
		if rec.ChallengeStatus == "fixed" {
			t.Fatal("SECURITY VIOLATION: Review record exists with fixed status in store")
		}
	}
}

func TestCLI_FixContext(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatal(err)
	}

	finding := evidence.Finding{
		ID:                 "F-CLI-01",
		Fingerprint:        "fp-cli-01",
		Tool:               "gitleaks",
		RuleID:             "token-leak",
		NormalizedSeverity: evidence.SeverityHigh,
		Locations:          []evidence.Location{{URI: "secrets.go"}},
		Evidence:           evidence.FindingEvidence{Match: "secret-token"},
	}
	rep := evidence.Report{
		SchemaVersion: "v1",
		Findings:      []evidence.Finding{finding},
		Runs:          []evidence.RunOutcome{{Tool: "gitleaks", Status: evidence.StatusOK}},
	}
	session, _ := st.CreateRun("run-cli")
	_ = st.SaveLatestReport(session, rep)

	var stdout, stderr bytes.Buffer
	code := runFixContext(ctx, []string{"--json", "--finding-id", "F-CLI-01", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	var fixCtx app.FixContext
	if err := json.Unmarshal(stdout.Bytes(), &fixCtx); err != nil {
		t.Fatalf("unmarshal fix context JSON: %v\noutput: %s", err, stdout.String())
	}
	if fixCtx.FindingID != "F-CLI-01" {
		t.Fatalf("expected F-CLI-01, got %s", fixCtx.FindingID)
	}
}

func TestCLI_Verify(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	st, err := store.New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatal(err)
	}

	finding := evidence.Finding{
		ID:                 "F-CLI-VERIFY-01",
		Fingerprint:        "fp-cli-verify-01",
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
	session, _ := st.CreateRun("run-cli-verify")
	_ = st.SaveLatestReport(session, rep)

	var stdout, stderr bytes.Buffer
	code := runVerify(ctx, []string{"--json", "--finding-id", "F-CLI-VERIFY-01", "--approved", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	var verifyRep evidence.Report
	if err := json.Unmarshal(stdout.Bytes(), &verifyRep); err != nil {
		t.Fatalf("unmarshal report JSON: %v\noutput: %s", err, stdout.String())
	}
	if verifyRep.Outcome != evidence.OutcomeCleared {
		t.Fatalf("expected Cleared outcome, got %s", verifyRep.Outcome)
	}
}
