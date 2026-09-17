package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

func initTestGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\noutput: %s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test")
	runGit("config", "user.email", "test@example.com")

	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "file.txt")
	runGit("commit", "-m", "initial commit")

	return dir
}

func TestDetectTarget_NonGitTargetReportedHonestly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "some-file.txt"), []byte("not a git repo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	target := DetectTarget(context.Background(), dir)

	if target.Commit == "" {
		t.Fatal("commit must not be emitted as a blank field for a non-git target")
	}
	if target.Commit != evidence.NotAGitRepository {
		t.Fatalf("target.Commit = %q, want %q", target.Commit, evidence.NotAGitRepository)
	}
	if target.Repository != evidence.NotAGitRepository {
		t.Fatalf("target.Repository = %q, want %q", target.Repository, evidence.NotAGitRepository)
	}
	if target.Fingerprint != evidence.NotAGitRepository {
		t.Fatalf("target.Fingerprint = %q, want %q", target.Fingerprint, evidence.NotAGitRepository)
	}
	if target.Dirty {
		t.Fatal("target.Dirty should be false for a non-git target")
	}
}

func TestDetectTarget_DirtyTreeFingerprintStableAndDistinct(t *testing.T) {
	ctx := context.Background()
	dir := initTestGitRepo(t)

	// Clean tree initially
	clean1 := DetectTarget(ctx, dir)
	if clean1.Dirty {
		t.Fatal("clean tree reported as dirty")
	}
	if clean1.Fingerprint != evidence.CleanTreeFingerprint {
		t.Fatalf("fingerprint = %q, want %q", clean1.Fingerprint, evidence.CleanTreeFingerprint)
	}

	clean2 := DetectTarget(ctx, dir)
	if clean2.Fingerprint != clean1.Fingerprint {
		t.Fatalf("clean fingerprints differ: %q vs %q", clean1.Fingerprint, clean2.Fingerprint)
	}

	// Modify tracked file to make tree dirty
	trackedFile := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(trackedFile, []byte("hello world modified\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dirty1 := DetectTarget(ctx, dir)
	if !dirty1.Dirty {
		t.Fatal("modified tree reported as clean")
	}
	if dirty1.Fingerprint == evidence.CleanTreeFingerprint {
		t.Fatal("dirty tree got clean fingerprint")
	}

	// Stable across two calls on unchanged dirty tree
	dirty2 := DetectTarget(ctx, dir)
	if dirty1.Fingerprint != dirty2.Fingerprint {
		t.Fatalf("dirty tree fingerprint was not stable across calls: %q vs %q", dirty1.Fingerprint, dirty2.Fingerprint)
	}

	// Modifying the tree further changes the fingerprint
	if err := os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("new untracked file\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dirty3 := DetectTarget(ctx, dir)
	if dirty3.Fingerprint == dirty1.Fingerprint {
		t.Fatal("fingerprint did not change after adding untracked file")
	}
}

func TestEngine_TimedOutAdapterProducesUnavailableRatherThanPass(t *testing.T) {
	// Drive the runner with a real command that genuinely outsleeps its bound,
	// verifying that timeout status reaches the evidence model honestly.
	timeoutAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		var cmdName string
		var args []string
		if runtime.GOOS == "windows" {
			cmdName = "powershell"
			args = []string{"-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 10"}
		} else {
			cmdName = "sleep"
			args = []string{"10"}
		}

		res := Run(ctx, Spec{
			Name:    "hung-tool",
			Command: cmdName,
			Args:    args,
			Timeout: 50 * time.Millisecond,
		})

		outcome := evidence.RunOutcome{
			Tool:        "hung-tool",
			ToolVersion: "v1.0.0",
			Command:     cmdName,
			ExitCode:    res.ExitCode,
			Duration:    res.Duration.String(),
		}

		if res.TimedOut {
			outcome.Status = evidence.StatusTimedOut
		} else if res.ExitCode == 0 {
			outcome.Status = evidence.StatusOK
		} else {
			outcome.Status = evidence.StatusCrashed
		}

		return []evidence.RunOutcome{outcome}
	}

	engine := NewEngine(timeoutAdapter)
	dir := t.TempDir()

	report, err := engine.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("engine.Scan failed: %v", err)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Status == evidence.StatusOK {
		t.Fatal("timed out run was recorded as StatusOK (pass)!")
	}
	if run.Status != evidence.StatusTimedOut {
		t.Fatalf("run.Status = %s, want %s", run.Status, evidence.StatusTimedOut)
	}

	// Invariant: Timed out check MUST be recorded under Uncovered.TimedOut
	if len(report.Uncovered.TimedOut) != 1 {
		t.Fatalf("expected 1 uncovered timed-out check, got %d", len(report.Uncovered.TimedOut))
	}
	if report.Uncovered.TimedOut[0].Tool != "hung-tool" {
		t.Fatalf("uncovered timed out tool = %q, want hung-tool", report.Uncovered.TimedOut[0].Tool)
	}

	// Invariant: Verdict must not be a pass
	if report.Outcome == evidence.OutcomeCleared || report.Outcome == evidence.OutcomeClearedWithResidualRisk {
		t.Fatalf("timed out check resulted in passing verdict: %s", report.Outcome)
	}
}

func TestEngine_QuickRunOnDirtyTree_RecordsExactFileSetCommitFingerprint(t *testing.T) {
	ctx := context.Background()
	dir := initTestGitRepo(t)

	// Modify tracked file and add untracked file to make working tree dirty
	trackedFile := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(trackedFile, []byte("tracked dirty content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	untrackedFile := filepath.Join(dir, "dirty-untracked.go")
	if err := os.WriteFile(untrackedFile, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	report, err := engine.Scan(ctx, dir)
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	// 1. Commit recorded
	if report.Target.Commit == "" || report.Target.Commit == evidence.NotAGitRepository {
		t.Fatalf("expected real commit SHA, got %q", report.Target.Commit)
	}

	// 2. Dirty-tree fingerprint recorded
	if !report.Target.Dirty {
		t.Fatal("expected report.Target.Dirty=true")
	}
	if report.Target.Fingerprint == "" || report.Target.Fingerprint == evidence.CleanTreeFingerprint {
		t.Fatalf("expected dirty fingerprint, got %q", report.Target.Fingerprint)
	}

	// 3. Exact file set recorded in coverage
	if report.Coverage.Scope != "quick" {
		t.Fatalf("coverage.scope = %q, want quick", report.Coverage.Scope)
	}
	if len(report.Coverage.FilesChecked) != 2 {
		t.Fatalf("expected 2 files checked in dirty quick run, got %d: %v",
			len(report.Coverage.FilesChecked), report.Coverage.FilesChecked)
	}

	hasTracked := false
	hasUntracked := false
	for _, f := range report.Coverage.FilesChecked {
		if f == "file.txt" {
			hasTracked = true
		}
		if f == "dirty-untracked.go" {
			hasUntracked = true
		}
	}
	if !hasTracked || !hasUntracked {
		t.Fatalf("expected file.txt and dirty-untracked.go, got %v", report.Coverage.FilesChecked)
	}
}

func TestEngine_CancellingRun_StopsChildrenLeavesArtifactStoreConsistent(t *testing.T) {
	cmdName, args := sleepSpec(30)

	slowAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		res := Run(ctx, Spec{
			Name:    "slow-child",
			Command: cmdName,
			Args:    args,
			Dir:     targetDir,
			Timeout: 30 * time.Second,
		})
		return []evidence.RunOutcome{
			{
				Tool:     "slow-child",
				Status:   evidence.StatusUnavailable,
				ExitCode: res.ExitCode,
			},
		}
	}

	engine := NewEngine(slowAdapter)
	dir := initTestGitRepo(t)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		_, err := engine.Scan(ctx, dir)
		errCh <- err
	}()

	// Allow process to start, then cancel
	time.Sleep(100 * time.Millisecond)
	cancel()

	err := <-errCh
	if err == nil {
		t.Fatal("expected cancellation error from engine.Scan, got nil")
	}

	// Check artifact store consistency: no dangling .tmp files in .clearance
	clearanceDir := filepath.Join(dir, ".clearance")
	if _, statErr := os.Stat(clearanceDir); statErr == nil {
		err := filepath.Walk(clearanceDir, func(p string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if strings.HasSuffix(p, ".tmp") {
				t.Fatalf("found leftover temporary file in artifact store after cancellation: %s", p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestEngine_RawOutputRetrievableAfterNormalization(t *testing.T) {
	dir := initTestGitRepo(t)

	rawPayload := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"mock-scanner"}}}]}`)

	mockAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		// Write a raw file to simulate scanner output
		sarifFile := filepath.Join(targetDir, "output.sarif")
		_ = os.WriteFile(sarifFile, rawPayload, 0o644)

		return []evidence.RunOutcome{
			{
				Tool:        "mock-scanner",
				ToolVersion: "v1.0.0",
				Command:     "mock-scanner scan",
				ExitCode:    0,
				Status:      evidence.StatusOK,
				RawArtifact: &evidence.ArtifactReference{
					URI:    sarifFile,
					Format: "sarif",
					Index:  0,
				},
				Findings: []evidence.Finding{
					{
						ID:                 "mock-1",
						Tool:               "mock-scanner",
						RuleID:             "rule-1",
						NativeSeverity:     "HIGH",
						NormalizedSeverity: evidence.SeverityHigh,
					},
				},
			},
		}
	}

	engine := NewEngine(mockAdapter)
	report, err := engine.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.RawArtifact == nil || run.RawArtifact.URI == "" {
		t.Fatal("run.RawArtifact URI must be populated")
	}

	// Retrieve raw output from the artifact store using the persisted reference
	data, err := os.ReadFile(run.RawArtifact.URI)
	if err != nil {
		t.Fatalf("could not retrieve raw artifact from %s: %v", run.RawArtifact.URI, err)
	}

	if string(data) != string(rawPayload) {
		t.Fatalf("retrieved raw output does not match original bytes:\ngot:  %s\nwant: %s",
			string(data), string(rawPayload))
	}

	// Also verify finding has matching RawArtifact reference
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.RawArtifact.URI != run.RawArtifact.URI {
		t.Fatalf("finding RawArtifact URI %q != run RawArtifact URI %q",
			finding.RawArtifact.URI, run.RawArtifact.URI)
	}
}
