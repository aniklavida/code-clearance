package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
}
