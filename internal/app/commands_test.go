package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/policy"
)

func TestCommands_UntrustedInput_HostileValuesRejectedOrInert(t *testing.T) {
	repoDir := t.TempDir()

	// 1. Hostile: Leading '-' that could be read as a flag
	t.Run("leading-hyphen-rejected", func(t *testing.T) {
		_, _, err := ParseCommand("-flag-as-command", repoDir)
		if err == nil {
			t.Fatal("expected error for command starting with '-', got nil")
		}
		if !strings.Contains(err.Error(), "cannot start with '-'") {
			t.Fatalf("unexpected error message: %v", err)
		}

		_, _, err2 := ParseCommand("--all-options", repoDir)
		if err2 == nil {
			t.Fatal("expected error for command starting with '--', got nil")
		}
	})

	// 2. Hostile: Newline injection
	t.Run("newline-injection-rejected", func(t *testing.T) {
		_, _, err := ParseCommand("echo safe\nrm -rf /", repoDir)
		if err == nil {
			t.Fatal("expected error for command with newline injection, got nil")
		}
		if !strings.Contains(err.Error(), "newline injection") {
			t.Fatalf("unexpected error message: %v", err)
		}

		_, _, errCRLF := ParseCommand("echo safe\r\nrm -rf /", repoDir)
		if errCRLF == nil {
			t.Fatal("expected error for command with CRLF newline injection, got nil")
		}
	})

	// 3. Hostile: Path traversing out of repository
	t.Run("path-traversal-out-of-repo-rejected", func(t *testing.T) {
		_, _, err := ParseCommand("../outside-binary", repoDir)
		if err == nil {
			t.Fatal("expected error for command path traversing outside repo, got nil")
		}
		if !strings.Contains(err.Error(), "traverses outside repository") {
			t.Fatalf("unexpected error message: %v", err)
		}

		_, _, errNested := ParseCommand("sub/../../outside-binary", repoDir)
		if errNested == nil {
			t.Fatal("expected error for nested path traversal escaping repo, got nil")
		}
	})

	// 4. Hostile: Arbitrary shell execution wrappers (no sh -c)
	t.Run("shell-wrapper-rejected", func(t *testing.T) {
		_, _, err := ParseCommand("sh -c 'rm -rf /'", repoDir)
		if err == nil {
			t.Fatal("expected error for 'sh -c', got nil")
		}
		if !strings.Contains(err.Error(), "arbitrary shell execution forbidden") {
			t.Fatalf("unexpected error message: %v", err)
		}

		_, _, errBash := ParseCommand("bash -c 'whoami'", repoDir)
		if errBash == nil {
			t.Fatal("expected error for 'bash -c', got nil")
		}
	})

	// 5. Hostile: Direct metacharacters in executable name
	t.Run("metacharacter-command-rejected", func(t *testing.T) {
		_, _, err := ParseCommand("; rm -rf /", repoDir)
		if err == nil {
			t.Fatal("expected error for ';' command name, got nil")
		}

		_, _, errPipe := ParseCommand("| cat", repoDir)
		if errPipe == nil {
			t.Fatal("expected error for '|' command name, got nil")
		}
	})
}

func TestCommands_Execution_MetacharactersPassThroughAsInertArgv(t *testing.T) {
	if _, err := exec.LookPath("echo"); err != nil {
		t.Skip("echo executable missing on PATH")
	}

	repoDir := t.TempDir()
	canaryPath := filepath.Join(repoDir, "canary.txt")
	if err := os.WriteFile(canaryPath, []byte("intact\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	canaryCreatedPath := filepath.Join(repoDir, "canary-created.txt")

	ctx := context.Background()

	// 1. Hostile '; rm ...': must NOT execute rm; canary must remain intact
	t.Run("semicolon-injection-is-inert-argument", func(t *testing.T) {
		rule := policy.CommandRule{
			Name: "test-semicolon",
			Run:  "echo '; rm " + canaryPath + "'",
		}

		outcome, stdout, err := RunRepositoryCommand(ctx, rule, repoDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if outcome.Status != "ok" {
			t.Fatalf("outcome status = %s, want ok", outcome.Status)
		}

		// Canary file must still exist (rm was never executed)
		if _, err := os.Stat(canaryPath); os.IsNotExist(err) {
			t.Fatal("SECURITY VIOLATION: canary file was deleted! Shell injection executed rm!")
		}

		// Stdout must contain literal string
		if !strings.Contains(string(stdout), "; rm") {
			t.Fatalf("expected stdout to contain '; rm', got: %s", string(stdout))
		}
	})

	// 2. Hostile '$(...)': command substitution must NOT execute; canary must NOT be created
	t.Run("command-substitution-is-inert-argument", func(t *testing.T) {
		rule := policy.CommandRule{
			Name: "test-subshell",
			Run:  "echo \"$(touch " + canaryCreatedPath + ")\"",
		}

		outcome, stdout, err := RunRepositoryCommand(ctx, rule, repoDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if outcome.Status != "ok" {
			t.Fatalf("outcome status = %s, want ok", outcome.Status)
		}

		// Canary file must NOT be created (touch was never executed)
		if _, err := os.Stat(canaryCreatedPath); !os.IsNotExist(err) {
			t.Fatal("SECURITY VIOLATION: canary file was created! $(...) was evaluated!")
		}

		// Output contains literal $(touch ...)
		if !strings.Contains(string(stdout), "$(touch") {
			t.Fatalf("expected stdout to contain literal '$(touch', got: %s", string(stdout))
		}
	})

	// 3. Hostile backticks '`...`': backticks must NOT execute
	t.Run("backticks-are-inert-argument", func(t *testing.T) {
		rule := policy.CommandRule{
			Name: "test-backticks",
			Run:  "echo `touch " + canaryCreatedPath + "`",
		}

		outcome, stdout, err := RunRepositoryCommand(ctx, rule, repoDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if outcome.Status != "ok" {
			t.Fatalf("outcome status = %s, want ok", outcome.Status)
		}

		if _, err := os.Stat(canaryCreatedPath); !os.IsNotExist(err) {
			t.Fatal("SECURITY VIOLATION: canary file was created! Backticks were evaluated!")
		}

		if !strings.Contains(string(stdout), "touch") {
			t.Fatalf("expected stdout to contain literal 'touch', got: %s", string(stdout))
		}
	})
}
