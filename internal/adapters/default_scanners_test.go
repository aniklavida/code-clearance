package adapters

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
)

// Two of the four default scanners used to return nil when their binary was
// absent, so a missing tool produced no outcome and vanished from the report.
// It was not recorded as passed — the schema forbids that — but it was not
// recorded at all, which is worse, because the policy layer turns an
// unavailable required adapter into Incomplete and had nothing to turn.
//
// This exercises the real production wiring rather than a stand-in adapter.
// The earlier version of this test used a custom adapter and therefore never
// reached DefaultScanners at all: reverting the fix left it passing.
func TestDefaultScanners_EveryScannerReportsEvenWhenItsBinaryIsAbsent(t *testing.T) {
	// A PATH containing nothing makes every scanner unavailable regardless of
	// what happens to be installed, so this test behaves identically on a bare
	// laptop and a fully provisioned runner. Without that, coverage is
	// inverted: the better-equipped the machine, the less this proves.
	empty := t.TempDir()
	t.Setenv("PATH", empty)

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "package-lock.json"), []byte(`{"name":"x","lockfileVersion":3}`), 0o644); err != nil {
		t.Fatal(err)
	}

	scanners := DefaultScanners()
	if len(scanners) == 0 {
		t.Fatal("no default scanners registered")
	}

	var outcomes []evidence.RunOutcome
	for _, s := range scanners {
		outcomes = append(outcomes, s(context.Background(), target)...)
	}

	if len(outcomes) != len(scanners) {
		t.Fatalf("every scanner must report its own absence: %d scanners produced %d outcomes", len(scanners), len(outcomes))
	}

	for _, o := range outcomes {
		if o.Tool == "" {
			t.Error("an outcome names no tool; absence must say which tool is absent")
		}
		if o.Status == evidence.StatusOK {
			t.Errorf("%s reported StatusOK with no binary on PATH", o.Tool)
		}
	}
}

// The exit-code switch has four branches and only two were reached by any
// test. A crashed adapter and an adapter whose process failed to start could
// both be mapped to StatusOK with the whole suite staying green, while the
// pull request's own criteria table said the crashed case was covered.
func TestFinishFromSarifFile_CrashAndExecFailureAreNeverPasses(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-report.sarif")

	cases := []struct {
		name string
		res  appResult
		want evidence.RunStatus
	}{
		{"process failed to start", appResult{Err: errors.New("exec: not found"), ExitCode: -1}, evidence.StatusNotInstalled},
		{"unexpected exit code", appResult{ExitCode: 127}, evidence.StatusCrashed},
		{"timed out", appResult{TimedOut: true, ExitCode: -1}, evidence.StatusTimedOut},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := finishFromSarifFile("fixture-tool", "v1", missing, toRunResult(c.res), normalize.GitleaksSeverity, map[int]bool{0: true, 1: true})
			if out.Status == evidence.StatusOK {
				t.Fatalf("%s reported StatusOK; no failure mode may be a pass", c.name)
			}
			if out.Status != c.want {
				t.Errorf("want %q, got %q", c.want, out.Status)
			}
		})
	}
}

// A recorded command that is not the command that ran is evidence which
// misdescribes itself. Gitleaks built its argv separately from its declared
// command and recorded the declared one, which omitted --report-path.
func TestGitleaks_RecordedCommandIsTheCommandThatRan(t *testing.T) {
	requireTool(t, "gitleaks")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := NewGitleaksAdapter().Run(context.Background(), dir)

	// The report path is generated per run, so its presence in the recorded
	// command is what proves the record describes the real invocation rather
	// than the declaration.
	if !strings.Contains(out.Command, "--report-path") {
		t.Fatalf("recorded command omits an argument that was passed: %q", out.Command)
	}
	if strings.Contains(out.Command, "sh -c") {
		t.Fatalf("recorded command went through a shell: %q", out.Command)
	}
}

type appResult struct {
	Err      error
	ExitCode int
	TimedOut bool
}

func toRunResult(r appResult) app.Result {
	return app.Result{Err: r.Err, ExitCode: r.ExitCode, TimedOut: r.TimedOut}
}

// Three adapters carry their own copy of the exit-code switch rather than
// going through finishFromSarifFile, and nothing reached those copies. Breaking
// only those three — leaving the shared helper intact — left the whole suite
// green while a scanner that failed to start reported success.
//
// This drives each adapter's real Run with no binary on PATH, which is the
// exec-failure path, and asserts on the outcome each one actually produces.
func TestEveryAdapter_ExecFailureIsNeverAPass(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("PATH", empty)

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "package-lock.json"), []byte(`{"name":"x","lockfileVersion":3}`), 0o644); err != nil {
		t.Fatal(err)
	}

	adapters := map[string]func(context.Context, string) evidence.RunOutcome{
		"gitleaks":    NewGitleaksAdapter().Run,
		"osv-scanner": func(ctx context.Context, d string) evidence.RunOutcome { return NewOSVScannerAdapter().Run(ctx, d) },
		"semgrep":     NewSemgrepAdapter().Run,
		"trivy":       NewTrivyAdapter().Run,
	}

	for name, run := range adapters {
		t.Run(name, func(t *testing.T) {
			out := run(context.Background(), target)
			if out.Status == evidence.StatusOK {
				t.Fatalf("%s reported StatusOK with no binary on PATH", name)
			}
			if out.Tool == "" {
				t.Errorf("%s produced an outcome naming no tool", name)
			}
		})
	}
}
