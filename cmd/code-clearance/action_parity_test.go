package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aniklavida/code-clearance/internal/action"
	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Done when line 1: the CLI and the GitHub Action entry point must return the
// identical policy outcome for the same recorded evidence and configuration.
//
// Both transports are exercised on one fixture checkout. The CLI runs through
// runScan with the injected deterministic engine; the Action runs through
// action.Run with the same engine. The shared core decides the verdict, and the
// test fails if either transport ever diverges from it.
func TestCLIAndAction_ReachIdenticalPolicyOutcomeOnSameRecordedEvidence(t *testing.T) {
	dir := initParityFixture(t)
	rep := loadParityRecordedReport(t)
	engine := parityRecordedEngine(rep)

	// CLI transport: runScan is the exact function `code-clearance scan` calls.
	previous := scanEngine
	scanEngine = engine
	defer func() { scanEngine = previous }()

	var cliOut, cliErr bytes.Buffer
	_ = runScan(context.Background(), []string{"--scope", "full", "--json", dir}, &cliOut, &cliErr)

	var cliReport evidence.Report
	if err := json.Unmarshal(cliOut.Bytes(), &cliReport); err != nil {
		t.Fatalf("CLI did not emit a parseable report: %v\nstdout: %s\nstderr: %s",
			err, cliOut.String(), cliErr.String())
	}

	// Action transport: the exported entry point the composite action invokes.
	diffPath := filepath.Join("..", "..", "testdata", "action", "pr.diff")
	act, err := action.Run(context.Background(), engine, action.Options{
		TargetDir:   dir,
		Scope:       "full",
		DiffPath:    diffPath,
		ChangedOnly: true,
	})
	if err != nil {
		t.Fatalf("action.Run: %v", err)
	}

	// The single claim: they must agree.
	if cliReport.Outcome != act.Report.Outcome {
		t.Fatalf("ACCEPTANCE FAILURE: CLI outcome %q != Action outcome %q",
			cliReport.Outcome, act.Report.Outcome)
	}
	if cliReport.Reason != act.Report.Reason {
		t.Fatalf("ACCEPTANCE FAILURE: CLI reason %q != Action reason %q",
			cliReport.Reason, act.Report.Reason)
	}
	if cliReport.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("fixture expected a blocked outcome, got %q", cliReport.Outcome)
	}

	// Same evidence means the same findings, and the Action must not invent,
	// drop or re-classify one on the way to annotations.
	if got, want := findingIDs(act.Report.Findings), findingIDs(cliReport.Findings); !equalStrings(got, want) {
		t.Fatalf("finding set mismatch: action=%v cli=%v", got, want)
	}

	// The annotations are scoped to the changed line in the simulated PR diff.
	if len(act.Annotations) != 1 {
		t.Fatalf("action annotations = %d, want 1 on the changed line", len(act.Annotations))
	}
	if a := act.Annotations[0]; a.Path != "src/app.go" || a.StartLine != 12 {
		t.Fatalf("annotation location = %s:%d, want src/app.go:12", a.Path, a.StartLine)
	}
}

func findingIDs(findings []evidence.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func loadParityRecordedReport(t *testing.T) evidence.Report {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "action", "recorded-report.json"))
	if err != nil {
		t.Fatalf("read recorded report: %v", err)
	}
	var rep evidence.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal recorded report: %v", err)
	}
	return rep
}

func parityRecordedEngine(rep evidence.Report) *app.Engine {
	engine := app.NewEngine()
	seen := map[string]bool{}
	for _, run := range rep.Runs {
		r := run
		if r.Tool == "" || seen[r.Tool] {
			continue
		}
		seen[r.Tool] = true
		engine.AddNamedAdapter(r.Tool, func(_ context.Context, _ string) []evidence.RunOutcome {
			return []evidence.RunOutcome{r}
		})
	}
	return engine
}

func initParityFixture(t *testing.T) string {
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
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test")
	runGit("config", "user.email", "test@example.com")

	write := func(rel, content string) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitignore", ".clearance/\n")
	write("src/app.go", "package app\n\nfunc main() {\n}\n")
	write("src/legacy.go", "package app\n\nfunc legacy() {\n}\n")

	cfg, err := os.ReadFile(filepath.Join("..", "..", "testdata", "action", "clearance.json"))
	if err != nil {
		t.Fatalf("read clearance fixture: %v", err)
	}
	write("clearance.json", string(cfg))

	runGit("add", ".")
	runGit("commit", "-m", "initial commit")
	return dir
}
