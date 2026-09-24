package action

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
	"github.com/aniklavida/code-clearance/internal/policy"
)

func testdataPath(rel string) string {
	return filepath.Join("..", "..", "testdata", "action", rel)
}

func loadRecordedReport(t *testing.T) evidence.Report {
	t.Helper()
	data, err := os.ReadFile(testdataPath("recorded-report.json"))
	if err != nil {
		t.Fatalf("read recorded report: %v", err)
	}
	var rep evidence.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal recorded report: %v", err)
	}
	return rep
}

func loadPRDiff(t *testing.T) *Diff {
	t.Helper()
	data, err := os.ReadFile(testdataPath("pr.diff"))
	if err != nil {
		t.Fatalf("read PR diff fixture: %v", err)
	}
	return ParseUnifiedDiff(data)
}

// initFixture builds a clean git checkout containing src/app.go, src/legacy.go
// and the shared clearance.json, mirroring the shape of a real PR checkout.
func initFixture(t *testing.T) string {
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

	cfg, err := os.ReadFile(testdataPath("clearance.json"))
	if err != nil {
		t.Fatalf("read clearance fixture: %v", err)
	}
	write("clearance.json", string(cfg))

	runGit("add", ".")
	runGit("commit", "-m", "initial commit")
	return dir
}

// recordedEngine replays a recorded report's runs as fixed adapters, so the
// same recorded evidence can flow through the CLI and the Action paths.
func recordedEngine(rep evidence.Report) *app.Engine {
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

// Done when line 2: annotation output names scope, tools and versions, coverage
// and residual risk for changed lines, demonstrated against a PR diff fixture.
func TestAction_AnnotationsScopedToChangedLines_UsingPRDiffFixture(t *testing.T) {
	rep := loadRecordedReport(t)
	rep.ResidualRisk = []evidence.ResidualRiskItem{{
		FindingID: "F-ACCEPTED",
		RuleID:    "known-limitation",
		Severity:  evidence.SeverityMedium,
		Reason:    "documented limitation pending refactor",
		ExpiresAt: "2030-01-01T00:00:00Z",
	}}
	diff := loadPRDiff(t)

	if got := diff.ChangedFiles(); len(got) != 1 || got[0] != "src/app.go" {
		t.Fatalf("diff fixture changed files = %v, want [src/app.go]", got)
	}
	if !diff.IsChangedLine("src/app.go", 12) {
		t.Fatal("diff fixture must mark src/app.go:12 as changed")
	}
	if diff.IsChangedLine("src/legacy.go", 3) {
		t.Fatal("diff fixture must not mark src/legacy.go:3 as changed")
	}

	annotations, skipped := BuildAnnotations(rep, diff, true)
	if skipped != 1 {
		t.Fatalf("annotations skipped = %d, want 1 (the unchanged src/legacy.go finding)", skipped)
	}
	if len(annotations) != 1 {
		t.Fatalf("annotations = %d, want 1 scoped to the changed line", len(annotations))
	}
	a := annotations[0]
	if a.Path != "src/app.go" || a.StartLine != 12 {
		t.Fatalf("annotation location = %s:%d, want src/app.go:12", a.Path, a.StartLine)
	}
	if a.Level != "error" {
		t.Fatalf("annotation level = %q, want error for a high finding", a.Level)
	}
	cmd := a.GitHubCommand()
	if !strings.HasPrefix(cmd, "::error file=src/app.go,line=12") {
		t.Fatalf("annotation workflow command malformed: %s", cmd)
	}
	if !strings.Contains(cmd, "recorded-scanner") {
		t.Fatalf("annotation must name the tool that found it: %s", cmd)
	}

	summary := BuildSummary(rep, diff, "file:pr.diff", annotations, skipped, true)
	for _, want := range []string{
		"full",                  // scope
		"recorded-scanner",      // tool
		"v1.2.3",                // tool version
		"Adapters ran",          // coverage
		"residual risk",         // residual risk
		"src/app.go:12",         // changed line location
		"1 finding(s) outside",  // honest about scope
		"documented limitation", // residual risk detail
	} {
		if !strings.Contains(strings.ToLower(summary), strings.ToLower(want)) {
			t.Fatalf("summary is missing %q:\n%s", want, summary)
		}
	}
}

// Done when line 3: simulating an unavailable required scanner (the same
// technique internal/app and internal/policy tests use) must make the Action
// entry point report Incomplete, never a pass. This reuses the existing
// constraint in internal/policy rather than adding a second version of it.
func TestAction_UnavailableRequiredScannerProducesIncompleteNotPass(t *testing.T) {
	dir := initFixture(t)

	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"required-scanner"}

	engine := app.NewEngine()
	engine.AddNamedAdapter("required-scanner", func(_ context.Context, _ string) []evidence.RunOutcome {
		return []evidence.RunOutcome{{
			Tool:        "required-scanner",
			ToolVersion: "unknown",
			Command:     "required-scanner",
			Status:      evidence.StatusNotInstalled,
		}}
	})

	result, err := Run(context.Background(), engine, Options{
		TargetDir:   dir,
		Scope:       "full",
		Config:      &cfg,
		ChangedOnly: false,
	})
	if err != nil {
		t.Fatalf("action.Run: %v", err)
	}

	if result.Report.Outcome != evidence.OutcomeIncomplete {
		t.Fatalf("an unavailable required scanner must produce %q, got %q",
			evidence.OutcomeIncomplete, result.Report.Outcome)
	}
	if result.Report.Outcome == evidence.OutcomeCleared || result.Report.Outcome == evidence.OutcomeClearedWithResidualRisk {
		t.Fatalf("VIOLATION: unavailable required scanner produced a passing outcome %q", result.Report.Outcome)
	}
	if !strings.Contains(result.Report.Reason, "required-scanner") {
		t.Fatalf("reason %q must name the unavailable required scanner", result.Report.Reason)
	}
	if !strings.Contains(result.Summary, "required-scanner") {
		t.Fatalf("summary must name the unavailable required scanner; got:\n%s", result.Summary)
	}
}

// SARIF-compatible output: this tool's own findings exported as valid SARIF for
// consumers that expect it, checked structurally against the 2.1.0 required
// fields (no SARIF JSON Schema is vendored in this repository).
func TestAction_SARIFExportIsStructurallyValid(t *testing.T) {
	rep := loadRecordedReport(t)

	log, err := normalize.Export(rep)
	if err != nil {
		t.Fatalf("normalize.Export: %v", err)
	}
	data, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("exported SARIF failed structural validation: %v", err)
	}

	// A malformed document must be rejected, so the check has teeth.
	bad := []byte(`{"version":"2.0.0","runs":[]}`)
	if err := ValidateSARIF(bad); err == nil {
		t.Fatal("ValidateSARIF accepted a document with the wrong version and no runs")
	}
}

// The Action entry point must open no network connection: it reads only the
// checkout it is handed and never uploads source. This mirrors the honeypot
// guard in internal/app/network_test.go.
func TestAction_RunOpensNoNetworkConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	honeypot := ln.Addr().String()
	var attempts int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&attempts, 1)
			_ = conn.Close()
		}
	}()

	proxyURL := "http://" + honeypot
	t.Setenv("HTTP_PROXY", proxyURL)
	t.Setenv("HTTPS_PROXY", proxyURL)
	t.Setenv("ALL_PROXY", proxyURL)
	t.Setenv("http_proxy", proxyURL)
	t.Setenv("https_proxy", proxyURL)

	origTransport := http.DefaultTransport
	var httpAttempts int32
	http.DefaultTransport = roundTripCounter{attempts: &httpAttempts}
	defer func() { http.DefaultTransport = origTransport }()

	dir := initFixture(t)
	engine := app.NewEngine()
	engine.AddNamedAdapter("recorded-scanner", func(_ context.Context, _ string) []evidence.RunOutcome {
		return []evidence.RunOutcome{{
			Tool:        "recorded-scanner",
			ToolVersion: "v1.2.3",
			Command:     "recorded-scanner",
			Status:      evidence.StatusOK,
		}}
	})

	if _, err := Run(context.Background(), engine, Options{
		TargetDir:   dir,
		Scope:       "full",
		ChangedOnly: false,
	}); err != nil {
		t.Fatalf("action.Run: %v", err)
	}

	if n := atomic.LoadInt32(&attempts); n > 0 {
		t.Fatalf("SECURITY VIOLATION: action opened %d network connection(s)", n)
	}
	if n := atomic.LoadInt32(&httpAttempts); n > 0 {
		t.Fatalf("SECURITY VIOLATION: action made %d outbound HTTP request(s)", n)
	}
}

type roundTripCounter struct {
	attempts *int32
}

func (r roundTripCounter) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(r.attempts, 1)
	return nil, net.UnknownNetworkError("network blocked by action security guard")
}
