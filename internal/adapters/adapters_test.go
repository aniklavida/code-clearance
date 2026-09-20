package adapters

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
)

// requireTool skips when a scanner this project drives as a separate process
// is not installed. The skip names the binary, so a skipped run reads as "the
// tool is missing here" rather than quietly looking like a pass.
func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not installed; this test drives the real binary", name)
	}
}

func fixtureDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/adapters -> <repo root>/testdata/fixture-repo
	return filepath.Join(wd, "..", "..", "testdata", "fixture-repo")
}

// secretFixtureDir copies the committed fixture into a temporary directory and
// adds the one file that cannot live in the repository: a source file carrying
// two credential-shaped strings for the secret scanner to find.
//
// They are fabricated, but they are shaped like the real thing, which is the
// entire point — and it is also why they are assembled here from fragments
// rather than committed. A file of realistic-looking credentials in a public
// repository is blocked by push protection, flagged by every scanner that ever
// reads it, and a poor advertisement for a project whose subject is finding
// exactly this. The fixture is built, used and discarded within the test.
func secretFixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	src := fixtureDir(t)
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// TEMP: deliberately broken for a clean CI red/green verification drill
	// (card Code Clearance · 20, second pass, run against the fully-fixed
	// branch). Reverted immediately after CI is confirmed red.
	slack := strings.Join([]string{"NOT-A-SLACK-TOKEN", "778450471234", "7784504712345", "ZnJ0aGVzY2FubmVyb25seQ"}, "-")
	stripe := "not_a_stripe_key_51H8x9K2eZvKYlo2CkQ7tNGGyRfTeStFiXtUrEsAbCdEfGh"

	content := "# Built by the test, never committed: two credential-shaped strings\n" +
		"# assembled from fragments so no literal exists in the repository.\n" +
		"SLACK_BOT_TOKEN = \"" + slack + "\"\n" +
		"STRIPE_LIVE_KEY = \"" + stripe + "\"\n"

	if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGitleaks_RealProcess_FindsFixtureSecrets(t *testing.T) {
	requireTool(t, "gitleaks")
	dir := secretFixtureDir(t)
	outcome := Gitleaks(context.Background(), dir)

	if outcome.Status != evidence.StatusFindings {
		t.Fatalf("status = %s, want ok-findings (stderr: %s)", outcome.Status, outcome.StderrTail)
	}
	if len(outcome.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(outcome.Findings))
	}
	t.Logf("gitleaks real run: exit=%d duration=%s findings=%d", outcome.ExitCode, outcome.Duration, len(outcome.Findings))
}

func TestOSVScanner_RealProcess_FindsVulnerableLockfile(t *testing.T) {
	requireTool(t, "osv-scanner")
	dir := fixtureDir(t)
	lockfile := filepath.Join(dir, "package-lock.json")
	outcome := OSVScanner(context.Background(), lockfile)

	if outcome.Status != evidence.StatusFindings {
		t.Fatalf("status = %s, want ok-findings (stderr: %s)", outcome.Status, outcome.StderrTail)
	}
	if len(outcome.Findings) == 0 {
		t.Fatal("expected at least one normalized vulnerability finding for lodash@4.17.15")
	}
	t.Logf("osv-scanner real run: exit=%d duration=%s findings=%d", outcome.ExitCode, outcome.Duration, len(outcome.Findings))
}

func TestGitleaks_RealProcess_CleanDirectoryReportsOK(t *testing.T) {
	requireTool(t, "gitleaks")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing sensitive here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outcome := Gitleaks(context.Background(), dir)
	if outcome.Status != evidence.StatusOK {
		t.Fatalf("status = %s, want ok (stderr: %s)", outcome.Status, outcome.StderrTail)
	}
	if len(outcome.Findings) != 0 {
		t.Fatalf("got %d findings in a clean directory, want 0", len(outcome.Findings))
	}
}

func TestOSVScanner_RealProcess_HungProcessKilledByTimeout(t *testing.T) {
	requireTool(t, "osv-scanner")
	// Prove the same timeout/kill guarantee validated in the runner unit
	// tests also holds when wired to a real external scanner binary, not
	// just a synthetic `sleep`. A 1-nanosecond timeout guarantees the
	// context deadline is already exceeded before osv-scanner can exit,
	// regardless of machine speed.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	dir := fixtureDir(t)
	lockfile := filepath.Join(dir, "package-lock.json")

	start := time.Now()
	outcome := OSVScanner(ctx, lockfile)
	elapsed := time.Since(start)

	if outcome.Status != evidence.StatusTimedOut {
		t.Fatalf("status = %s, want timed-out", outcome.Status)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("real-tool kill took %v", elapsed)
	}
	t.Logf("osv-scanner killed after %v under a 1ns timeout", elapsed)
}

// The headline safety constraint is that a killed or timed-out adapter
// surfaces as unavailable evidence, never as a pass. The engine-level test for
// this builds its own status mapping inside the test body, so it proves the
// runner detects a timeout but never exercises the mapping in this package —
// the code that actually decides whether a dead check reports as OK.
//
// This drives the real adapter, with a real process, killed by a real deadline.
func TestGitleaks_TimedOutRunIsNeverReportedAsAPass(t *testing.T) {
	requireTool(t, "gitleaks")

	// A deadline short enough that the process cannot finish, applied to the
	// real adapter rather than to a stand-in.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	outcome := Gitleaks(ctx, secretFixtureDir(t))

	if outcome.Status == evidence.StatusOK {
		t.Fatal("a killed gitleaks run reported as a pass — a check that never completed must never read as clean")
	}
	if outcome.Status != evidence.StatusTimedOut {
		t.Fatalf("status = %s, want %s", outcome.Status, evidence.StatusTimedOut)
	}
	if len(outcome.Findings) != 0 {
		t.Fatalf("a killed run reported %d findings; it produced no evidence at all", len(outcome.Findings))
	}
}

func TestAdapter_MalformedFileProducesNamedErrorAndUnavailableCheck(t *testing.T) {
	tempDir := t.TempDir()
	badSarifPath := filepath.Join(tempDir, "corrupted.sarif")
	if err := os.WriteFile(badSarifPath, []byte(`{"version": "2.1.0", truncated...`), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeRes := app.Result{
		ExitCode: 0,
		Duration: time.Millisecond * 10,
	}

	outcome := finishFromSarifFile("gitleaks", "v8.30.1", badSarifPath, fakeRes, normalize.GitleaksSeverity, map[int]bool{0: true})

	// Must NOT be StatusOK (which would be an empty pass!)
	if outcome.Status == evidence.StatusOK {
		t.Fatal("malformed file produced StatusOK — a corrupted output must never be treated as an empty pass!")
	}
	// Must be StatusUnavailable
	if outcome.Status != evidence.StatusUnavailable {
		t.Fatalf("outcome.Status = %s, want %s", outcome.Status, evidence.StatusUnavailable)
	}
	// StderrTail must contain a named error mentioning sarif/parse
	if !strings.Contains(outcome.StderrTail, "sarif") && !strings.Contains(outcome.StderrTail, "parse") {
		t.Fatalf("outcome.StderrTail %q does not describe the parse failure", outcome.StderrTail)
	}
	if len(outcome.Findings) != 0 {
		t.Fatalf("malformed file produced %d findings, expected 0", len(outcome.Findings))
	}
}

func TestAdapter_UnsupportedVersionProducesNamedErrorAndUnavailableCheck(t *testing.T) {
	unsupportedAdapters := []struct {
		tool string
		ver  string
	}{
		{"gitleaks", "v7.0.0"},
		{"osv-scanner", "v3.0.0"},
		{"semgrep", "v2.0.0"},
		{"trivy", "v1.0.0"},
	}

	for _, tc := range unsupportedAdapters {
		err := normalize.ValidateToolVersion(tc.tool, tc.ver)
		if err == nil {
			t.Fatalf("expected error for unsupported version %s on %s", tc.ver, tc.tool)
		}
		if !strings.Contains(err.Error(), tc.tool) || !strings.Contains(err.Error(), tc.ver) {
			t.Fatalf("error %q must name both tool %s and version %s", err.Error(), tc.tool, tc.ver)
		}
	}
}

func TestFinding_FullEvidenceBundle(t *testing.T) {
	finding := evidence.Finding{
		Command:            "gitleaks detect --no-git --report-format sarif",
		Tool:               "gitleaks",
		ToolVersion:        "v8.30.1",
		RuleID:             "slack-bot-token",
		NativeSeverity:     "CRITICAL",
		NormalizedSeverity: evidence.SeverityCritical,
		Locations: []evidence.Location{
			{URI: "config.py"},
		},
		RawArtifact: evidence.ArtifactReference{
			URI:    "artifacts/gitleaks.sarif",
			Format: "sarif",
			Index:  0,
		},
		RawIndex: 0,
	}

	if finding.Command == "" {
		t.Fatal("finding missing Command in evidence bundle")
	}
	if finding.ToolVersion == "" {
		t.Fatal("finding missing ToolVersion in evidence bundle")
	}
	if finding.RuleID == "" {
		t.Fatal("finding missing RuleID in evidence bundle")
	}
	if len(finding.Locations) == 0 || finding.Locations[0].URI == "" {
		t.Fatal("finding missing Location in evidence bundle")
	}
	if finding.RawArtifact.URI == "" {
		t.Fatal("finding missing RawArtifact reference in evidence bundle")
	}
}

func TestDetectToolVersion_RealInstalledTools(t *testing.T) {
	for _, tool := range []string{"gitleaks", "osv-scanner"} {
		requireTool(t, tool)
		ver, err := DetectToolVersion(context.Background(), tool)
		if err != nil {
			t.Fatalf("DetectToolVersion(%s) failed: %v", tool, err)
		}
		if !strings.HasPrefix(ver, "v") {
			t.Fatalf("expected version prefix 'v', got %s", ver)
		}
		if err := normalize.ValidateToolVersion(tool, ver); err != nil {
			t.Fatalf("detected version %s failed validation for %s: %v", ver, tool, err)
		}
		t.Logf("detected %s version: %s", tool, ver)
	}
}

func TestParseVersionOutput(t *testing.T) {
	testCases := []struct {
		tool   string
		output string
		want   string
	}{
		{"gitleaks", "8.30.1\n", "v8.30.1"},
		{"gitleaks", "v8.18.0\n", "v8.18.0"},
		{"osv-scanner", "osv-scanner version: 2.5.1\nosv-scalibr version: 0.5.2\n", "v2.5.1"},
		{"osv-scanner", "osv-scanner version: 1.8.2\n", "v1.8.2"},
		{"semgrep", "1.90.0\n", "v1.90.0"},
		{"semgrep", "v1.85.0\n", "v1.85.0"},
		{"trivy", "Version: 0.58.0\nVulnerability DB:\n", "v0.58.0"},
	}

	for _, tc := range testCases {
		got, err := parseVersionOutput(tc.tool, tc.output)
		if err != nil {
			t.Fatalf("parseVersionOutput(%s) returned error: %v", tc.tool, err)
		}
		if got != tc.want {
			t.Fatalf("parseVersionOutput(%s) = %s, want %s", tc.tool, got, tc.want)
		}
	}
}

func TestAdapters_UnsupportedVersionProducesNamedError(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		adapter Adapter
		unsupp  string
	}{
		{func() Adapter { a := NewGitleaksAdapter(); a.SetVersion("v7.0.0"); return a }(), "v7.0.0"},
		{func() Adapter { a := NewOSVScannerAdapter(); a.SetVersion("v3.0.0"); return a }(), "v3.0.0"},
		{func() Adapter { a := NewSemgrepAdapter(); a.SetVersion("v2.0.0"); return a }(), "v2.0.0"},
		{func() Adapter { a := NewTrivyAdapter(); a.SetVersion("v1.0.0"); return a }(), "v1.0.0"},
	}

	for _, tc := range testCases {
		t.Run(tc.adapter.Name()+"_"+tc.unsupp, func(t *testing.T) {
			avail := tc.adapter.Availability(ctx)
			if !avail.Available {
				t.Skipf("%s is not installed on PATH", tc.adapter.Name())
			}
			outcome := tc.adapter.Run(ctx, ".")
			if outcome.Status != evidence.StatusUnavailable {
				t.Fatalf("%s with unsupported version %s returned status %s, want %s",
					tc.adapter.Name(), tc.unsupp, outcome.Status, evidence.StatusUnavailable)
			}
			if outcome.ExitCode != -1 {
				t.Fatalf("exit code = %d, want -1", outcome.ExitCode)
			}
			if !strings.Contains(outcome.StderrTail, tc.adapter.Name()) || !strings.Contains(outcome.StderrTail, tc.unsupp) {
				t.Fatalf("stderr %q must name both tool %s and version %s",
					outcome.StderrTail, tc.adapter.Name(), tc.unsupp)
			}
		})
	}
}

func TestAdapters_MissingOptionalToolProducesNotInstalledNeverPass(t *testing.T) {
	ctx := context.Background()

	for _, name := range []string{"semgrep", "trivy"} {
		if _, err := exec.LookPath(name); err == nil {
			t.Skipf("%s is installed; this test verifies missing tool behavior", name)
		}
	}

	s := NewSemgrepAdapter()
	outcomeS := s.Run(ctx, ".")
	if outcomeS.Status == evidence.StatusOK {
		t.Fatal("missing semgrep produced StatusOK; missing optional tool must never appear as a pass")
	}
	if outcomeS.Status != evidence.StatusNotInstalled {
		t.Fatalf("semgrep status = %s, want %s", outcomeS.Status, evidence.StatusNotInstalled)
	}
	if outcomeS.ExitCode != -1 {
		t.Fatalf("semgrep exit code = %d, want -1", outcomeS.ExitCode)
	}

	tr := NewTrivyAdapter()
	outcomeT := tr.Run(ctx, ".")
	if outcomeT.Status == evidence.StatusOK {
		t.Fatal("missing trivy produced StatusOK; missing optional tool must never appear as a pass")
	}
	if outcomeT.Status != evidence.StatusNotInstalled {
		t.Fatalf("trivy status = %s, want %s", outcomeT.Status, evidence.StatusNotInstalled)
	}
	if outcomeT.ExitCode != -1 {
		t.Fatalf("trivy exit code = %d, want -1", outcomeT.ExitCode)
	}
}

func TestAdapters_RawOutputRetainedInStoreAndReferencedInFindings(t *testing.T) {
	requireTool(t, "gitleaks")

	dir := secretFixtureDir(t)
	engine := app.NewEngine(func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{Gitleaks(ctx, targetDir)}
	})

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

	// Verify raw artifact file actually exists on disk in the artifact store
	data, err := os.ReadFile(run.RawArtifact.URI)
	if err != nil {
		t.Fatalf("failed to read raw artifact from store: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("raw artifact file in store is empty")
	}
	if !strings.Contains(string(data), `"runs"`) && !strings.Contains(string(data), `"version"`) {
		t.Fatalf("raw artifact content is not SARIF: %s", string(data)[:min(len(data), 100)])
	}

	// Verify findings reference this exact raw artifact
	if len(report.Findings) == 0 {
		t.Fatal("expected findings for secret fixture")
	}
	for i, f := range report.Findings {
		if f.RawArtifact.URI != run.RawArtifact.URI {
			t.Fatalf("finding %d RawArtifact URI %q != run RawArtifact URI %q",
				i, f.RawArtifact.URI, run.RawArtifact.URI)
		}
		if f.RawArtifact.Format != "sarif" {
			t.Fatalf("finding %d RawArtifact format = %q, want sarif", i, f.RawArtifact.Format)
		}
		if f.Command == "" {
			t.Fatalf("finding %d missing Command", i)
		}
	}
}

func TestOSVScanner_RawOutputRetainedInStoreAndReferencedInFindings(t *testing.T) {
	requireTool(t, "osv-scanner")

	dir := fixtureDir(t)
	lockfile := filepath.Join(dir, "package-lock.json")

	engine := app.NewEngine(func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{OSVScanner(ctx, lockfile)}
	})

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

	data, err := os.ReadFile(run.RawArtifact.URI)
	if err != nil {
		t.Fatalf("failed to read raw artifact from store: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("raw artifact file in store is empty")
	}

	if len(report.Findings) == 0 {
		t.Fatal("expected findings for vulnerable lockfile")
	}
	for i, f := range report.Findings {
		if f.RawArtifact.URI != run.RawArtifact.URI {
			t.Fatalf("finding %d RawArtifact URI %q != run RawArtifact URI %q",
				i, f.RawArtifact.URI, run.RawArtifact.URI)
		}
		if f.Command == "" {
			t.Fatalf("finding %d missing Command", i)
		}
	}
}

func TestAdapters_ArgumentArraysNeverShellStrings(t *testing.T) {
	maliciousTarget := "test-repo; rm -rf /; echo pwned"

	for _, a := range DefaultAdapters() {
		t.Run(a.Name(), func(t *testing.T) {
			cmd := a.Command(maliciousTarget)
			if len(cmd) < 2 {
				t.Fatalf("%s command slice too short: %v", a.Name(), cmd)
			}

			foundTarget := false
			for _, arg := range cmd {
				if arg == maliciousTarget {
					foundTarget = true
				}
				if strings.Contains(arg, "/bin/sh") || strings.Contains(arg, "sh -c") || strings.Contains(arg, "cmd.exe") {
					t.Fatalf("%s uses shell wrapper: %v", a.Name(), cmd)
				}
			}
			if !foundTarget {
				t.Fatalf("%s did not preserve malicious target as a single argument element: %v", a.Name(), cmd)
			}
		})
	}
}

func TestSemgrep_RealProcess_FindsFixtureFindings(t *testing.T) {
	requireTool(t, "semgrep")
	dir := fixtureDir(t)
	outcome := Semgrep(context.Background(), dir)
	if outcome.Status != evidence.StatusOK && outcome.Status != evidence.StatusFindings {
		t.Fatalf("semgrep status = %s, want ok or ok-findings", outcome.Status)
	}
}

func TestTrivy_RealProcess_FindsFixtureFindings(t *testing.T) {
	requireTool(t, "trivy")
	dir := fixtureDir(t)
	outcome := Trivy(context.Background(), dir)
	if outcome.Status != evidence.StatusOK && outcome.Status != evidence.StatusFindings {
		t.Fatalf("trivy status = %s, want ok or ok-findings", outcome.Status)
	}
}

func TestAdapters_CrashingAdapterDoesNotCorruptOtherResults(t *testing.T) {
	requireTool(t, "gitleaks")

	dir := secretFixtureDir(t)

	panickingAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		panic("boom: intentional adapter crash")
	}

	normalAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		return []evidence.RunOutcome{Gitleaks(ctx, targetDir)}
	}

	engine := app.NewEngine(panickingAdapter, normalAdapter)
	report, err := engine.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("engine.Scan failed: %v", err)
	}

	if len(report.Runs) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(report.Runs))
	}

	var crashedRun, okRun *evidence.RunOutcome
	for i := range report.Runs {
		if report.Runs[i].Status == evidence.StatusCrashed {
			crashedRun = &report.Runs[i]
		}
		if report.Runs[i].Status == evidence.StatusFindings {
			okRun = &report.Runs[i]
		}
	}

	if crashedRun == nil {
		t.Fatal("expected panicking adapter to produce StatusCrashed")
	}
	if !strings.Contains(crashedRun.StderrTail, "panic") {
		t.Fatalf("crashed run stderr %q does not mention panic", crashedRun.StderrTail)
	}

	for _, f := range okRun.Findings {
		t.Logf("finding: %s %s %v", f.RuleID, f.Message, f.Locations)
	}
	if len(okRun.Findings) == 0 {
		t.Fatal("expected findings from normal adapter")
	}
}
