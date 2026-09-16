package adapters

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

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

	slack := strings.Join([]string{"xoxb", "778450471234", "7784504712345", "ZnJ0aGVzY2FubmVyb25seQ"}, "-")
	stripe := "sk_" + "live_" + "51H8x9K2eZvKYlo2CkQ7tNGGyRfTeStFiXtUrEsAbCdEfGh"

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

// The card's headline safety constraint is that a killed or timed-out adapter
// surfaces as unavailable evidence, never as a pass. The engine-level test for
// this builds its own status mapping inside the test body, so it proves the
// runner detects a timeout but never exercises the mapping in this package —
// the code that actually decides whether a dead check reports as OK.
//
// This drives the real adapter, with a real process, killed by a real deadline.
func TestGitleaks_TimedOutRunIsNeverReportedAsAPass(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks is not installed; this test needs the real binary to be killed mid-run")
	}

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
