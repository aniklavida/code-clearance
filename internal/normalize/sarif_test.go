package normalize

import (
	"os"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// These fixtures are real, unmodified SARIF 2.1.0 output captured during
// the two tools this was first proven against:
//   - gitleaks.sarif:    `gitleaks detect --no-git --report-format sarif`
//     against a fixture file containing two fabricated secrets.
//   - osv-scanner.sarif: `osv-scanner scan source --format sarif -L package-lock.json`
//     against a fixture pinning lodash@4.17.15, a version with known CVEs.

func TestNormalize_Gitleaks_RealOutput(t *testing.T) {
	data, err := os.ReadFile("testdata/gitleaks.sarif")
	if err != nil {
		t.Fatal(err)
	}
	log, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	findings := Normalize("gitleaks", "v8.30.1", log, GitleaksSeverity)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (slack-bot-token, stripe-access-token)", len(findings))
	}

	byRule := map[string]evidence.Finding{}
	for _, f := range findings {
		byRule[f.RuleID] = f
	}

	slack, ok := byRule["slack-bot-token"]
	if !ok {
		t.Fatal("missing slack-bot-token finding")
	}
	if slack.NormalizedSeverity != evidence.SeverityCritical {
		t.Errorf("slack severity = %s, want critical (gitleaks SARIF carries no severity field at all)", slack.NormalizedSeverity)
	}
	if len(slack.Locations) != 1 {
		t.Fatalf("slack locations = %d, want 1", len(slack.Locations))
	}
	loc := slack.Locations[0]
	if loc.StartLine == nil || *loc.StartLine != 4 {
		t.Errorf("slack start line = %v, want 4", loc.StartLine)
	}
	if loc.Snippet == "" {
		t.Error("expected gitleaks to include a snippet")
	}

	stripe, ok := byRule["stripe-access-token"]
	if !ok {
		t.Fatal("missing stripe-access-token finding")
	}
	if stripe.Locations[0].StartLine == nil || *stripe.Locations[0].StartLine != 5 {
		t.Errorf("stripe start line = %v, want 5", stripe.Locations[0].StartLine)
	}
}

func TestNormalize_OSVScanner_RealOutput(t *testing.T) {
	data, err := os.ReadFile("testdata/osv-scanner.sarif")
	if err != nil {
		t.Fatal(err)
	}
	log, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	rawCount := len(log.Runs[0].Results)
	findings := Normalize("osv-scanner", "v2.5.1", log, OSVScannerSeverity)

	// Real observed behaviour: osv-scanner's own SARIF run contained 6
	// raw results but only 4 distinct rule IDs — two results were
	// byte-identical duplicates of the same CVE against the same
	// package within a single run. Normalize must collapse those.
	if rawCount != 6 {
		t.Fatalf("fixture assumption changed: raw results = %d, want 6", rawCount)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d normalized findings, want 4 after intra-run dedupe", len(findings))
	}

	foundSeverity := map[evidence.Severity]int{}
	for _, f := range findings {
		foundSeverity[f.NormalizedSeverity]++
		// osv-scanner gives whole-file locations for lockfile findings:
		// no line/column at all. This is the opposite of gitleaks and
		// must not be treated as a parse failure.
		if len(f.Locations) != 1 {
			t.Fatalf("%s: locations = %d, want 1", f.RuleID, len(f.Locations))
		}
		if f.Locations[0].StartLine != nil {
			t.Errorf("%s: expected no line info for a lockfile-level finding, got %v", f.RuleID, *f.Locations[0].StartLine)
		}
	}
	if foundSeverity[evidence.SeverityUnknown] > 0 {
		t.Errorf("expected every osv-scanner finding to resolve a severity from security-severity, got %d unknown", foundSeverity[evidence.SeverityUnknown])
	}
}

func TestNormalize_CrossToolFingerprintsDoNotCollide(t *testing.T) {
	gData, _ := os.ReadFile("testdata/gitleaks.sarif")
	oData, _ := os.ReadFile("testdata/osv-scanner.sarif")
	gLog, _ := Parse(gData)
	oLog, _ := Parse(oData)

	gFindings := Normalize("gitleaks", "v8.30.1", gLog, GitleaksSeverity)
	oFindings := Normalize("osv-scanner", "v2.5.1", oLog, OSVScannerSeverity)

	seen := map[string]string{}
	for _, f := range append(gFindings, oFindings...) {
		if prev, ok := seen[f.ID]; ok {
			t.Fatalf("fingerprint collision: %s used by both %s and %s", f.ID, prev, f.Tool)
		}
		seen[f.ID] = f.Tool
	}
}

func TestParse_RejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte(`{not json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if _, err := Parse([]byte(`{"version":"2.1.0"}`)); err == nil {
		t.Fatal("expected error for missing runs")
	}
}
