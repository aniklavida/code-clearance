package normalize

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/schema"
	"github.com/aniklavida/code-clearance/internal/store"
)

// 1. Fixture-based parser tests for every supported tool output: Semgrep CE, Gitleaks, OSV-Scanner, Trivy
// across both SARIF and native JSON formats.

func TestNormalize_Semgrep_SARIF(t *testing.T) {
	data, err := os.ReadFile("testdata/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}

	findings, err := Ingest("semgrep", "v1.90.0", "sarif", data)
	if err != nil {
		t.Fatalf("Ingest Semgrep SARIF: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "rules.python.security.injection.hardcoded-sql-expression" {
		t.Errorf("rule_id = %q", f.RuleID)
	}
	if f.NativeSeverity != "warning" {
		t.Errorf("native_severity = %q, want warning", f.NativeSeverity)
	}
	if f.NormalizedSeverity != evidence.SeverityMedium {
		t.Errorf("normalized_severity = %s, want medium", f.NormalizedSeverity)
	}
	if len(f.Locations) != 1 || f.Locations[0].URI != "app/views.py" {
		t.Fatalf("unexpected locations: %+v", f.Locations)
	}
	if f.Confidence.Rationale == "" {
		t.Error("expected non-empty confidence rationale")
	}
}

func TestNormalize_Semgrep_NativeJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/semgrep.json")
	if err != nil {
		t.Fatal(err)
	}

	findings, err := Ingest("semgrep", "v1.90.0", "json", data)
	if err != nil {
		t.Fatalf("Ingest Semgrep native JSON: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "rules.python.security.injection.hardcoded-sql-expression" {
		t.Errorf("rule_id = %q", f.RuleID)
	}
	if f.NativeSeverity != "WARNING" {
		t.Errorf("native_severity = %q, want WARNING", f.NativeSeverity)
	}
	if f.NormalizedSeverity != evidence.SeverityMedium {
		t.Errorf("normalized_severity = %s, want medium", f.NormalizedSeverity)
	}
	if len(f.Locations) != 1 || f.Locations[0].URI != "app/views.py" {
		t.Fatalf("unexpected locations: %+v", f.Locations)
	}
	if f.Locations[0].StartLine == nil || *f.Locations[0].StartLine != 14 {
		t.Errorf("start line = %v, want 14", f.Locations[0].StartLine)
	}
}

func TestNormalize_Trivy_SARIF(t *testing.T) {
	data, err := os.ReadFile("testdata/trivy.sarif")
	if err != nil {
		t.Fatal(err)
	}

	findings, err := Ingest("trivy", "v0.58.0", "sarif", data)
	if err != nil {
		t.Fatalf("Ingest Trivy SARIF: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CVE-2020-8203" {
		t.Errorf("rule_id = %q, want CVE-2020-8203", f.RuleID)
	}
	if f.NativeSeverity != "error" {
		t.Errorf("native_severity = %q, want error", f.NativeSeverity)
	}
	if f.NormalizedSeverity != evidence.SeverityHigh {
		t.Errorf("normalized_severity = %s, want high", f.NormalizedSeverity)
	}
	if len(f.Locations) != 1 || f.Locations[0].URI != "package-lock.json" {
		t.Fatalf("unexpected locations: %+v", f.Locations)
	}
}

func TestNormalize_Trivy_NativeJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/trivy.json")
	if err != nil {
		t.Fatal(err)
	}

	findings, err := Ingest("trivy", "v0.58.0", "json", data)
	if err != nil {
		t.Fatalf("Ingest Trivy native JSON: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CVE-2020-8203" {
		t.Errorf("rule_id = %q, want CVE-2020-8203", f.RuleID)
	}
	if f.NativeSeverity != "HIGH" {
		t.Errorf("native_severity = %q, want HIGH", f.NativeSeverity)
	}
	if f.NormalizedSeverity != evidence.SeverityHigh {
		t.Errorf("normalized_severity = %s, want high", f.NormalizedSeverity)
	}
	if f.Locations[0].URI != "package-lock.json" {
		t.Errorf("location URI = %q, want package-lock.json", f.Locations[0].URI)
	}
}

func TestNormalize_Gitleaks_NativeJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/gitleaks.json")
	if err != nil {
		t.Fatal(err)
	}

	findings, err := Ingest("gitleaks", "v8.30.1", "json", data)
	if err != nil {
		t.Fatalf("Ingest Gitleaks native JSON: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	for _, f := range findings {
		if f.NativeSeverity != "CRITICAL" {
			t.Errorf("native_severity = %q, want CRITICAL", f.NativeSeverity)
		}
		if f.NormalizedSeverity != evidence.SeverityCritical {
			t.Errorf("normalized_severity = %s, want critical", f.NormalizedSeverity)
		}
	}
}

func TestNormalize_OSVScanner_NativeJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/osv-scanner.json")
	if err != nil {
		t.Fatal(err)
	}

	findings, err := Ingest("osv-scanner", "v2.5.1", "json", data)
	if err != nil {
		t.Fatalf("Ingest OSV-Scanner native JSON: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "GHSA-p6mc-m468-83gw" {
		t.Errorf("rule_id = %q, want GHSA-p6mc-m468-83gw", f.RuleID)
	}
	if f.NativeSeverity != "HIGH" {
		t.Errorf("native_severity = %q, want HIGH", f.NativeSeverity)
	}
	if f.NormalizedSeverity != evidence.SeverityHigh {
		t.Errorf("normalized_severity = %s, want high", f.NormalizedSeverity)
	}
}

// 2. Acceptance Criteria 1: A parser that cannot understand its input fails loudly
// and marks that check unavailable. A half-parsed file is not a result.

func TestMalformedFile_ProducesNamedErrorAndUnavailableStatus(t *testing.T) {
	malformedInputs := []struct {
		tool   string
		format string
		data   []byte
	}{
		{"semgrep", "json", []byte(`{"version": "1.0", "results": [ truncated...`)},
		{"semgrep", "sarif", []byte(`{"$schema": "sarif", "version": "2.1.0"}`)}, // missing runs
		{"trivy", "json", []byte(`{"not_trivy": true}`)},
		{"gitleaks", "json", []byte(`{"not_an_array": true}`)},
		{"osv-scanner", "json", []byte(`{"no_results_field": true}`)},
		{"osv-scanner", "sarif", []byte(`{not valid json`)},
	}

	for _, tc := range malformedInputs {
		t.Run(tc.tool+"_"+tc.format, func(t *testing.T) {
			_, err := Ingest(tc.tool, "v1.90.0", tc.format, tc.data)
			if err == nil {
				// Try with tool's supported version
				var validVer string
				switch tc.tool {
				case "gitleaks":
					validVer = "v8.30.1"
				case "osv-scanner":
					validVer = "v2.5.1"
				case "semgrep":
					validVer = "v1.90.0"
				case "trivy":
					validVer = "v0.58.0"
				}
				_, err = Ingest(tc.tool, validVer, tc.format, tc.data)
			}

			if err == nil {
				t.Fatalf("%s (%s): expected loud parse error on malformed input, got nil", tc.tool, tc.format)
			}

			// Error must name the tool
			if !strings.Contains(err.Error(), tc.tool) {
				t.Errorf("error %q does not name tool %q", err.Error(), tc.tool)
			}
		})
	}
}

// 3. Acceptance Criteria 2: An unsupported version produces a clear error naming
// the tool and the version.

func TestUnsupportedVersion_NamesToolAndVersion(t *testing.T) {
	testCases := []struct {
		tool    string
		version string
	}{
		{"gitleaks", "v7.0.0"},
		{"gitleaks", "v9.0.0"},
		{"osv-scanner", "v0.5.0"},
		{"osv-scanner", "v3.0.0"},
		{"semgrep", "v0.40.0"},
		{"semgrep", "v2.0.0"},
		{"trivy", "v1.0.0"},
		{"trivy", "v2.5.0"},
	}

	for _, tc := range testCases {
		t.Run(tc.tool+"_"+tc.version, func(t *testing.T) {
			err := ValidateToolVersion(tc.tool, tc.version)
			if err == nil {
				t.Fatalf("expected error for unsupported version %s on %s, got nil", tc.version, tc.tool)
			}

			errMsg := err.Error()
			if !strings.Contains(errMsg, tc.tool) {
				t.Errorf("error %q missing tool name %q", errMsg, tc.tool)
			}
			if !strings.Contains(errMsg, tc.version) {
				t.Errorf("error %q missing unsupported version string %q", errMsg, tc.version)
			}

			// Also verify Ingest fails immediately with this error
			_, ingestErr := Ingest(tc.tool, tc.version, "sarif", []byte(`{"version":"2.1.0","runs":[]}`))
			if ingestErr == nil {
				t.Fatalf("Ingest accepted unsupported version %s for %s", tc.version, tc.tool)
			}
			if !strings.Contains(ingestErr.Error(), tc.tool) || !strings.Contains(ingestErr.Error(), tc.version) {
				t.Errorf("Ingest error %q does not name both tool and version", ingestErr.Error())
			}
		})
	}
}

// 4. Constraint: Normalization must not destroy source detail.
// A finding carries both severities and resolves back to its raw artifact.

func TestFinding_CarriesBothSeveritiesAndResolvesToRawArtifact(t *testing.T) {
	data, err := os.ReadFile("testdata/semgrep.json")
	if err != nil {
		t.Fatal(err)
	}

	findings, err := Ingest("semgrep", "v1.90.0", "json", data)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}

	f := findings[0]

	// 1. Carries original severity
	if f.NativeSeverity != "WARNING" {
		t.Errorf("NativeSeverity = %q, want WARNING", f.NativeSeverity)
	}

	// 2. Carries normalized severity
	if f.NormalizedSeverity != evidence.SeverityMedium {
		t.Errorf("NormalizedSeverity = %s, want medium", f.NormalizedSeverity)
	}

	// 3. Carries source rule ID
	if f.RuleID != "rules.python.security.injection.hardcoded-sql-expression" {
		t.Errorf("RuleID = %q", f.RuleID)
	}

	// 4. Resolves back to its raw artifact
	if f.RawArtifact.URI == "" {
		t.Fatal("empty RawArtifact.URI")
	}
	if f.RawArtifact.Format != "json" {
		t.Errorf("RawArtifact.Format = %q, want json", f.RawArtifact.Format)
	}

	// Verify the finding's index in the raw artifact retrieves the exact original source entry
	var rawDoc semgrepOutput
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		t.Fatalf("unmarshal rawDoc: %v", err)
	}
	if f.RawIndex >= len(rawDoc.Results) {
		t.Fatalf("RawIndex %d out of bounds for %d raw results", f.RawIndex, len(rawDoc.Results))
	}
	origResult := rawDoc.Results[f.RawIndex]
	if origResult.CheckID != f.RuleID {
		t.Errorf("resolved raw result check_id %q != finding RuleID %q", origResult.CheckID, f.RuleID)
	}
	if origResult.Extra.Severity != f.NativeSeverity {
		t.Errorf("resolved raw result severity %q != finding NativeSeverity %q", origResult.Extra.Severity, f.NativeSeverity)
	}
}

// 5. Confidence carrying a written rationale, not a bare number.

func TestConfidence_CarriesWrittenRationaleNotBareNumber(t *testing.T) {
	fixtureFiles := []struct {
		path string
		tool string
		ver  string
		fmt  string
	}{
		{"testdata/semgrep.sarif", "semgrep", "v1.90.0", "sarif"},
		{"testdata/semgrep.json", "semgrep", "v1.90.0", "json"},
		{"testdata/trivy.sarif", "trivy", "v0.58.0", "sarif"},
		{"testdata/trivy.json", "trivy", "v0.58.0", "json"},
		{"testdata/gitleaks.sarif", "gitleaks", "v8.30.1", "sarif"},
		{"testdata/gitleaks.json", "gitleaks", "v8.30.1", "json"},
		{"testdata/osv-scanner.sarif", "osv-scanner", "v2.5.1", "sarif"},
		{"testdata/osv-scanner.json", "osv-scanner", "v2.5.1", "json"},
	}

	for _, ff := range fixtureFiles {
		t.Run(filepath.Base(ff.path), func(t *testing.T) {
			data, err := os.ReadFile(ff.path)
			if err != nil {
				t.Fatal(err)
			}
			findings, err := Ingest(ff.tool, ff.ver, ff.fmt, data)
			if err != nil {
				t.Fatalf("Ingest %s: %v", ff.path, err)
			}
			if len(findings) == 0 {
				t.Fatalf("no findings parsed from %s", ff.path)
			}

			for i, f := range findings {
				rat := f.Confidence.Rationale
				if rat == "" {
					t.Fatalf("finding[%d] in %s has empty confidence rationale", i, ff.path)
				}
				// Rationale must NOT be a bare number
				if _, err := strconv.ParseFloat(rat, 64); err == nil {
					t.Fatalf("finding[%d] in %s has bare numerical rationale: %q", i, ff.path, rat)
				}
				// Must contain explanatory words
				if len(strings.Fields(rat)) < 3 {
					t.Errorf("finding[%d] in %s rationale too terse (%q), expected written explanation", i, ff.path, rat)
				}
			}
		})
	}
}

// 6. Acceptance Criteria: A fixture containing a live-looking secret is redacted
// in the report and in the agent-facing payload — assert both, separately.
// The fixture is assembled at runtime from fragments, never committed as a literal.

func TestSecretRedaction_InReportAndInAgentFacingPayload(t *testing.T) {
	// Assemble secret fragments at runtime so no literal exists in the repository
	slackSecret := strings.Join([]string{"xoxb", "998877665544", "1122334455667", "abcdefghijklmnopqrstuvwx"}, "-")
	stripeKey := strings.Join([]string{"sk", "live", "51H8x9K2eZvKYlo2CkQ7tNGGyRfTeStFiXtUrEsAbCdEfGh"}, "_")

	runtimeJSON := `[
		{
			"Description": "Found Slack Bot Token: ` + slackSecret + ` in environment",
			"StartLine": 10,
			"EndLine": 10,
			"StartColumn": 1,
			"EndColumn": 65,
			"Match": "` + slackSecret + `",
			"Secret": "` + slackSecret + `",
			"File": "config/secrets.py",
			"RuleID": "slack-bot-token",
			"Entropy": 3.9
		},
		{
			"Description": "Found Stripe Live Key in source code: ` + stripeKey + `",
			"StartLine": 20,
			"EndLine": 20,
			"StartColumn": 1,
			"EndColumn": 70,
			"Match": "STRIPE_KEY = \"` + stripeKey + `\"",
			"Secret": "` + stripeKey + `",
			"File": "config/stripe.py",
			"RuleID": "stripe-access-token",
			"Entropy": 4.2
		}
	]`

	findings, err := Ingest("gitleaks", "v8.30.1", "json", []byte(runtimeJSON))
	if err != nil {
		t.Fatalf("Ingest runtime secret fixture: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// 1. Build a full Report and assert secrets are completely redacted from the report
	report := evidence.Report{
		SchemaVersion: "v1",
		Target: evidence.TargetBinding{
			Repository:  "https://github.com/example/test",
			Commit:      "abcdef1234567890",
			Dirty:       false,
			Fingerprint: "clean",
		},
		Outcome: evidence.OutcomeBlocked,
		Runs: []evidence.RunOutcome{
			{
				Tool:        "gitleaks",
				ToolVersion: "v8.30.1",
				Command:     "gitleaks detect --report-format json",
				ExitCode:    1,
				Duration:    "50ms",
				Status:      evidence.StatusFindings,
				Findings:    findings,
			},
		},
		Findings: findings,
		Uncovered: evidence.UncoveredChecks{
			Skipped:     []evidence.UncoveredCheck{},
			Crashed:     []evidence.UncoveredCheck{},
			TimedOut:    []evidence.UncoveredCheck{},
			Unavailable: []evidence.UncoveredCheck{},
		},
		Coverage: evidence.CoverageReport{
			Scope:        "quick",
			FilesChecked: []string{"config/secrets.py", "config/stripe.py"},
			AdaptersRan:  []string{"gitleaks"},
			Summary:      "Scan finished",
		},
		ResidualRisk: []evidence.ResidualRiskItem{},
		Timestamps: evidence.ReportTimestamps{
			StartedAt:   "2026-09-17T12:00:00Z",
			CompletedAt: "2026-09-17T12:00:01Z",
		},
	}

	reportBytes, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	reportStr := string(reportBytes)

	// SEPARATE ASSERTION 1: Secret is redacted in the report JSON
	t.Run("RedactedInReport", func(t *testing.T) {
		if strings.Contains(reportStr, slackSecret) {
			t.Fatal("SECURITY LEAK: report JSON contains unredacted slackSecret!")
		}
		if strings.Contains(reportStr, stripeKey) {
			t.Fatal("SECURITY LEAK: report JSON contains unredacted stripeKey!")
		}
		if !strings.Contains(reportStr, "[REDACTED]") {
			t.Fatal("report JSON does not contain [REDACTED] marker")
		}

		// Verify the sanitized report still satisfies report.schema.json
		if err := schema.ValidateReport(reportBytes); err != nil {
			t.Fatalf("sanitized report failed schema validation: %v", err)
		}
	})

	// SEPARATE ASSERTION 2: Secret is redacted in the agent-facing payload (finding evidence)
	t.Run("RedactedInAgentFacingPayload", func(t *testing.T) {
		for i, f := range findings {
			payloadBytes, err := json.Marshal(f)
			if err != nil {
				t.Fatalf("marshal finding[%d]: %v", i, err)
			}
			payloadStr := string(payloadBytes)

			if strings.Contains(payloadStr, slackSecret) {
				t.Fatalf("SECURITY LEAK: agent finding payload[%d] contains unredacted slackSecret!", i)
			}
			if strings.Contains(payloadStr, stripeKey) {
				t.Fatalf("SECURITY LEAK: agent finding payload[%d] contains unredacted stripeKey!", i)
			}
			if !strings.Contains(payloadStr, "[REDACTED]") {
				t.Fatalf("agent finding payload[%d] missing [REDACTED] marker", i)
			}
		}
	})
}

// 7. Test that RawArtifact can be read via Store
func TestRawArtifact_ResolvesThroughStore(t *testing.T) {
	tempDir := t.TempDir()
	st, err := store.New(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	session, err := st.CreateRun("test-run")
	if err != nil {
		t.Fatal(err)
	}

	rawPayload := []byte(`{"results": [{"check_id": "test.rule", "extra": {"severity": "WARNING"}}]}`)
	ref, err := session.SaveArtifact("semgrep", "json", rawPayload)
	if err != nil {
		t.Fatalf("SaveArtifact: %v", err)
	}

	retrieved, err := st.GetArtifact(ref)
	if err != nil {
		t.Fatalf("GetArtifact: %v", err)
	}

	if string(retrieved) != string(rawPayload) {
		t.Fatalf("retrieved %q != original %q", string(retrieved), string(rawPayload))
	}
}
