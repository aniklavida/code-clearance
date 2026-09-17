package correlate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/correlate"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
)

// TestCrossToolCorrelation_TwoAdaptersOneIssue verifies that when two adapters report
// one issue, correlation produces a single correlated finding that names both sources
// and preserves both records.
func TestCrossToolCorrelation_TwoAdaptersOneIssue(t *testing.T) {
	// Load real fixtures: OSV-Scanner and Trivy reporting the same lodash CVE on package-lock.json
	osvData, err := os.ReadFile(filepath.Join("..", "normalize", "testdata", "osv-scanner.json"))
	if err != nil {
		t.Fatalf("read osv-scanner testdata: %v", err)
	}
	trivyData, err := os.ReadFile(filepath.Join("..", "normalize", "testdata", "trivy.json"))
	if err != nil {
		t.Fatalf("read trivy testdata: %v", err)
	}

	osvFindings, err := normalize.Ingest("osv-scanner", "v2.5.1", "json", osvData)
	if err != nil {
		t.Fatalf("ingest osv-scanner: %v", err)
	}
	trivyFindings, err := normalize.Ingest("trivy", "v0.58.0", "json", trivyData)
	if err != nil {
		t.Fatalf("ingest trivy: %v", err)
	}

	if len(osvFindings) != 1 {
		t.Fatalf("expected 1 osv-scanner finding, got %d", len(osvFindings))
	}
	if len(trivyFindings) != 1 {
		t.Fatalf("expected 1 trivy finding, got %d", len(trivyFindings))
	}

	osvID := osvFindings[0].ID
	trivyID := trivyFindings[0].ID

	// Assemble multi-tool report with raw outcomes
	report := evidence.Report{
		Runs: []evidence.RunOutcome{
			{
				Tool:        "osv-scanner",
				ToolVersion: "v2.5.1",
				Status:      evidence.StatusOK,
				Findings:    osvFindings,
				RawArtifact: &evidence.ArtifactReference{
					URI:    "json://osv-scanner/results.json",
					Format: "json",
					Index:  0,
				},
			},
			{
				Tool:        "trivy",
				ToolVersion: "v0.58.0",
				Status:      evidence.StatusOK,
				Findings:    trivyFindings,
				RawArtifact: &evidence.ArtifactReference{
					URI:    "json://trivy/results.json",
					Format: "json",
					Index:  1,
				},
			},
		},
	}

	// Exercise production correlation path
	correlate.CorrelateReport(&report)

	// Invariant 1: Exactly 1 single correlated finding produced in report.Findings
	if len(report.Findings) != 1 {
		t.Fatalf("expected exactly 1 correlated finding, got %d", len(report.Findings))
	}

	correlated := report.Findings[0]

	// Invariant 2: Names both sources
	if !strings.Contains(correlated.Tool, "osv-scanner") || !strings.Contains(correlated.Tool, "trivy") {
		t.Fatalf("correlated finding must name both tools in Tool field, got %q", correlated.Tool)
	}
	if !strings.Contains(correlated.Reviewer.Identity, "osv-scanner") || !strings.Contains(correlated.Reviewer.Identity, "trivy") {
		t.Fatalf("correlated finding must name both tools in Reviewer.Identity, got %q", correlated.Reviewer.Identity)
	}
	if !strings.Contains(correlated.Confidence.Rationale, "osv-scanner") || !strings.Contains(correlated.Confidence.Rationale, "trivy") {
		t.Fatalf("correlated finding must name both tools in Confidence.Rationale, got %q", correlated.Confidence.Rationale)
	}
	if !strings.Contains(correlated.Evidence.Details, "osv-scanner") || !strings.Contains(correlated.Evidence.Details, "trivy") {
		t.Fatalf("correlated finding must preserve evidence details from both tools, got %q", correlated.Evidence.Details)
	}

	// Invariant 3: Preserves both source records intact in report.Runs
	if len(report.Runs) != 2 {
		t.Fatalf("expected 2 runs in report, got %d", len(report.Runs))
	}
	if len(report.Runs[0].Findings) != 1 {
		t.Fatalf("expected 1 finding in run 0 (osv-scanner), got %d", len(report.Runs[0].Findings))
	}
	if len(report.Runs[1].Findings) != 1 {
		t.Fatalf("expected 1 finding in run 1 (trivy), got %d", len(report.Runs[1].Findings))
	}
	if report.Runs[0].Findings[0].Tool != "osv-scanner" {
		t.Fatalf("run 0 finding tool = %q, want osv-scanner", report.Runs[0].Findings[0].Tool)
	}
	if report.Runs[1].Findings[0].Tool != "trivy" {
		t.Fatalf("run 1 finding tool = %q, want trivy", report.Runs[1].Findings[0].Tool)
	}

	// Invariant 4: Report answers "which tools saw this?"
	tools := report.ToolsForFinding(correlated.ID)
	if len(tools) != 2 || tools[0] != "osv-scanner" || tools[1] != "trivy" {
		t.Fatalf("report.ToolsForFinding(%q) = %v, want [osv-scanner, trivy]", correlated.ID, tools)
	}
	// Also answers via constituent IDs
	toolsFromOSV := report.ToolsForFinding(osvID)
	if len(toolsFromOSV) != 2 || toolsFromOSV[0] != "osv-scanner" || toolsFromOSV[1] != "trivy" {
		t.Fatalf("report.ToolsForFinding(osvID) = %v, want [osv-scanner, trivy]", toolsFromOSV)
	}

	// Invariant 5: Both source records accessible via SourceRecordsForFinding
	records := report.SourceRecordsForFinding(correlated.ID)
	if len(records) != 2 {
		t.Fatalf("report.SourceRecordsForFinding = %d records, want 2", len(records))
	}

	// Invariant 6: Related and duplicate finding IDs written into the records
	hasTrivyInRel := false
	hasOSVInRel := false
	for _, id := range correlated.RelatedFindingIDs {
		if id == trivyID {
			hasTrivyInRel = true
		}
		if id == osvID {
			hasOSVInRel = true
		}
	}
	if !hasTrivyInRel || !hasOSVInRel {
		t.Fatalf("correlated finding missing constituent IDs in RelatedFindingIDs: %v", correlated.RelatedFindingIDs)
	}

	// Constituent records in runs also carry cross-references
	osvRunFinding := report.Runs[0].Findings[0]
	trivyRunFinding := report.Runs[1].Findings[0]

	foundTrivyInOSV := false
	for _, id := range osvRunFinding.RelatedFindingIDs {
		if id == trivyID {
			foundTrivyInOSV = true
			break
		}
	}
	if !foundTrivyInOSV {
		t.Fatalf("osv-scanner run finding must link to trivy finding in RelatedFindingIDs, got: %v",
			osvRunFinding.RelatedFindingIDs)
	}

	foundOSVInTrivy := false
	for _, id := range trivyRunFinding.RelatedFindingIDs {
		if id == osvID {
			foundOSVInTrivy = true
			break
		}
	}
	if !foundOSVInTrivy {
		t.Fatalf("trivy run finding must link to osv-scanner finding in RelatedFindingIDs, got: %v",
			trivyRunFinding.RelatedFindingIDs)
	}
}

// TestSingleAdapterDeduplication asserts that duplicate findings within a single adapter
// are collapsed into one finding while recording DuplicateFindingIDs and preserving evidence.
func TestSingleAdapterDeduplication(t *testing.T) {
	line10 := 10
	f1 := evidence.Finding{
		ID:                 "dup-1",
		Fingerprint:        "dup-1",
		Tool:               "semgrep",
		RuleID:             "sql-injection",
		Locations:          []evidence.Location{{URI: "app/views.py", StartLine: &line10, Snippet: "SELECT * FROM users"}},
		Scope:              evidence.FindingScope{Path: "app/views.py"},
		SnippetHash:        "snip-hash-abc",
		Message:            "SQL injection 1",
		Evidence:           evidence.FindingEvidence{Details: "rule matched on parameter user_id"},
		NormalizedSeverity: evidence.SeverityHigh,
	}

	// Exact duplicate from same tool/snippet/file with slightly different detail
	f2 := evidence.Finding{
		ID:                 "dup-2",
		Fingerprint:        "dup-2",
		Tool:               "semgrep",
		RuleID:             "sql-injection",
		Locations:          []evidence.Location{{URI: "app/views.py", StartLine: &line10, Snippet: "SELECT * FROM users"}},
		Scope:              evidence.FindingScope{Path: "app/views.py"},
		SnippetHash:        "snip-hash-abc",
		Message:            "SQL injection 2",
		Evidence:           evidence.FindingEvidence{Details: "additional taint sink detected"},
		NormalizedSeverity: evidence.SeverityHigh,
	}

	// Verify direct Deduplicate call
	directDedup := correlate.Deduplicate([]evidence.Finding{f1, f2})
	if len(directDedup) != 1 {
		t.Fatalf("correlate.Deduplicate failed to collapse duplicates, got %d findings", len(directDedup))
	}
	if len(directDedup[0].DuplicateFindingIDs) == 0 || directDedup[0].DuplicateFindingIDs[0] != "dup-2" {
		t.Fatalf("correlate.Deduplicate missing duplicate ID: %v", directDedup[0].DuplicateFindingIDs)
	}

	report := evidence.Report{
		Runs: []evidence.RunOutcome{
			{
				Tool:     "semgrep",
				Status:   evidence.StatusOK,
				Findings: []evidence.Finding{f1, f2},
			},
		},
	}

	correlate.CorrelateReport(&report)

	// Should collapse to 1 finding
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding after single-adapter deduplication, got %d", len(report.Findings))
	}

	collapsed := report.Findings[0]

	// DuplicateFindingIDs must record the second finding's ID
	foundDup2 := false
	for _, id := range collapsed.DuplicateFindingIDs {
		if id == "dup-2" {
			foundDup2 = true
			break
		}
	}
	if !foundDup2 {
		t.Fatalf("expected 'dup-2' in DuplicateFindingIDs, got: %v", collapsed.DuplicateFindingIDs)
	}

	// Evidence must be preserved
	if !strings.Contains(collapsed.Evidence.Details, "rule matched on parameter user_id") ||
		!strings.Contains(collapsed.Evidence.Details, "additional taint sink detected") {
		t.Fatalf("collapsed finding must preserve details from both duplicates, got: %q",
			collapsed.Evidence.Details)
	}
}

// TestCrossToolCorrelation_CodeSecrets asserts that two tools detecting a secret in the
// same file on the same line/snippet produce a single correlated finding naming both tools.
func TestCrossToolCorrelation_CodeSecrets(t *testing.T) {
	line4 := 4
	snippet := "SLACK_TOKEN = \"[REDACTED CREDENTIAL — matched here]\""
	snippetHash := "hash-slack-token-xyz"

	gitleaksFinding := evidence.Finding{
		ID:                 "gitl-1",
		Fingerprint:        "gitl-1",
		Tool:               "gitleaks",
		RuleID:             "slack-bot-token",
		Locations:          []evidence.Location{{URI: "config.py", StartLine: &line4, Snippet: snippet}},
		Scope:              evidence.FindingScope{Path: "config.py"},
		SnippetHash:        snippetHash,
		Message:            "Slack Bot Token",
		Evidence:           evidence.FindingEvidence{Details: "gitleaks entropy 4.2", Snippet: snippet},
		NormalizedSeverity: evidence.SeverityCritical,
	}

	semgrepFinding := evidence.Finding{
		ID:                 "semg-1",
		Fingerprint:        "semg-1",
		Tool:               "semgrep",
		RuleID:             "python.slack.token",
		Locations:          []evidence.Location{{URI: "config.py", StartLine: &line4, Snippet: snippet}},
		Scope:              evidence.FindingScope{Path: "config.py"},
		SnippetHash:        snippetHash,
		Message:            "Hardcoded Slack Token",
		Evidence:           evidence.FindingEvidence{Details: "semgrep AST pattern matched token", Snippet: snippet},
		NormalizedSeverity: evidence.SeverityHigh,
	}

	report := evidence.Report{
		Runs: []evidence.RunOutcome{
			{
				Tool:     "gitleaks",
				Findings: []evidence.Finding{gitleaksFinding},
			},
			{
				Tool:     "semgrep",
				Findings: []evidence.Finding{semgrepFinding},
			},
		},
	}

	correlate.CorrelateReport(&report)

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(report.Findings))
	}

	correlated := report.Findings[0]
	if !strings.Contains(correlated.Tool, "gitleaks") || !strings.Contains(correlated.Tool, "semgrep") {
		t.Fatalf("expected both tools named in correlated finding, got %q", correlated.Tool)
	}

	// Both source records must still exist in Runs
	if len(report.Runs[0].Findings) != 1 || len(report.Runs[1].Findings) != 1 {
		t.Fatalf("both source records must remain in Runs, got %d and %d",
			len(report.Runs[0].Findings), len(report.Runs[1].Findings))
	}

	// Normalized severity takes the higher severity (Critical > High)
	if correlated.NormalizedSeverity != evidence.SeverityCritical {
		t.Fatalf("expected normalized severity to be Critical, got %s", correlated.NormalizedSeverity)
	}
}

// TestCorrelationNeverDeletesSourceRecords asserts that correlation never deletes a source record.
func TestCorrelationNeverDeletesSourceRecords(t *testing.T) {
	// 3 tools reporting findings (2 reporting the same bug, 1 reporting a separate bug)
	r1 := evidence.Finding{
		ID:          "f-1",
		Tool:        "tool-a",
		Scope:       evidence.FindingScope{Path: "app.py"},
		SnippetHash: "hash-same",
		RawArtifact: evidence.ArtifactReference{URI: "art-1", Format: "json", Index: 0},
	}
	r2 := evidence.Finding{
		ID:          "f-2",
		Tool:        "tool-b",
		Scope:       evidence.FindingScope{Path: "app.py"},
		SnippetHash: "hash-same", // same as f-1
		RawArtifact: evidence.ArtifactReference{URI: "art-2", Format: "json", Index: 1},
	}
	r3 := evidence.Finding{
		ID:          "f-3",
		Tool:        "tool-c",
		Scope:       evidence.FindingScope{Path: "other.py"},
		SnippetHash: "hash-different",
		RawArtifact: evidence.ArtifactReference{URI: "art-3", Format: "json", Index: 2},
	}

	report := evidence.Report{
		Runs: []evidence.RunOutcome{
			{Tool: "tool-a", Findings: []evidence.Finding{r1}},
			{Tool: "tool-b", Findings: []evidence.Finding{r2}},
			{Tool: "tool-c", Findings: []evidence.Finding{r3}},
		},
	}

	correlate.CorrelateReport(&report)

	// Top level has 2 findings (f-1+f-2 correlated, f-3 distinct)
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 correlated findings, got %d", len(report.Findings))
	}

	// Invariant: Exactly 3 findings remain across Runs, none deleted!
	totalRunFindings := 0
	for _, run := range report.Runs {
		totalRunFindings += len(run.Findings)
	}
	if totalRunFindings != 3 {
		t.Fatalf("correlation deleted source records! Total run findings = %d, want 3", totalRunFindings)
	}

	// Raw artifacts preserved
	if report.Runs[0].Findings[0].RawArtifact.URI != "art-1" ||
		report.Runs[1].Findings[0].RawArtifact.URI != "art-2" ||
		report.Runs[2].Findings[0].RawArtifact.URI != "art-3" {
		t.Fatal("raw artifact references corrupted or lost")
	}
}
