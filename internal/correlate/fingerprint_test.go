package correlate_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/correlate"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// TestFingerprint_StableAcrossLineInsertion verifies that inserting an unrelated line
// above a finding does not change its fingerprint.
// Real production before/after: build fixture, ingest/fingerprint, insert line above,
// ingest/fingerprint again, and assert equality.
func TestFingerprint_StableAcrossLineInsertion(t *testing.T) {
	// Original fixture code: finding at line 3
	originalContent := "import os\nimport sys\ncursor.execute(\"SELECT * FROM users WHERE id = '%s'\" % user_id)\n"

	// Construct native JSON output representing finding on line 3
	type semgrepPos struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	}
	type semgrepExtra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Lines    string `json:"lines"`
	}
	type semgrepResult struct {
		CheckID string       `json:"check_id"`
		Path    string       `json:"path"`
		Start   semgrepPos   `json:"start"`
		End     semgrepPos   `json:"end"`
		Extra   semgrepExtra `json:"extra"`
	}
	type semgrepOutput struct {
		Version string          `json:"version"`
		Results []semgrepResult `json:"results"`
	}

	snippet := "cursor.execute(\"SELECT * FROM users WHERE id = '%s'\" % user_id)"
	ruleID := "rules.python.security.injection.hardcoded-sql-expression"
	filePath := "app/views.py"

	outBefore := semgrepOutput{
		Version: "1.90.0",
		Results: []semgrepResult{
			{
				CheckID: ruleID,
				Path:    filePath,
				Start:   semgrepPos{Line: 3, Col: 1},
				End:     semgrepPos{Line: 3, Col: 65},
				Extra: semgrepExtra{
					Message:  "Possible SQL injection detected in database query execution.",
					Severity: "WARNING",
					Lines:    snippet,
				},
			},
		},
	}
	dataBefore, err := json.Marshal(outBefore)
	if err != nil {
		t.Fatalf("marshal before: %v", err)
	}

	findingsBefore, err := normalize.Ingest("semgrep", "v1.90.0", "json", dataBefore)
	if err != nil {
		t.Fatalf("ingest before: %v", err)
	}
	if len(findingsBefore) != 1 {
		t.Fatalf("expected 1 finding before, got %d", len(findingsBefore))
	}
	fpBefore := findingsBefore[0].Fingerprint
	startLineBefore := *findingsBefore[0].Locations[0].StartLine
	if startLineBefore != 3 {
		t.Fatalf("expected start line 3 before, got %d", startLineBefore)
	}

	// Insert an unrelated comment line at the top of the file
	_ = "# Unrelated header comment\n" + originalContent

	// Scanner rerun on modified file: finding has shifted from line 3 to line 4
	outAfter := semgrepOutput{
		Version: "1.90.0",
		Results: []semgrepResult{
			{
				CheckID: ruleID,
				Path:    filePath,
				Start:   semgrepPos{Line: 4, Col: 1}, // shifted by 1 line
				End:     semgrepPos{Line: 4, Col: 65},
				Extra: semgrepExtra{
					Message:  "Possible SQL injection detected in database query execution.",
					Severity: "WARNING",
					Lines:    snippet, // snippet content is unchanged
				},
			},
		},
	}
	dataAfter, err := json.Marshal(outAfter)
	if err != nil {
		t.Fatalf("marshal after: %v", err)
	}

	findingsAfter, err := normalize.Ingest("semgrep", "v1.90.0", "json", dataAfter)
	if err != nil {
		t.Fatalf("ingest after: %v", err)
	}
	if len(findingsAfter) != 1 {
		t.Fatalf("expected 1 finding after, got %d", len(findingsAfter))
	}
	fpAfter := findingsAfter[0].Fingerprint
	startLineAfter := *findingsAfter[0].Locations[0].StartLine

	// Confirm line number actually moved
	if startLineAfter != 4 {
		t.Fatalf("expected start line 4 after, got %d", startLineAfter)
	}
	if startLineBefore == startLineAfter {
		t.Fatal("precondition failed: line number did not shift")
	}

	// Invariant check: Fingerprints MUST be identical despite line shift
	if fpBefore != fpAfter {
		t.Fatalf("fingerprint drift detected on unrelated line insertion:\n  before (line %d): %s\n  after  (line %d): %s",
			startLineBefore, fpBefore, startLineAfter, fpAfter)
	}
}

// TestFingerprint_DeterministicAcrossRuns asserts that re-running an unchanged repository
// produces byte-identical fingerprints.
func TestFingerprint_DeterministicAcrossRuns(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "normalize", "testdata", "semgrep.json"))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	// Run 1
	findings1, err := normalize.Ingest("semgrep", "v1.90.0", "json", data)
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}

	// Run 2
	findings2, err := normalize.Ingest("semgrep", "v1.90.0", "json", data)
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}

	if len(findings1) != len(findings2) || len(findings1) == 0 {
		t.Fatalf("mismatched finding counts: %d vs %d", len(findings1), len(findings2))
	}

	for i := range findings1 {
		if findings1[i].ID != findings2[i].ID {
			t.Fatalf("non-deterministic ID at index %d: %q != %q", i, findings1[i].ID, findings2[i].ID)
		}
		if findings1[i].Fingerprint != findings2[i].Fingerprint {
			t.Fatalf("non-deterministic Fingerprint at index %d: %q != %q", i, findings1[i].Fingerprint, findings2[i].Fingerprint)
		}
	}
}

// TestFingerprint_DistinguishesDifferentIssuesInSameFile ensures that two different issues
// in the same file receive distinct fingerprints.
func TestFingerprint_DistinguishesDifferentIssuesInSameFile(t *testing.T) {
	f1 := evidence.Finding{
		Tool:        "semgrep",
		RuleID:      "sql-injection",
		Scope:       evidence.FindingScope{Path: "app/views.py"},
		SnippetHash: "a1b2c3d4e5f6",
		Message:     "SQL injection on line 10",
	}
	f2 := evidence.Finding{
		Tool:        "semgrep",
		RuleID:      "sql-injection",
		Scope:       evidence.FindingScope{Path: "app/views.py"},
		SnippetHash: "f6e5d4c3b2a1", // different snippet
		Message:     "SQL injection on line 40",
	}

	fp1 := correlate.Fingerprint(f1)
	fp2 := correlate.Fingerprint(f2)

	if fp1 == fp2 {
		t.Fatalf("expected distinct fingerprints for distinct snippets, got %s", fp1)
	}
}

// TestAcceptedRisk_MatchesAfterUnrelatedEdit asserts that an accepted-risk rule
// keyed on a fingerprint still matches and suppresses the finding after an unrelated edit.
func TestAcceptedRisk_MatchesAfterUnrelatedEdit(t *testing.T) {
	snippet := "token = \"[REDACTED CREDENTIAL — matched here]\""
	ruleID := "stripe-access-token"
	filePath := "config.py"

	// Before edit: finding on line 10
	startLine10 := 10
	fBefore := evidence.Finding{
		Tool:               "gitleaks",
		ToolVersion:        "v8.30.1",
		RuleID:             ruleID,
		NativeSeverity:     "CRITICAL",
		NormalizedSeverity: evidence.SeverityCritical,
		Locations: []evidence.Location{
			{URI: filePath, StartLine: &startLine10, Snippet: snippet},
		},
		Scope:       evidence.FindingScope{Commit: "HEAD", Path: filePath},
		SnippetHash: "stripe-token-hash-12345",
		Message:     "Stripe Access Token detected",
		Evidence:    evidence.FindingEvidence{Snippet: snippet},
	}
	fBefore.ID = correlate.Fingerprint(fBefore)
	fBefore.Fingerprint = fBefore.ID

	// Create policy config with an accepted risk keyed on the finding's fingerprint
	cfg := policy.DefaultConfig()
	cfg.Policy.AcceptedRisks = []policy.AcceptedRiskRule{
		{
			FindingID: fBefore.ID,
			Reason:    "Test key for mock environment",
			ExpiresAt: "9999-12-31T23:59:59Z",
		},
	}

	repBefore := evidence.Report{
		Runs: []evidence.RunOutcome{
			{
				Tool:     "gitleaks",
				Status:   evidence.StatusOK,
				Findings: []evidence.Finding{fBefore},
			},
		},
	}
	correlate.CorrelateReport(&repBefore)

	// Evaluate policy before edit: must be cleared with residual risk (finding suppressed)
	verdictBefore := policy.Evaluate(cfg, repBefore)
	if verdictBefore.Outcome != evidence.OutcomeClearedWithResidualRisk {
		t.Fatalf("before edit: expected cleared-with-residual-risk, got %s (reason: %s)",
			verdictBefore.Outcome, verdictBefore.Reason)
	}
	if len(verdictBefore.ResidualRisk) != 1 {
		t.Fatalf("before edit: expected 1 residual risk, got %d", len(verdictBefore.ResidualRisk))
	}
	if len(verdictBefore.BlockingFindings) != 0 {
		t.Fatalf("before edit: expected 0 blocking findings, got %d", len(verdictBefore.BlockingFindings))
	}

	// Now insert 5 unrelated lines above the finding -> finding moves to line 15
	startLine15 := 15
	fAfter := evidence.Finding{
		Tool:               "gitleaks",
		ToolVersion:        "v8.30.1",
		RuleID:             ruleID,
		NativeSeverity:     "CRITICAL",
		NormalizedSeverity: evidence.SeverityCritical,
		Locations: []evidence.Location{
			{URI: filePath, StartLine: &startLine15, Snippet: snippet},
		},
		Scope:       evidence.FindingScope{Commit: "HEAD", Path: filePath},
		SnippetHash: "stripe-token-hash-12345", // snippet hash is invariant
		Message:     "Stripe Access Token detected",
		Evidence:    evidence.FindingEvidence{Snippet: snippet},
	}
	fAfter.ID = correlate.Fingerprint(fAfter)
	fAfter.Fingerprint = fAfter.ID

	// The fingerprint must not have changed
	if fBefore.ID != fAfter.ID {
		t.Fatalf("fingerprint changed after line shift: %s != %s", fBefore.ID, fAfter.ID)
	}

	repAfter := evidence.Report{
		Runs: []evidence.RunOutcome{
			{
				Tool:     "gitleaks",
				Status:   evidence.StatusOK,
				Findings: []evidence.Finding{fAfter},
			},
		},
	}
	correlate.CorrelateReport(&repAfter)

	// Evaluate policy after edit: MUST STILL be cleared with residual risk!
	verdictAfter := policy.Evaluate(cfg, repAfter)
	if verdictAfter.Outcome != evidence.OutcomeClearedWithResidualRisk {
		t.Fatalf("after edit: accepted risk rule failed to match! Got %s (reason: %s)",
			verdictAfter.Outcome, verdictAfter.Reason)
	}
	if len(verdictAfter.ResidualRisk) != 1 {
		t.Fatalf("after edit: expected 1 residual risk item, got %d", len(verdictAfter.ResidualRisk))
	}
	if len(verdictAfter.BlockingFindings) != 0 {
		t.Fatalf("after edit: finding un-suppressed! Blocking findings: %v", verdictAfter.BlockingFindings)
	}
}
