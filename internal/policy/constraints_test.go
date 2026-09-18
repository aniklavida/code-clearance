package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/schema"
)

// Constraint 1: An unavailable required adapter must produce Incomplete, never a pass.
// The dishonest alternative must be UNREPRESENTABLE: there must be no field in which
// a missing check can be recorded as having passed.
func TestConstraint1_UnavailableRequiredAdapterMustProduceIncompleteNeverPass(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Adapters.Required = []string{"gitleaks", "osv-scanner"}

	testCases := []struct {
		name   string
		status evidence.RunStatus
	}{
		{"not-installed", evidence.StatusNotInstalled},
		{"unavailable", evidence.StatusUnavailable},
		{"crashed", evidence.StatusCrashed},
		{"timed-out", evidence.StatusTimedOut},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report := evidence.Report{
				SchemaVersion: "v1",
				Target: evidence.TargetBinding{
					Repository:  "https://github.com/example/repo",
					Commit:      "abcdef123456",
					Dirty:       false,
					Fingerprint: "clean",
				},
				Runs: []evidence.RunOutcome{
					{
						Tool:        "gitleaks",
						ToolVersion: "v8.30.1",
						Command:     "gitleaks detect",
						ExitCode:    -1,
						Status:      tc.status,
						Findings:    []evidence.Finding{},
					},
					{
						Tool:        "osv-scanner",
						ToolVersion: "v2.5.1",
						Command:     "osv-scanner scan",
						ExitCode:    0,
						Status:      evidence.StatusOK,
						Findings:    []evidence.Finding{},
					},
				},
			}

			verdict := Evaluate(cfg, report)

			// Invariant: MUST produce OutcomeIncomplete
			if verdict.Outcome != evidence.OutcomeIncomplete {
				t.Fatalf("required adapter with status %q produced outcome %q, want %q",
					tc.status, verdict.Outcome, evidence.OutcomeIncomplete)
			}

			// Invariant: MUST NEVER produce Cleared
			if verdict.Outcome == evidence.OutcomeCleared || verdict.Outcome == evidence.OutcomeClearedWithResidualRisk {
				t.Fatalf("VIOLATION: unavailable required adapter produced passing verdict: %q", verdict.Outcome)
			}
		})
	}

	t.Run("missing-from-runs-entirely", func(t *testing.T) {
		report := evidence.Report{
			SchemaVersion: "v1",
			Target: evidence.TargetBinding{
				Repository:  "https://github.com/example/repo",
				Commit:      "abcdef123456",
				Dirty:       false,
				Fingerprint: "clean",
			},
			// osv-scanner ran cleanly with 0 findings, but required gitleaks never ran
			Runs: []evidence.RunOutcome{
				{
					Tool:        "osv-scanner",
					ToolVersion: "v2.5.1",
					Command:     "osv-scanner scan",
					ExitCode:    0,
					Status:      evidence.StatusOK,
					Findings:    []evidence.Finding{},
				},
			},
		}

		verdict := Evaluate(cfg, report)
		if verdict.Outcome != evidence.OutcomeIncomplete {
			t.Fatalf("missing required adapter produced %q, want %q", verdict.Outcome, evidence.OutcomeIncomplete)
		}
		if verdict.Outcome == evidence.OutcomeCleared {
			t.Fatal("missing required adapter produced OutcomeCleared!")
		}
	})

	t.Run("schema-enforces-unrepresentable-pass-for-unavailable", func(t *testing.T) {
		// Attempting to construct a report with outcome="cleared" while declaring
		// an unavailable check in uncovered.unavailable MUST fail schema validation.
		dishonestJSON := []byte(`{
			"schema_version": "v1",
			"target": {
				"repository": "https://github.com/example/repo",
				"commit": "abcdef123456",
				"dirty": false,
				"fingerprint": "clean"
			},
			"outcome": "cleared",
			"runs": [],
			"findings": [],
			"uncovered": {
				"skipped": [],
				"crashed": [],
				"timed_out": [],
				"unavailable": [
					{
						"tool": "gitleaks",
						"reason": "gitleaks missing on host"
					}
				]
			},
			"coverage": {
				"scope": "quick",
				"files_checked": [],
				"adapters_ran": [],
				"summary": "dishonest report"
			},
			"residual_risk": [],
			"timestamps": {
				"started_at": "2026-09-17T12:00:00Z",
				"completed_at": "2026-09-17T12:01:00Z"
			}
		}`)

		err := schema.ValidateReport(dishonestJSON)
		if err == nil {
			t.Fatal("schema permitted dishonest report: outcome='cleared' with unavailable check present!")
		}
	})
}

// Constraint 2: Normalization must never destroy source evidence.
// Original severity and the raw artifact reference are required fields, not optional ones.
func TestConstraint2_SourceEvidenceMustNeverBeDestroyed(t *testing.T) {
	schemaPath, err := schema.FindSchemaPath("report.schema.json")
	if err != nil {
		t.Fatalf("FindSchemaPath: %v", err)
	}

	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var rawSchema map[string]any
	if err := json.Unmarshal(data, &rawSchema); err != nil {
		t.Fatalf("Unmarshal schema: %v", err)
	}

	defs, ok := rawSchema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema missing $defs")
	}

	findingDef, ok := defs["finding"].(map[string]any)
	if !ok {
		t.Fatal("schema missing finding definition in $defs")
	}

	reqList, ok := findingDef["required"].([]any)
	if !ok {
		t.Fatal("finding definition missing required list")
	}

	hasNativeSeverity := false
	hasRawArtifact := false

	for _, item := range reqList {
		s, _ := item.(string)
		if s == "native_severity" {
			hasNativeSeverity = true
		}
		if s == "raw_artifact" {
			hasRawArtifact = true
		}
	}

	if !hasNativeSeverity {
		t.Fatal("ACCEPTANCE FAILURE: native_severity is not in schemas/report.schema.json required fields")
	}
	if !hasRawArtifact {
		t.Fatal("ACCEPTANCE FAILURE: raw_artifact is not in schemas/report.schema.json required fields")
	}

	// Verify schema rejects a report where a finding omits native_severity
	samplePath := filepath.Join("..", "..", "testdata", "sample-report.json")
	sampleBytes, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}

	var sampleMap map[string]any
	if err := json.Unmarshal(sampleBytes, &sampleMap); err != nil {
		t.Fatalf("unmarshal sample report: %v", err)
	}

	findings := sampleMap["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("sample report has no findings")
	}

	// 1. Test removing native_severity causes validation failure
	finding0 := findings[0].(map[string]any)
	delete(finding0, "native_severity")

	corruptedBytes, _ := json.Marshal(sampleMap)
	if err := schema.ValidateReport(corruptedBytes); err == nil {
		t.Fatal("schema failed to reject finding missing required 'native_severity'!")
	}

	// 2. Test removing raw_artifact causes validation failure
	if err := json.Unmarshal(sampleBytes, &sampleMap); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	finding0 = sampleMap["findings"].([]any)[0].(map[string]any)
	delete(finding0, "raw_artifact")

	corruptedBytes, _ = json.Marshal(sampleMap)
	if err := schema.ValidateReport(corruptedBytes); err == nil {
		t.Fatal("schema failed to reject finding missing required 'raw_artifact'!")
	}
}

// Constraint 3: Identical evidence and configuration must produce an identical outcome.
// Nothing feeding the verdict may depend on a clock or on run ordering.
// TestConstraint3_UncoveredOrderingIsIndependentOfRunOrder covers the case the
// permutation test below cannot reach.
//
// That test permutes run order, but every adapter in its scenario produced a
// result, so `Uncovered` stays empty and there is no order-sensitive field in
// the verdict for the permutation to disturb. Remove *both* order
// normalisations in Evaluate — the input sort over `runs` and `sortUncovered`
// on the way out — and it still passes. It cannot detect run-order dependence.
//
// This one can. Three required adapters produce no results (not installed,
// unavailable, timed out), so the verdict carries three uncovered entries whose
// order follows the order the runs arrived in. With both normalisations removed
// it fails; with either one present it passes, because determinism here is
// protected twice over and no single-point sabotage reveals it.
func TestConstraint3_UncoveredOrderingIsIndependentOfRunOrder(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Adapters.Required = []string{"zeta", "alpha", "mu"}

	target := evidence.TargetBinding{
		Repository: "example/repo",
		Commit:     "0000000000000000000000000000000000000000",
	}
	timestamps := evidence.ReportTimestamps{
		StartedAt:   "2026-01-01T00:00:00Z",
		CompletedAt: "2026-01-01T00:01:00Z",
	}

	zeta := evidence.RunOutcome{Tool: "zeta", ToolVersion: "v1", Command: "zeta", Status: evidence.StatusNotInstalled}
	alpha := evidence.RunOutcome{Tool: "alpha", ToolVersion: "v1", Command: "alpha", Status: evidence.StatusUnavailable}
	mu := evidence.RunOutcome{Tool: "mu", ToolVersion: "v1", Command: "mu", Status: evidence.StatusTimedOut}

	perms := [][]evidence.RunOutcome{
		{zeta, alpha, mu},
		{mu, zeta, alpha},
		{alpha, mu, zeta},
	}

	var first []byte
	for i, runs := range perms {
		rep := evidence.Report{
			SchemaVersion: "v1",
			Target:        target,
			Runs:          runs,
			Timestamps:    timestamps,
		}
		v := Evaluate(cfg, rep)
		if v.Outcome != evidence.OutcomeIncomplete {
			t.Fatalf("permutation %d: required adapters did not run, want %q, got %q",
				i, evidence.OutcomeIncomplete, v.Outcome)
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("permutation %d: marshal: %v", i, err)
		}
		if i == 0 {
			first = b
			continue
		}
		if !bytes.Equal(first, b) {
			t.Fatalf("ACCEPTANCE FAILURE: verdict depends on run order.\npermutation 0: %s\npermutation %d: %s", first, i, b)
		}
	}
}

func TestConstraint3_IdenticalEvidenceAndConfigProducesByteIdenticalVerdicts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.BlockingSeverities = []evidence.Severity{evidence.SeverityCritical, evidence.SeverityHigh}
	cfg.Adapters.Required = []string{"tool-alpha", "tool-beta", "tool-gamma"}
	cfg.Policy.AcceptedRisks = []AcceptedRiskRule{
		{
			FindingID: "f-accepted-1",
			Reason:    "approved risk exception",
			ExpiresAt: "2030-01-01T00:00:00Z",
		},
	}

	f1 := evidence.Finding{
		ID:                 "f-01",
		Tool:               "tool-alpha",
		RuleID:             "rule-alpha-1",
		NativeSeverity:     "HIGH",
		NormalizedSeverity: evidence.SeverityHigh,
		ChallengeStatus:    evidence.ChallengeConfirmed,
	}
	f2 := evidence.Finding{
		ID:                 "f-02",
		Tool:               "tool-beta",
		RuleID:             "rule-beta-1",
		NativeSeverity:     "LOW",
		NormalizedSeverity: evidence.SeverityLow,
		ChallengeStatus:    evidence.ChallengeUnreviewed,
	}
	f3 := evidence.Finding{
		ID:                 "f-accepted-1",
		Tool:               "tool-gamma",
		RuleID:             "rule-gamma-1",
		NativeSeverity:     "CRITICAL",
		NormalizedSeverity: evidence.SeverityCritical,
		ChallengeStatus:    evidence.ChallengeAcceptedRisk,
	}

	runA := evidence.RunOutcome{
		Tool:        "tool-alpha",
		ToolVersion: "v1.0",
		Command:     "tool-alpha --scan",
		ExitCode:    1,
		Status:      evidence.StatusFindings,
		Findings:    []evidence.Finding{f1},
	}
	runB := evidence.RunOutcome{
		Tool:        "tool-beta",
		ToolVersion: "v2.0",
		Command:     "tool-beta --scan",
		ExitCode:    0,
		Status:      evidence.StatusOK,
		Findings:    []evidence.Finding{f2},
	}
	runC := evidence.RunOutcome{
		Tool:        "tool-gamma",
		ToolVersion: "v3.0",
		Command:     "tool-gamma --scan",
		ExitCode:    1,
		Status:      evidence.StatusFindings,
		Findings:    []evidence.Finding{f3},
	}

	target := evidence.TargetBinding{
		Repository:  "https://github.com/example/deterministic-test",
		Commit:      "112233445566",
		Dirty:       false,
		Fingerprint: "clean",
	}

	timestamps := evidence.ReportTimestamps{
		StartedAt:   "2026-09-17T12:00:00Z",
		CompletedAt: "2026-09-17T12:05:00Z",
	}

	// Report 1: order A, B, C; findings f1, f2, f3
	rep1 := evidence.Report{
		SchemaVersion: "v1",
		Target:        target,
		Runs:          []evidence.RunOutcome{runA, runB, runC},
		Findings:      []evidence.Finding{f1, f2, f3},
		Timestamps:    timestamps,
	}

	// Report 2: order C, A, B; findings f3, f1, f2 (scrambled)
	rep2 := evidence.Report{
		SchemaVersion: "v1",
		Target:        target,
		Runs:          []evidence.RunOutcome{runC, runA, runB},
		Findings:      []evidence.Finding{f3, f1, f2},
		Timestamps:    timestamps,
	}

	// Report 3: order B, C, A; findings f2, f3, f1 (another permutation)
	rep3 := evidence.Report{
		SchemaVersion: "v1",
		Target:        target,
		Runs:          []evidence.RunOutcome{runB, runC, runA},
		Findings:      []evidence.Finding{f2, f3, f1},
		Timestamps:    timestamps,
	}

	v1 := Evaluate(cfg, rep1)
	v2 := Evaluate(cfg, rep2)
	v3 := Evaluate(cfg, rep3)

	b1, err1 := json.Marshal(v1)
	b2, err2 := json.Marshal(v2)
	b3, err3 := json.Marshal(v3)

	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("json marshal failed: %v %v %v", err1, err2, err3)
	}

	if !bytes.Equal(b1, b2) {
		t.Fatalf("ACCEPTANCE FAILURE: verdicts differ across run order permutations:\nb1: %s\nb2: %s", b1, b2)
	}

	if !bytes.Equal(b1, b3) {
		t.Fatalf("ACCEPTANCE FAILURE: verdicts differ across run order permutations:\nb1: %s\nb3: %s", b1, b3)
	}
}

// Constraint 4: Human-required classes cannot be cleared by an agent.
func TestConstraint4_HumanRequiredClassesCannotBeClearedByAgent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Adapters.Required = []string{"gitleaks"}
	cfg.Policy.HumanRequiredClasses = []HumanRequiredClass{
		{Tool: "gitleaks", Severity: evidence.SeverityHigh},
	}

	finding := evidence.Finding{
		ID:                 "F1",
		Tool:               "gitleaks",
		NormalizedSeverity: evidence.SeverityHigh,
		ChallengeStatus:    evidence.ChallengeRejected, // Agent tries to clear it
		Reviewer: evidence.Reviewer{
			Type:     evidence.ReviewerAgent,
			Identity: "ai-reviewer",
		},
	}

	rep := evidence.Report{
		Target: evidence.TargetBinding{Dirty: false},
		Runs: []evidence.RunOutcome{
			{Tool: "gitleaks", Status: evidence.StatusOK},
		},
		Findings: []evidence.Finding{finding},
	}

	v := Evaluate(cfg, rep)
	if v.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("expected blocked, got %v", v.Outcome)
	}
	if len(v.BlockingFindings) == 0 || v.BlockingFindings[0] != "F1" {
		t.Fatalf("expected F1 to be blocking")
	}

	// Now a human resolves it
	rep.Findings[0].Reviewer.Type = evidence.ReviewerHuman
	rep.Findings[0].Reviewer.Identity = "alice"

	vHuman := Evaluate(cfg, rep)
	if vHuman.Outcome != evidence.OutcomeCleared {
		t.Fatalf("expected cleared, got %v", vHuman.Outcome)
	}
}
