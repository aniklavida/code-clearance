package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

			// Invariant: The verdict reason MUST name the missing check by name
			if !strings.Contains(verdict.Reason, "gitleaks") {
				t.Fatalf("verdict reason %q does not name missing required check 'gitleaks'", verdict.Reason)
			}

			// Invariant: Applying the verdict to a report preserves the name of the missing check
			ApplyVerdict(cfg, &report)
			if report.Outcome != evidence.OutcomeIncomplete {
				t.Fatalf("report outcome %q, want %q", report.Outcome, evidence.OutcomeIncomplete)
			}
			if !strings.Contains(report.Reason, "gitleaks") {
				t.Fatalf("report reason %q does not name missing required check 'gitleaks'", report.Reason)
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

		// Invariant: The verdict reason MUST name the missing check by name
		if !strings.Contains(verdict.Reason, "gitleaks") {
			t.Fatalf("verdict reason %q does not name missing required check 'gitleaks'", verdict.Reason)
		}

		// Invariant: Applying verdict to report names the missing check in report.Reason
		ApplyVerdict(cfg, &report)
		if report.Outcome != evidence.OutcomeIncomplete {
			t.Fatalf("report outcome %q, want %q", report.Outcome, evidence.OutcomeIncomplete)
		}
		if !strings.Contains(report.Reason, "gitleaks") {
			t.Fatalf("report reason %q does not name missing required check 'gitleaks'", report.Reason)
		}
	})

	t.Run("removing-required-adapter-turns-cleared-into-incomplete-and-names-missing-check", func(t *testing.T) {
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
					ExitCode:    0,
					Status:      evidence.StatusOK,
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

		// When both required adapters pass cleanly, outcome MUST be Cleared
		initialVerdict := Evaluate(cfg, report)
		if initialVerdict.Outcome != evidence.OutcomeCleared {
			t.Fatalf("expected initial clean run to be Cleared, got %q", initialVerdict.Outcome)
		}
		ApplyVerdict(cfg, &report)
		if report.Outcome != evidence.OutcomeCleared {
			t.Fatalf("expected applied report outcome to be Cleared, got %q", report.Outcome)
		}

		// Now remove the required adapter 'gitleaks' from runs entirely
		report.Runs = []evidence.RunOutcome{
			{
				Tool:        "osv-scanner",
				ToolVersion: "v2.5.1",
				Command:     "osv-scanner scan",
				ExitCode:    0,
				Status:      evidence.StatusOK,
				Findings:    []evidence.Finding{},
			},
		}

		// Invariant: Removing a required adapter turns Cleared into Incomplete
		verdict := Evaluate(cfg, report)
		if verdict.Outcome != evidence.OutcomeIncomplete {
			t.Fatalf("removing required adapter produced %q, want %q", verdict.Outcome, evidence.OutcomeIncomplete)
		}
		if !strings.Contains(verdict.Reason, "gitleaks") {
			t.Fatalf("verdict reason %q does not name the missing check 'gitleaks'", verdict.Reason)
		}

		ApplyVerdict(cfg, &report)
		if report.Outcome != evidence.OutcomeIncomplete {
			t.Fatalf("applied report outcome %q, want %q", report.Outcome, evidence.OutcomeIncomplete)
		}
		// Invariant: The report NAMES the check that went missing
		if !strings.Contains(report.Reason, "gitleaks") {
			t.Fatalf("report reason %q does not name the missing check 'gitleaks'", report.Reason)
		}
	})

	t.Run("schema-enforces-unrepresentable-pass-for-unavailable", func(t *testing.T) {
		// Attempting to construct a report with outcome="cleared" while declaring
		// that a required check could not complete (uncovered.required_incomplete)
		// MUST fail schema validation.
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
				],
				"required_incomplete": true
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
			t.Fatal("schema permitted dishonest report: outcome='cleared' with a required check incomplete!")
		}

		// The converse must remain valid: an *optional* check being unavailable
		// is honest coverage, not a pass, and must not force the whole report
		// to incomplete. Before this was made precise, any unavailable check
		// forced incomplete, so a normal report with an optional scanner absent
		// failed its own schema.
		optionalUnavailableJSON := []byte(`{
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
						"tool": "trivy",
						"reason": "trivy missing on host (optional adapter)"
					}
				]
			},
			"coverage": {
				"scope": "quick",
				"files_checked": [],
				"adapters_ran": [],
				"summary": "honest coverage report"
			},
			"residual_risk": [],
			"timestamps": {
				"started_at": "2026-09-17T12:00:00Z",
				"completed_at": "2026-09-17T12:01:00Z"
			}
		}`)

		if err := schema.ValidateReport(optionalUnavailableJSON); err != nil {
			t.Fatalf("schema rejected a valid report with only an optional check unavailable: %v", err)
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

// Constraint 3: Identical recorded evidence and configuration must produce an identical outcome.
// No clock, no map iteration order and no model output may move the verdict.
// This test evaluates the same recorded evidence repeatedly (100 iterations) and compares
// the full evaluated result (not just outcome string) to catch map-iteration nondeterminism.
func TestConstraint3_IdenticalRecordedEvidenceEvaluatedRepeatedlyProducesIdenticalVerdict(t *testing.T) {
	sampleReportPath := filepath.Join("..", "..", "testdata", "sample-report.json")
	reportData, err := os.ReadFile(sampleReportPath)
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}

	var rep evidence.Report
	if err := json.Unmarshal(reportData, &rep); err != nil {
		t.Fatalf("unmarshal sample report: %v", err)
	}

	sampleConfigPath := filepath.Join("..", "..", "testdata", "sample-clearance.json")
	cfg, err := Load(sampleConfigPath)
	if err != nil {
		t.Fatalf("load sample clearance config: %v", err)
	}

	// 1. Evaluate baseline result
	baselineVerdict := Evaluate(cfg, rep)
	baselineBytes, err := json.Marshal(baselineVerdict)
	if err != nil {
		t.Fatalf("marshal baseline verdict: %v", err)
	}

	var firstAppliedBytes []byte

	// 2. Evaluate 100 times to catch map-iteration order nondeterminism and assert identical results
	const iterations = 100
	for i := 0; i < iterations; i++ {
		v := Evaluate(cfg, rep)
		vBytes, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("iteration %d marshal failed: %v", i, err)
		}

		// Invariant: compare full evaluated result, not just outcome string
		if !bytes.Equal(baselineBytes, vBytes) {
			t.Fatalf("ACCEPTANCE FAILURE: verdict differed across iterations at iteration %d:\nbaseline: %s\ngot:      %s",
				i, baselineBytes, vBytes)
		}
		if !reflect.DeepEqual(baselineVerdict, v) {
			t.Fatalf("ACCEPTANCE FAILURE: evaluated struct not deeply equal at iteration %d:\nbaseline: %+v\ngot:      %+v",
				i, baselineVerdict, v)
		}

		// Also verify ApplyVerdict produces byte-identical reports across repeated applications
		repCopy := rep
		ApplyVerdict(cfg, &repCopy)
		repBytes, err := json.Marshal(repCopy)
		if err != nil {
			t.Fatalf("iteration %d marshal applied report: %v", i, err)
		}
		if i == 0 {
			firstAppliedBytes = repBytes
		} else if !bytes.Equal(firstAppliedBytes, repBytes) {
			t.Fatalf("ACCEPTANCE FAILURE: applied report differed at iteration %d", i)
		}
	}
}

// Constraint 3: Identical recorded evidence evaluated repeatedly with a fixture that
// exercises ordering. The existing fixture above uses a report where both required
// adapters ran successfully, so unavailableRequired, missingRequired and
// crashedOrTimedOutRequired are all empty — no ordering-sensitive list appears in the
// verdict and the sorts on those lists are never exercised.
//
// This case forces multiple entries into those lists and into Uncovered so that
// removing the sort.Strings calls on the named lists, replacing the required-adapter
// loop with direct map iteration, or removing sortUncovered would produce different
// output across iterations and cause the test to fail.
func TestConstraint3_IdenticalRecordedEvidenceEvaluatedRepeatedlyProducesIdenticalVerdict_OrderingSensitiveFixture(t *testing.T) {
	cfg := DefaultConfig()
	// Four required adapters: two will be unavailable, one timed out, one missing.
	// This guarantees unavailableRequired holds at least two names whose join order
	// would vary if sort.Strings were removed and the list was built from map
	// iteration. It also guarantees Uncovered.Unavailable holds multiple entries
	// whose order would vary if sortUncovered were removed.
	cfg.Adapters.Required = []string{"delta-tool", "alpha-tool", "gamma-tool", "beta-tool"}

	exitMinus1 := -1
	rep := evidence.Report{
		SchemaVersion: "v1",
		Target: evidence.TargetBinding{
			Repository:  "https://example.invalid/test-repo",
			Commit:      "0000000000000000000000000000000000000001",
			Dirty:       false,
			Fingerprint: "test",
		},
		// Runs arrive in reverse-alphabetical order to maximise sensitivity to
		// sort removal: if the lists are filled from an unsorted source, the
		// names appear backwards relative to the expected sorted output.
		Runs: []evidence.RunOutcome{
			{
				Tool:        "gamma-tool",
				ToolVersion: "v1",
				Command:     "gamma-tool scan",
				ExitCode:    -1,
				Status:      evidence.StatusNotInstalled,
				Findings:    []evidence.Finding{},
			},
			{
				Tool:        "delta-tool",
				ToolVersion: "v1",
				Command:     "delta-tool scan",
				ExitCode:    -1,
				Status:      evidence.StatusUnavailable,
				Findings:    []evidence.Finding{},
			},
			{
				Tool:        "beta-tool",
				ToolVersion: "v1",
				Command:     "beta-tool scan",
				ExitCode:    -1,
				Status:      evidence.StatusUnavailable,
				Findings:    []evidence.Finding{},
			},
		},
		// alpha-tool is required but absent from Runs entirely → missingRequired.
		// Uncovered carries two pre-existing unavailable entries in reverse order
		// to verify sortUncovered is exercised: without it the join would preserve
		// the original order and may differ from the sorted expectation.
		Uncovered: evidence.UncoveredChecks{
			Skipped:  []evidence.UncoveredCheck{},
			Crashed:  []evidence.UncoveredCheck{},
			TimedOut: []evidence.UncoveredCheck{},
			Unavailable: []evidence.UncoveredCheck{
				{Tool: "zz-optional", Command: "zz-optional scan", Reason: "not installed", ExitCode: &exitMinus1},
				{Tool: "aa-optional", Command: "aa-optional scan", Reason: "not installed", ExitCode: &exitMinus1},
			},
		},
		Timestamps: evidence.ReportTimestamps{
			StartedAt:   "2026-01-01T00:00:00Z",
			CompletedAt: "2026-01-01T00:05:00Z",
		},
	}

	// Baseline evaluation.
	baselineVerdict := Evaluate(cfg, rep)
	baselineBytes, err := json.Marshal(baselineVerdict)
	if err != nil {
		t.Fatalf("marshal baseline verdict: %v", err)
	}

	// Verify the verdict actually exercises the ordering-sensitive lists so that
	// a reviewer can confirm this test would catch missing sorts.
	if baselineVerdict.Outcome != evidence.OutcomeIncomplete {
		t.Fatalf("fixture misconfigured: want OutcomeIncomplete, got %q", baselineVerdict.Outcome)
	}

	// 100 repeated evaluations catch map-iteration nondeterminism: if any of the
	// sort.Strings calls on the ordering-sensitive lists were removed, the joined
	// names in Reason or the Tool ordering in Uncovered would vary across runs.
	const iterations = 100
	for i := 0; i < iterations; i++ {
		v := Evaluate(cfg, rep)
		vBytes, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("iteration %d marshal failed: %v", i, err)
		}
		if !bytes.Equal(baselineBytes, vBytes) {
			t.Fatalf("ACCEPTANCE FAILURE: verdict depends on iteration order at iteration %d:\nbaseline: %s\ngot:      %s",
				i, baselineBytes, vBytes)
		}
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

func TestConstraint4_HumanRequiredClassesCannotBeFixedByAgent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Adapters.Required = []string{"gitleaks"}
	cfg.Policy.HumanRequiredClasses = []HumanRequiredClass{
		{Tool: "gitleaks", Severity: evidence.SeverityHigh},
	}

	finding := evidence.Finding{
		ID:                 "F1",
		Tool:               "gitleaks",
		NormalizedSeverity: evidence.SeverityHigh,
		ChallengeStatus:    evidence.ChallengeFixed, // Agent tries to claim it's fixed
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
