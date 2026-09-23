package policy

import (
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Required-check audit.
//
// This is the exhaustive companion to the targeted Constraint 1 tests. Rather
// than sampling the statuses we happened to think of, it walks every value the
// run-status enum can hold (plus the empty/unrecognised value and the
// absent-from-runs case) and asserts that none of them converts a required
// check into a pass. The only statuses that may proceed to a non-Incomplete
// outcome are the two that mean "the scanner ran to completion": ok and
// ok-findings. Everything else — skipped, crashed, timed-out, not-installed,
// unavailable, unknown — is Incomplete when the check is required.
func TestAudit_EveryNonPassStatusForARequiredAdapterYieldsIncomplete(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Adapters.Required = []string{"required-tool"}

	cleanTarget := evidence.TargetBinding{
		Repository:  "example/repo",
		Commit:      "0123456789abcdef",
		Dirty:       false,
		Fingerprint: evidence.CleanTreeFingerprint,
	}

	nonPass := map[string]evidence.RunStatus{
		"skipped":        evidence.StatusSkipped,
		"crashed":        evidence.StatusCrashed,
		"timed-out":      evidence.StatusTimedOut,
		"not-installed":  evidence.StatusNotInstalled,
		"unavailable":    evidence.StatusUnavailable,
		"empty-unknown":  evidence.RunStatus(""),
		"future-unknown": evidence.RunStatus("teleported"),
	}

	for name, status := range nonPass {
		t.Run(name, func(t *testing.T) {
			rep := evidence.Report{
				SchemaVersion: "v1",
				Target:        cleanTarget,
				Runs: []evidence.RunOutcome{{
					Tool:        "required-tool",
					ToolVersion: "v1",
					Command:     "required-tool scan",
					ExitCode:    -1,
					Status:      status,
					Findings:    []evidence.Finding{},
				}},
			}

			v := Evaluate(cfg, rep)
			if v.Outcome != evidence.OutcomeIncomplete {
				t.Fatalf("required check with status %q produced %q, want %q", status, v.Outcome, evidence.OutcomeIncomplete)
			}
			if !strings.Contains(v.Reason, "required-tool") {
				t.Fatalf("verdict reason %q does not name the required check", v.Reason)
			}
		})
	}

	t.Run("absent-from-runs", func(t *testing.T) {
		rep := evidence.Report{
			SchemaVersion: "v1",
			Target:        cleanTarget,
			Runs:          []evidence.RunOutcome{},
		}
		v := Evaluate(cfg, rep)
		if v.Outcome != evidence.OutcomeIncomplete {
			t.Fatalf("absent required check produced %q, want %q", v.Outcome, evidence.OutcomeIncomplete)
		}
		if !strings.Contains(v.Reason, "required-tool") {
			t.Fatalf("verdict reason %q does not name the absent required check", v.Reason)
		}
	})
}

// The complementary half of the audit: the two completion statuses do reach a
// verdict, and it is driven by findings and tree state rather than by the
// status being treated as a blanket pass.
func TestAudit_OnlyCompleteExecutionStatusesReachANonIncompleteVerdict(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Adapters.Required = []string{"required-tool"}

	target := evidence.TargetBinding{
		Repository:  "example/repo",
		Commit:      "0123456789abcdef",
		Dirty:       false,
		Fingerprint: evidence.CleanTreeFingerprint,
	}

	okRun := evidence.RunOutcome{
		Tool:        "required-tool",
		ToolVersion: "v1",
		Command:     "required-tool scan",
		Status:      evidence.StatusOK,
		Findings:    []evidence.Finding{},
	}

	v := Evaluate(cfg, evidence.Report{SchemaVersion: "v1", Target: target, Runs: []evidence.RunOutcome{okRun}})
	if v.Outcome != evidence.OutcomeCleared {
		t.Fatalf("completed required check with no blocking findings should be Cleared, got %q", v.Outcome)
	}

	// Findings-present still counts as completed execution, and the verdict is
	// then decided by severity, not by the status.
	lowFinding := evidence.Finding{
		ID:                 "F-LOW",
		Tool:               "required-tool",
		RuleID:             "low-rule",
		NativeSeverity:     "LOW",
		NormalizedSeverity: evidence.SeverityLow,
		ChallengeStatus:    evidence.ChallengeUnreviewed,
	}
	findingsRun := okRun
	findingsRun.Status = evidence.StatusFindings
	findingsRun.Findings = []evidence.Finding{lowFinding}

	v = Evaluate(cfg, evidence.Report{SchemaVersion: "v1", Target: target, Runs: []evidence.RunOutcome{findingsRun}})
	if v.Outcome != evidence.OutcomeCleared {
		t.Fatalf("completed required check with only non-blocking findings should be Cleared, got %q", v.Outcome)
	}

	blockingFinding := lowFinding
	blockingFinding.NormalizedSeverity = evidence.SeverityCritical
	findingsRun.Findings = []evidence.Finding{blockingFinding}
	v = Evaluate(cfg, evidence.Report{SchemaVersion: "v1", Target: target, Runs: []evidence.RunOutcome{findingsRun}})
	if v.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("completed required check with a blocking finding should be Blocked, got %q", v.Outcome)
	}
}
