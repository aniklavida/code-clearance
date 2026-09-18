package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// EvaluationVerdict captures the deterministic verdict and supporting reasons.
type EvaluationVerdict struct {
	Outcome          evidence.ClearanceOutcome   `json:"outcome"`
	Reason           string                      `json:"reason"`
	BlockingFindings []string                    `json:"blocking_findings"`
	ResidualRisk     []evidence.ResidualRiskItem `json:"residual_risk"`
	Uncovered        evidence.UncoveredChecks    `json:"uncovered"`
}

// Evaluate deterministically computes the ClearanceOutcome and supporting verdict
// details for a given Report against the specified Config.
//
// Invariants enforced:
//  1. An unavailable required adapter produces OutcomeIncomplete, never a pass.
//  2. Evaluation is completely deterministic: neither ordering of runs/findings
//     nor any wall-clock time lookup influences the verdict.
func Evaluate(cfg Config, rep evidence.Report) EvaluationVerdict {
	verdict := EvaluationVerdict{
		BlockingFindings: []string{},
		ResidualRisk:     []evidence.ResidualRiskItem{},
		Uncovered: evidence.UncoveredChecks{
			Skipped:     []evidence.UncoveredCheck{},
			Crashed:     []evidence.UncoveredCheck{},
			TimedOut:    []evidence.UncoveredCheck{},
			Unavailable: []evidence.UncoveredCheck{},
		},
	}

	// 1. Index runs by tool name. If duplicate runs exist for the same tool,
	// sort them deterministically by tool name and command.
	runs := make([]evidence.RunOutcome, len(rep.Runs))
	copy(runs, rep.Runs)
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].Tool != runs[j].Tool {
			return runs[i].Tool < runs[j].Tool
		}
		return runs[i].Command < runs[j].Command
	})

	runByTool := make(map[string]evidence.RunOutcome)
	for _, r := range runs {
		runByTool[r.Tool] = r

		// Categorize non-passing outcomes
		switch r.Status {
		case evidence.StatusSkipped:
			verdict.Uncovered.Skipped = append(verdict.Uncovered.Skipped, evidence.UncoveredCheck{
				Tool:     r.Tool,
				Command:  r.Command,
				Reason:   "check was skipped",
				ExitCode: &r.ExitCode,
			})
		case evidence.StatusCrashed:
			verdict.Uncovered.Crashed = append(verdict.Uncovered.Crashed, evidence.UncoveredCheck{
				Tool:     r.Tool,
				Command:  r.Command,
				Reason:   "scanner crashed or failed to parse",
				ExitCode: &r.ExitCode,
			})
		case evidence.StatusTimedOut:
			verdict.Uncovered.TimedOut = append(verdict.Uncovered.TimedOut, evidence.UncoveredCheck{
				Tool:     r.Tool,
				Command:  r.Command,
				Reason:   "scanner exceeded execution timeout",
				ExitCode: &r.ExitCode,
			})
		case evidence.StatusNotInstalled, evidence.StatusUnavailable:
			reason := "scanner executable missing or unavailable"
			if r.StderrTail != "" {
				reason = r.StderrTail
			}
			verdict.Uncovered.Unavailable = append(verdict.Uncovered.Unavailable, evidence.UncoveredCheck{
				Tool:     r.Tool,
				Command:  r.Command,
				Reason:   reason,
				ExitCode: &r.ExitCode,
			})
		}
	}

	// Also merge any existing uncovered items from report, maintaining sort
	for _, u := range rep.Uncovered.Unavailable {
		verdict.Uncovered.Unavailable = append(verdict.Uncovered.Unavailable, u)
	}
	for _, u := range rep.Uncovered.Crashed {
		verdict.Uncovered.Crashed = append(verdict.Uncovered.Crashed, u)
	}
	for _, u := range rep.Uncovered.TimedOut {
		verdict.Uncovered.TimedOut = append(verdict.Uncovered.TimedOut, u)
	}
	for _, u := range rep.Uncovered.Skipped {
		verdict.Uncovered.Skipped = append(verdict.Uncovered.Skipped, u)
	}

	// 2. Check required adapters.
	// Invariant: An unavailable required adapter must produce Incomplete, never a pass.
	// Check sorted required adapters list for deterministic error messaging.
	reqAdapters := make([]string, len(cfg.Adapters.Required))
	copy(reqAdapters, cfg.Adapters.Required)
	sort.Strings(reqAdapters)

	var missingRequired []string
	var unavailableRequired []string
	var crashedOrTimedOutRequired []string

	for _, reqName := range reqAdapters {
		run, ok := runByTool[reqName]
		if !ok {
			// Adapter was not run at all
			missingRequired = append(missingRequired, reqName)
			continue
		}
		switch run.Status {
		case evidence.StatusNotInstalled, evidence.StatusUnavailable:
			unavailableRequired = append(unavailableRequired, reqName)
		case evidence.StatusCrashed, evidence.StatusTimedOut:
			crashedOrTimedOutRequired = append(crashedOrTimedOutRequired, reqName)
		case evidence.StatusSkipped:
			missingRequired = append(missingRequired, reqName)
		case evidence.StatusOK, evidence.StatusFindings:
			// Ran successfully to completion
		default:
			unavailableRequired = append(unavailableRequired, reqName)
		}
	}

	// Check if any check listed in rep.Uncovered.Unavailable is required
	for _, unavail := range verdict.Uncovered.Unavailable {
		for _, reqName := range reqAdapters {
			if unavail.Tool == reqName {
				found := false
				for _, already := range unavailableRequired {
					if already == reqName {
						found = true
						break
					}
				}
				if !found {
					unavailableRequired = append(unavailableRequired, reqName)
				}
			}
		}
	}

	if len(unavailableRequired) > 0 {
		sort.Strings(unavailableRequired)
		verdict.Outcome = evidence.OutcomeIncomplete
		verdict.Reason = fmt.Sprintf("required adapter(s) unavailable: %s", strings.Join(unavailableRequired, ", "))
		sortUncovered(&verdict.Uncovered)
		return verdict
	}

	if len(missingRequired) > 0 {
		sort.Strings(missingRequired)
		verdict.Outcome = evidence.OutcomeIncomplete
		verdict.Reason = fmt.Sprintf("required adapter(s) did not run: %s", strings.Join(missingRequired, ", "))
		sortUncovered(&verdict.Uncovered)
		return verdict
	}

	if len(crashedOrTimedOutRequired) > 0 {
		sort.Strings(crashedOrTimedOutRequired)
		verdict.Outcome = evidence.OutcomeIncomplete
		verdict.Reason = fmt.Sprintf("required adapter(s) failed execution: %s", strings.Join(crashedOrTimedOutRequired, ", "))
		sortUncovered(&verdict.Uncovered)
		return verdict
	}

	// 3. Working tree check
	if !cfg.Policy.AllowDirty && rep.Target.Dirty {
		verdict.Outcome = evidence.OutcomeBlocked
		verdict.Reason = "working tree has uncommitted modifications and allow_dirty is false"
		sortUncovered(&verdict.Uncovered)
		return verdict
	}

	// 4. Collect and sort all findings across runs and report
	var allFindings []evidence.Finding
	seenFindings := make(map[string]bool)

	if len(rep.Findings) > 0 {
		for _, f := range rep.Findings {
			if !seenFindings[f.ID] {
				seenFindings[f.ID] = true
				allFindings = append(allFindings, f)
			}
		}
	} else {
		for _, r := range runs {
			for _, f := range r.Findings {
				if !seenFindings[f.ID] {
					seenFindings[f.ID] = true
					allFindings = append(allFindings, f)
				}
			}
		}
	}

	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].ID < allFindings[j].ID
	})

	// Index accepted risk rules
	acceptedByFindingID := make(map[string]AcceptedRiskRule)
	acceptedByRuleID := make(map[string]AcceptedRiskRule)
	for _, ar := range cfg.Policy.AcceptedRisks {
		if ar.FindingID != "" {
			acceptedByFindingID[ar.FindingID] = ar
		}
		if ar.RuleID != "" {
			acceptedByRuleID[ar.RuleID] = ar
		}
	}

	// Deterministic reference time for expiry: use completed_at if present, else started_at, else constant
	refTime := rep.Timestamps.CompletedAt
	if refTime == "" {
		refTime = rep.Timestamps.StartedAt
	}
	if refTime == "" {
		refTime = "2026-09-17T00:00:00Z"
	}

	blockingSeverityMap := make(map[evidence.Severity]bool)
	for _, s := range cfg.Policy.BlockingSeverities {
		blockingSeverityMap[s] = true
	}

	for _, f := range allFindings {
		isHumanReq := false
		for _, req := range cfg.Policy.HumanRequiredClasses {
			match := true
			if req.RuleID != "" && req.RuleID != f.RuleID {
				match = false
			}
			if req.Tool != "" && req.Tool != f.Tool {
				match = false
			}
			if req.Severity != "" && req.Severity != f.NormalizedSeverity {
				match = false
			}
			if match {
				isHumanReq = true
				break
			}
		}

		reviewerIsHuman := f.Reviewer.Type == evidence.ReviewerHuman

		hasOverrideStatus := f.ChallengeStatus == evidence.ChallengeRejected || f.ChallengeStatus == evidence.ChallengeAcceptedRisk
		ignoreOverride := isHumanReq && !reviewerIsHuman && hasOverrideStatus

		if !ignoreOverride && (f.ChallengeStatus == evidence.ChallengeRejected || f.ChallengeStatus == evidence.ChallengeFixed) {
			continue
		}

		// Check if finding is accepted
		var acceptedRule *AcceptedRiskRule
		if ar, ok := acceptedByFindingID[f.ID]; ok {
			acceptedRule = &ar
		} else if ar, ok := acceptedByRuleID[f.RuleID]; ok {
			acceptedRule = &ar
		} else {
			// Check if any duplicate or related finding ID was accepted
			for _, dupID := range f.DuplicateFindingIDs {
				if ar, ok := acceptedByFindingID[dupID]; ok {
					acceptedRule = &ar
					break
				}
			}
			if acceptedRule == nil {
				for _, relID := range f.RelatedFindingIDs {
					if ar, ok := acceptedByFindingID[relID]; ok {
						acceptedRule = &ar
						break
					}
				}
			}
		}

		if acceptedRule == nil && f.ChallengeStatus == evidence.ChallengeAcceptedRisk {
			if !ignoreOverride {
				// Finding was flagged as accepted risk without a specific config entry
				rule := AcceptedRiskRule{
					FindingID: f.ID,
					RuleID:    f.RuleID,
					Tool:      f.Tool,
					Reason:    "accepted during review challenge",
					ExpiresAt: "9999-12-31T23:59:59Z",
				}
				if f.Reviewer.Identity != "" {
					rule.Owner = string(f.Reviewer.Type) + ":" + f.Reviewer.Identity
				}
				acceptedRule = &rule
			}
		}

		if acceptedRule != nil {
			// Check expiration deterministically via string comparison for ISO 8601 timestamps
			if acceptedRule.ExpiresAt != "" && acceptedRule.ExpiresAt < refTime {
				// Expired risk acceptance is treated as unaccepted
				if blockingSeverityMap[f.NormalizedSeverity] {
					verdict.BlockingFindings = append(verdict.BlockingFindings, f.ID)
				}
			} else {
				// Valid non-expired risk acceptance
				verdict.ResidualRisk = append(verdict.ResidualRisk, evidence.ResidualRiskItem{
					FindingID:  f.ID,
					RuleID:     f.RuleID,
					Tool:       f.Tool,
					Severity:   f.NormalizedSeverity,
					Reason:     acceptedRule.Reason,
					AcceptedBy: acceptedRule.Owner,
					ExpiresAt:  acceptedRule.ExpiresAt,
				})
			}
			continue
		}

		// Check if severity is blocking
		if blockingSeverityMap[f.NormalizedSeverity] {
			verdict.BlockingFindings = append(verdict.BlockingFindings, f.ID)
		}
	}

	sort.Strings(verdict.BlockingFindings)
	sort.Slice(verdict.ResidualRisk, func(i, j int) bool {
		if verdict.ResidualRisk[i].FindingID != verdict.ResidualRisk[j].FindingID {
			return verdict.ResidualRisk[i].FindingID < verdict.ResidualRisk[j].FindingID
		}
		return verdict.ResidualRisk[i].RuleID < verdict.ResidualRisk[j].RuleID
	})
	sortUncovered(&verdict.Uncovered)

	if len(verdict.BlockingFindings) > 0 {
		verdict.Outcome = evidence.OutcomeBlocked
		verdict.Reason = fmt.Sprintf("%d blocking finding(s) detected: %s",
			len(verdict.BlockingFindings), strings.Join(verdict.BlockingFindings, ", "))
		return verdict
	}

	if len(verdict.ResidualRisk) > 0 {
		verdict.Outcome = evidence.OutcomeClearedWithResidualRisk
		verdict.Reason = fmt.Sprintf("cleared with %d accepted residual risk finding(s)", len(verdict.ResidualRisk))
		return verdict
	}

	verdict.Outcome = evidence.OutcomeCleared
	verdict.Reason = "all required checks passed with zero blocking findings"
	return verdict
}

// ApplyVerdict applies the evaluated outcome to a Report in-place.
func ApplyVerdict(cfg Config, rep *evidence.Report) {
	v := Evaluate(cfg, *rep)
	rep.Outcome = v.Outcome
	// The reason was computed and then discarded, so a report could say
	// "incomplete" without naming the requirement that made it so.
	rep.Reason = v.Reason
	rep.ResidualRisk = v.ResidualRisk
	rep.Uncovered = v.Uncovered
}

func sortUncovered(u *evidence.UncoveredChecks) {
	sort.Slice(u.Skipped, func(i, j int) bool {
		return u.Skipped[i].Tool < u.Skipped[j].Tool
	})
	sort.Slice(u.Crashed, func(i, j int) bool {
		return u.Crashed[i].Tool < u.Crashed[j].Tool
	})
	sort.Slice(u.TimedOut, func(i, j int) bool {
		return u.TimedOut[i].Tool < u.TimedOut[j].Tool
	})
	sort.Slice(u.Unavailable, func(i, j int) bool {
		return u.Unavailable[i].Tool < u.Unavailable[j].Tool
	})
}
