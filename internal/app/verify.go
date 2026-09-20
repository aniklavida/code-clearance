package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/store"
)

// VerifyArgs configures a targeted rerun to verify remediation of a finding.
type VerifyArgs struct {
	TargetDir      string                   `json:"target_dir" jsonschema:"absolute path to the target repository directory"`
	FindingID      string                   `json:"finding_id,omitempty" jsonschema:"optional finding ID to verify"`
	Fingerprint    string                   `json:"fingerprint,omitempty" jsonschema:"optional finding fingerprint to verify"`
	Patch          *evidence.PatchReference `json:"patch,omitempty" jsonschema:"optional candidate or applied patch reference"`
	PatchDiff      string                   `json:"patch_diff,omitempty" jsonschema:"optional diff of the patch"`
	PatchPath      string                   `json:"patch_path,omitempty" jsonschema:"optional file path of the patch"`
	PatchCommit    string                   `json:"patch_commit,omitempty" jsonschema:"optional commit hash where patch was applied"`
	Approved       bool                     `json:"approved,omitempty" jsonschema:"whether the patch/mutation has host approval"`
	TimeoutSeconds int                      `json:"timeout_seconds,omitempty" jsonschema:"optional timeout override in seconds"`
}

// Verify executes a targeted verification rerun using the default engine.
func Verify(ctx context.Context, args VerifyArgs) (evidence.Report, error) {
	return defaultEngine.Verify(ctx, args)
}

// Verify executes a targeted verification rerun on the engine.
func (e *Engine) Verify(ctx context.Context, args VerifyArgs) (evidence.Report, error) {
	absDir, err := filepath.Abs(args.TargetDir)
	if err != nil {
		absDir = args.TargetDir
	}

	if args.FindingID == "" && args.Fingerprint == "" {
		return evidence.Report{}, errors.New("finding_id or fingerprint is required")
	}

	patchRef := args.Patch
	if patchRef == nil && (args.PatchDiff != "" || args.PatchPath != "" || args.PatchCommit != "") {
		patchRef = &evidence.PatchReference{
			Diff:   args.PatchDiff,
			Path:   args.PatchPath,
			Commit: args.PatchCommit,
		}
	}

	st, err := store.New(filepath.Join(absDir, ".clearance"))
	if err != nil {
		return evidence.Report{}, fmt.Errorf("init store: %w", err)
	}

	var targetFinding evidence.Finding
	var found bool

	// 1. Locate original finding in latest report or via scan
	if latestRep, err := st.GetLatestReport(); err == nil && latestRep != nil {
		for _, f := range latestRep.Findings {
			if matchesFinding(f, args.FindingID, args.Fingerprint) {
				targetFinding = f
				found = true
				break
			}
		}
	}

	if !found {
		initialRep, err := e.ScanWithOptions(ctx, absDir, ScanOptions{Scope: "quick"})
		if err != nil {
			return evidence.Report{}, fmt.Errorf("scan target: %w", err)
		}
		for _, f := range initialRep.Findings {
			if matchesFinding(f, args.FindingID, args.Fingerprint) {
				targetFinding = f
				found = true
				break
			}
		}
	}

	if !found {
		return evidence.Report{}, fmt.Errorf("%w: finding_id=%q fingerprint=%q", ErrFindingNotFound, args.FindingID, args.Fingerprint)
	}

	// 2. Validate patch safety (no destructive fix and no broad mutation without approval)
	if err := ValidatePatchSafety(targetFinding, patchRef, args.Approved); err != nil {
		return evidence.Report{}, err
	}

	// 3. Configure timeout for targeted rerun
	timeout := 30 * time.Second
	if args.TimeoutSeconds > 0 {
		timeout = time.Duration(args.TimeoutSeconds) * time.Second
	}
	vCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runID := store.NewRunID()
	now := time.Now().UTC().Format(time.RFC3339)

	cfg := policy.DefaultConfig()
	cfgPath := filepath.Join(absDir, "clearance.json")
	if loadedCfg, err := policy.Load(cfgPath); err == nil {
		cfg = loadedCfg
	}

	// 4. Run targeted rerun of MINIMUM affected checks
	targetTools := []string{targetFinding.Tool}
	rerunReport, rerunErr := e.ScanWithOptions(vCtx, absDir, ScanOptions{
		Scope:       "quick",
		Config:      &cfg,
		TargetTools: targetTools,
	})

	targetBinding := rerunReport.Target
	if targetBinding.Repository == "" {
		targetBinding = DetectTarget(ctx, absDir)
	}

	// 5. Evaluate execution status: timeout vs failure vs success
	isTimeout := errors.Is(rerunErr, context.DeadlineExceeded) || (vCtx.Err() == context.DeadlineExceeded)
	if !isTimeout {
		for _, r := range rerunReport.Runs {
			if r.Status == evidence.StatusTimedOut {
				isTimeout = true
				break
			}
		}
	}

	isExecutionFailure := rerunErr != nil || len(rerunReport.Runs) == 0
	if !isExecutionFailure {
		for _, r := range rerunReport.Runs {
			if r.Status == evidence.StatusCrashed || r.Status == evidence.StatusUnavailable || r.Status == evidence.StatusNotInstalled {
				isExecutionFailure = true
				break
			}
		}
	}

	// Branch A: Timeout
	if isTimeout {
		vRun := evidence.VerificationRun{
			RunID:     runID,
			Timestamp: now,
			Status:    evidence.StatusTimedOut,
			Outcome:   "incomplete",
		}

		targetFinding.ChallengeStatus = evidence.ChallengeUnresolved
		targetFinding.Disposition = "unresolved"
		targetFinding.FixPatch = patchRef
		targetFinding.VerificationRuns = append(targetFinding.VerificationRuns, vRun)

		runs := rerunReport.Runs
		if len(runs) == 0 {
			runs = []evidence.RunOutcome{
				{
					Tool:        targetFinding.Tool,
					ToolVersion: targetFinding.ToolVersion,
					Status:      evidence.StatusTimedOut,
					StderrTail:  "verification rerun timed out",
				},
			}
		}

		rep := createVerificationReport(targetBinding, runID, evidence.OutcomeIncomplete, "verification rerun timed out", targetFinding, runs)
		saveVerificationRecords(st, targetFinding, rep)
		return rep, nil
	}

	// Branch B: Execution failure (crashed, missing tool, exit error)
	if isExecutionFailure {
		failedStatus := evidence.StatusCrashed
		for _, r := range rerunReport.Runs {
			if r.Status != evidence.StatusOK && r.Status != evidence.StatusFindings {
				failedStatus = r.Status
				break
			}
		}

		vRun := evidence.VerificationRun{
			RunID:     runID,
			Timestamp: now,
			Status:    failedStatus,
			Outcome:   "incomplete",
		}

		targetFinding.ChallengeStatus = evidence.ChallengeUnresolved
		targetFinding.Disposition = "unresolved"
		targetFinding.FixPatch = patchRef
		targetFinding.VerificationRuns = append(targetFinding.VerificationRuns, vRun)

		runs := rerunReport.Runs
		if len(runs) == 0 {
			runs = []evidence.RunOutcome{
				{
					Tool:        targetFinding.Tool,
					ToolVersion: targetFinding.ToolVersion,
					Status:      failedStatus,
					StderrTail:  "verification rerun failed to execute",
				},
			}
		}

		rep := createVerificationReport(targetBinding, runID, evidence.OutcomeIncomplete, "verification rerun failed to execute", targetFinding, runs)
		saveVerificationRecords(st, targetFinding, rep)
		return rep, nil
	}

	// Branch C: Check if finding is still detected
	findingStillPresent := false
	for _, f := range rerunReport.Findings {
		if matchesFinding(f, targetFinding.ID, targetFinding.Fingerprint) {
			findingStillPresent = true
			break
		}
	}

	if findingStillPresent {
		vRun := evidence.VerificationRun{
			RunID:     runID,
			Timestamp: now,
			Status:    evidence.StatusFindings,
			Outcome:   "failed",
		}

		targetFinding.ChallengeStatus = evidence.ChallengeUnresolved
		targetFinding.Disposition = "unresolved"
		targetFinding.FixPatch = patchRef
		targetFinding.VerificationRuns = append(targetFinding.VerificationRuns, vRun)

		rep := createVerificationReport(targetBinding, runID, evidence.OutcomeBlocked, "finding still present after targeted verification rerun", targetFinding, rerunReport.Runs)
		saveVerificationRecords(st, targetFinding, rep)
		return rep, nil
	}

	// Branch D: Finding no longer detected -> FIXED!
	vRun := evidence.VerificationRun{
		RunID:     runID,
		Timestamp: now,
		Status:    evidence.StatusOK,
		Outcome:   "cleared",
	}

	targetFinding.ChallengeStatus = evidence.ChallengeFixed
	targetFinding.Disposition = "fixed"
	targetFinding.FixPatch = patchRef
	targetFinding.VerificationRuns = append(targetFinding.VerificationRuns, vRun)
	targetFinding.Reviewer = evidence.Reviewer{
		Type:     evidence.ReviewerTool,
		Identity: "clearance_verify",
	}
	targetFinding.ChallengeRationale = "verified fixed by targeted rerun"

	rep := createVerificationReport(targetBinding, runID, evidence.OutcomeCleared, "verified fixed by targeted rerun", targetFinding, rerunReport.Runs)
	saveVerificationRecords(st, targetFinding, rep)
	return rep, nil
}

func createVerificationReport(target evidence.TargetBinding, runID string, outcome evidence.ClearanceOutcome, reason string, finding evidence.Finding, runs []evidence.RunOutcome) evidence.Report {
	now := time.Now().UTC().Format(time.RFC3339)
	if finding.Confidence.Level == "" {
		finding.Confidence.Level = evidence.ConfidenceHigh
	}
	if finding.Timestamps.DetectedAt == "" {
		finding.Timestamps.DetectedAt = now
	}
	if finding.DuplicateFindingIDs == nil {
		finding.DuplicateFindingIDs = []string{}
	}
	if finding.RelatedFindingIDs == nil {
		finding.RelatedFindingIDs = []string{}
	}
	if finding.VerificationRuns == nil {
		finding.VerificationRuns = []evidence.VerificationRun{}
	}
	return evidence.Report{
		SchemaVersion: "v1",
		Target:        target,
		Outcome:       outcome,
		Reason:        reason,
		Runs:          runs,
		Findings:      []evidence.Finding{finding},
		Uncovered: evidence.UncoveredChecks{
			Skipped:     []evidence.UncoveredCheck{},
			Crashed:     []evidence.UncoveredCheck{},
			TimedOut:    []evidence.UncoveredCheck{},
			Unavailable: []evidence.UncoveredCheck{},
		},
		Coverage: evidence.CoverageReport{
			Scope:        "quick",
			FilesChecked: []string{},
			AdaptersRan:  []string{finding.Tool},
			Summary:      fmt.Sprintf("Verification rerun (%s): 1 finding verified", finding.Tool),
		},
		ResidualRisk: []evidence.ResidualRiskItem{},
		Timestamps: evidence.ReportTimestamps{
			StartedAt:   now,
			CompletedAt: now,
		},
	}
}

func saveVerificationRecords(st *store.Store, f evidence.Finding, rep evidence.Report) {
	_ = st.SaveReview(f.Fingerprint, store.ReviewRecord{
		ChallengeStatus:  f.ChallengeStatus,
		ReviewerType:     f.Reviewer.Type,
		ReviewerIdentity: f.Reviewer.Identity,
		Reason:           f.ChallengeRationale,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		FixPatch:         f.FixPatch,
		VerificationRuns: f.VerificationRuns,
		Disposition:      f.Disposition,
	})

	session, err := st.CreateRun("")
	if err == nil {
		_ = st.SaveLatestReport(session, rep)
	}
}
