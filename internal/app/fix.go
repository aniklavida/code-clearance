package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/store"
)

var (
	ErrFindingNotFound            = errors.New("finding not found")
	ErrAutomaticMutationForbidden = errors.New("automatic mutation without approval is forbidden: host approval is required for all material code changes")
	ErrDestructiveFixForbidden    = errors.New("destructive fix rejected without approval")
	ErrBroadMutationForbidden     = errors.New("broad mutation rejected without approval: patch modifies files outside finding location scope")
)

// FixContextArgs identifies the target repository and the specific finding
// for which remediation context is requested.
type FixContextArgs struct {
	TargetDir   string `json:"target_dir"`
	FindingID   string `json:"finding_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// FixContext provides the exact evidence, location, remediation advice, and constraints
// an agent needs to prepare a targeted fix for one finding, and nothing beyond that.
type FixContext struct {
	FindingID          string                   `json:"finding_id"`
	Fingerprint        string                   `json:"fingerprint"`
	Tool               string                   `json:"tool"`
	ToolVersion        string                   `json:"tool_version,omitempty"`
	RuleID             string                   `json:"rule_id"`
	Message            string                   `json:"message"`
	NormalizedSeverity evidence.Severity        `json:"normalized_severity"`
	NativeSeverity     string                   `json:"native_severity,omitempty"`
	Locations          []evidence.Location      `json:"locations"`
	Scope              evidence.FindingScope    `json:"scope"`
	Evidence           evidence.FindingEvidence `json:"evidence"`
	Remediation        evidence.Remediation     `json:"remediation"`
	ChallengeStatus    evidence.ChallengeStatus `json:"challenge_status"`
	HumanRequired      bool                     `json:"human_required"`
	AffectedChecks     []string                 `json:"affected_checks"`
	Constraints        []string                 `json:"constraints"`
}

// GetFixContext returns the evidence and constraints an agent needs to prepare a patch
// for one finding, and nothing beyond that. Not the whole report, not unrelated findings.
func GetFixContext(ctx context.Context, args FixContextArgs) (*FixContext, error) {
	if args.FindingID == "" && args.Fingerprint == "" {
		return nil, errors.New("finding_id or fingerprint is required")
	}

	absDir, err := filepath.Abs(args.TargetDir)
	if err != nil {
		absDir = args.TargetDir
	}

	var foundFinding *evidence.Finding
	var report evidence.Report

	// 1. Check latest persisted report in store
	st, stErr := store.New(filepath.Join(absDir, ".clearance"))
	if stErr == nil {
		if rep, rErr := st.GetLatestReport(); rErr == nil && rep != nil {
			report = *rep
			for _, f := range rep.Findings {
				if matchesFinding(f, args.FindingID, args.Fingerprint) {
					found := f
					foundFinding = &found
					break
				}
			}
		}
	}

	// 2. Fall back to current scan if not found in latest report
	if foundFinding == nil {
		scanRep, scanErr := ScanWithOptions(ctx, absDir, ScanOptions{Scope: "quick"})
		if scanErr != nil {
			return nil, fmt.Errorf("scan target directory: %w", scanErr)
		}
		report = scanRep
		for _, f := range scanRep.Findings {
			if matchesFinding(f, args.FindingID, args.Fingerprint) {
				found := f
				foundFinding = &found
				break
			}
		}
	}

	if foundFinding == nil {
		return nil, fmt.Errorf("%w: finding_id=%q fingerprint=%q", ErrFindingNotFound, args.FindingID, args.Fingerprint)
	}

	// 3. Resolve human-required class constraints
	cfg := policy.DefaultConfig()
	cfgPath := filepath.Join(absDir, "clearance.json")
	if loadedCfg, err := policy.Load(cfgPath); err == nil {
		cfg = loadedCfg
	}
	prof := cfg.ActiveProfile(report.Coverage.Scope)

	isHumanReq := false
	for _, req := range prof.Policy.HumanRequiredClasses {
		match := true
		if req.RuleID != "" && req.RuleID != foundFinding.RuleID {
			match = false
		}
		if req.Tool != "" && req.Tool != foundFinding.Tool {
			match = false
		}
		if req.Severity != "" && req.Severity != foundFinding.NormalizedSeverity {
			match = false
		}
		if match {
			isHumanReq = true
			break
		}
	}

	// 4. Assemble actionable constraints
	var constraints []string
	constraints = append(constraints, "Host approval required before applying code changes; Code Clearance does not mutate code on its own authority.")
	constraints = append(constraints, "No destructive fix and no broad mutation: do not touch files outside finding location scope without explicit approval.")
	constraints = append(constraints, "Verification required: finding only becomes fixed through a recorded verification run (clearance_verify).")
	if isHumanReq {
		constraints = append(constraints, "Human approval required: finding belongs to a human-required policy class and cannot be cleared by an agent alone.")
	}

	affectedChecks := report.ToolsForFinding(foundFinding.ID)
	if len(affectedChecks) == 0 && foundFinding.Tool != "" {
		affectedChecks = []string{foundFinding.Tool}
	}

	return &FixContext{
		FindingID:          foundFinding.ID,
		Fingerprint:        foundFinding.Fingerprint,
		Tool:               foundFinding.Tool,
		ToolVersion:        foundFinding.ToolVersion,
		RuleID:             foundFinding.RuleID,
		Message:            foundFinding.Message,
		NormalizedSeverity: foundFinding.NormalizedSeverity,
		NativeSeverity:     foundFinding.NativeSeverity,
		Locations:          foundFinding.Locations,
		Scope:              foundFinding.Scope,
		Evidence:           foundFinding.Evidence,
		Remediation:        foundFinding.Remediation,
		ChallengeStatus:    foundFinding.ChallengeStatus,
		HumanRequired:      isHumanReq,
		AffectedChecks:     affectedChecks,
		Constraints:        constraints,
	}, nil
}

// ValidatePatchSafety verifies that a proposed or applied patch does not perform
// destructive actions or broad mutations without explicit approval.
func ValidatePatchSafety(finding evidence.Finding, patch *evidence.PatchReference, approved bool) error {
	if patch == nil {
		return nil
	}

	// 1. Destructive fix detection (e.g. file deletion)
	if isDestructivePatch(patch) {
		if !approved {
			return ErrDestructiveFixForbidden
		}
	}

	// 2. Broad mutation detection (modifying files outside the finding's locations)
	if isBroadMutation(finding, patch) {
		if !approved {
			return ErrBroadMutationForbidden
		}
	}

	return nil
}

// EnforceNoAutomaticMutationWithoutApproval ensures that Code Clearance never performs
// material code changes on its own authority.
func EnforceNoAutomaticMutationWithoutApproval(approved bool) error {
	if !approved {
		return ErrAutomaticMutationForbidden
	}
	return nil
}

func isDestructivePatch(patch *evidence.PatchReference) bool {
	if patch.Diff != "" {
		lower := strings.ToLower(patch.Diff)
		if strings.Contains(lower, "deleted file mode") ||
			(strings.Contains(lower, "--- a/") && strings.Contains(lower, "+++ /dev/null")) {
			return true
		}
	}
	return false
}

var diffFileRegex = regexp.MustCompile(`(?m)^(?:---|\+\+\+)\s+[ab]/(.+)$`)

func extractFilesFromDiff(diff string) []string {
	var files []string
	seen := make(map[string]bool)

	matches := diffFileRegex.FindAllStringSubmatch(diff, -1)
	for _, m := range matches {
		if len(m) > 1 {
			f := strings.TrimSpace(m[1])
			if f != "" && f != "dev/null" && !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	return files
}

func isBroadMutation(finding evidence.Finding, patch *evidence.PatchReference) bool {
	if patch.Diff == "" {
		return false
	}
	touchedFiles := extractFilesFromDiff(patch.Diff)
	if len(touchedFiles) == 0 {
		return false
	}

	allowedFiles := make(map[string]bool)
	for _, loc := range finding.Locations {
		if loc.URI != "" {
			cleanURI := filepath.Clean(strings.TrimPrefix(loc.URI, "file://"))
			allowedFiles[cleanURI] = true
			allowedFiles[filepath.Base(cleanURI)] = true
		}
	}
	if finding.Scope.Path != "" {
		cleanScope := filepath.Clean(finding.Scope.Path)
		allowedFiles[cleanScope] = true
		allowedFiles[filepath.Base(cleanScope)] = true
	}

	if len(allowedFiles) == 0 {
		return false
	}

	for _, f := range touchedFiles {
		cleanF := filepath.Clean(f)
		baseF := filepath.Base(cleanF)
		if !allowedFiles[cleanF] && !allowedFiles[baseF] {
			return true
		}
	}

	return false
}

func matchesFinding(f evidence.Finding, targetID, targetFingerprint string) bool {
	if targetID != "" && f.ID == targetID {
		return true
	}
	if targetFingerprint != "" && f.Fingerprint == targetFingerprint {
		return true
	}
	if targetID != "" {
		for _, dup := range f.DuplicateFindingIDs {
			if dup == targetID {
				return true
			}
		}
		for _, rel := range f.RelatedFindingIDs {
			if rel == targetID {
				return true
			}
		}
	}
	return false
}

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
