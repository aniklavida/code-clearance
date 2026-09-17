// Package evidence defines the normalized, tool-agnostic finding model
// that Code Clearance ingests SARIF and scanner outputs into.
package evidence

import (
	"fmt"
	"sort"
	"strings"
)

// ClearanceOutcome represents the overall policy verdict of a clearance run.
type ClearanceOutcome string

const (
	OutcomeCleared                 ClearanceOutcome = "cleared"
	OutcomeClearedWithResidualRisk ClearanceOutcome = "cleared-with-residual-risk"
	OutcomeBlocked                 ClearanceOutcome = "blocked"
	OutcomeIncomplete              ClearanceOutcome = "incomplete"
)

// Severity is a normalized severity band. The mapping from tool-native
// severity to this band is adapter-specific and is deliberately narrow so
// that policy rules can compare across tools.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

// ChallengeStatus represents the triage disposition of a finding.
type ChallengeStatus string

const (
	ChallengeUnreviewed   ChallengeStatus = "unreviewed"
	ChallengeConfirmed    ChallengeStatus = "confirmed"
	ChallengeRejected     ChallengeStatus = "rejected"
	ChallengeAcceptedRisk ChallengeStatus = "accepted-risk"
	ChallengeFixed        ChallengeStatus = "fixed"
	ChallengeUnresolved   ChallengeStatus = "unresolved"
)

// ReviewerType identifies the type of entity that performed a review.
type ReviewerType string

const (
	ReviewerTool  ReviewerType = "tool"
	ReviewerAgent ReviewerType = "agent"
	ReviewerHuman ReviewerType = "human"
)

// Reviewer identifies the entity that challenged or reviewed a finding.
type Reviewer struct {
	Type     ReviewerType `json:"type"`
	Identity string       `json:"identity"`
}

// ConfidenceLevel captures how confident the adapter or reviewer is in a finding.
type ConfidenceLevel string

const (
	ConfidenceHigh    ConfidenceLevel = "high"
	ConfidenceMedium  ConfidenceLevel = "medium"
	ConfidenceLow     ConfidenceLevel = "low"
	ConfidenceUnknown ConfidenceLevel = "unknown"
)

// Confidence pairs a confidence rating with an explanatory rationale.
type Confidence struct {
	Level     ConfidenceLevel `json:"level"`
	Rationale string          `json:"rationale"`
}

// FindingScope captures the commit and diff context of a finding.
type FindingScope struct {
	Commit   string `json:"commit"`
	DiffBase string `json:"diff_base,omitempty"`
	Path     string `json:"path"`
}

// FindingEvidence captures the concrete snippet, match string, or data proving the issue.
type FindingEvidence struct {
	Details string `json:"details"`
	Snippet string `json:"snippet,omitempty"`
	Match   string `json:"match,omitempty"`
	Context string `json:"context,omitempty"`
}

// Remediation provides actionable guidance to resolve the finding.
type Remediation struct {
	Recommendation   string `json:"recommendation"`
	DocumentationURL string `json:"documentation_url,omitempty"`
}

// ArtifactReference points to the raw scanner output artifact.
type ArtifactReference struct {
	URI    string `json:"uri"`
	Format string `json:"format"`
	Index  int    `json:"index"`
}

// PatchReference tracks candidate or applied remediation patches.
type PatchReference struct {
	Path   string `json:"path,omitempty"`
	Diff   string `json:"diff,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// VerificationRun tracks reruns validating whether a fix succeeded.
type VerificationRun struct {
	RunID     string    `json:"run_id"`
	Timestamp string    `json:"timestamp"`
	Status    RunStatus `json:"status"`
	Outcome   string    `json:"outcome"`
}

// FindingTimestamps records detection and update times.
type FindingTimestamps struct {
	DetectedAt string `json:"detected_at"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// Location points at the file/region a finding concerns. Region fields are
// pointers because some tools (e.g. osv-scanner for manifest-level findings)
// give a whole-file location with no line/column at all.
type Location struct {
	URI         string `json:"uri"`
	StartLine   *int   `json:"start_line,omitempty"`
	StartColumn *int   `json:"start_column,omitempty"`
	EndLine     *int   `json:"end_line,omitempty"`
	EndColumn   *int   `json:"end_column,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
	SnippetHash string `json:"snippet_hash,omitempty"`
}

// Finding is one normalized result, traceable back to exactly one raw
// scanner result in exactly one tool run.
type Finding struct {
	// ID is a stable identifier derived deterministically.
	ID string `json:"id"`

	// Fingerprint is the invariant content hash of the finding.
	Fingerprint string `json:"fingerprint"`

	// Tool is the adapter name, e.g. "gitleaks", "osv-scanner".
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
	RuleID      string `json:"rule_id"`

	// Command is the tool command invocation that produced this finding.
	Command string `json:"command,omitempty"`

	// NativeSeverity is the original severity as reported by the tool.
	// REQUIRED: Normalization must never destroy source evidence.
	NativeSeverity string `json:"native_severity"`

	// NormalizedSeverity is the normalized band for cross-tool policy comparison.
	NormalizedSeverity Severity `json:"normalized_severity"`

	// Locations records where the finding occurred.
	Locations []Location `json:"locations"`

	// Scope captures commit and path context.
	Scope FindingScope `json:"scope"`

	// SnippetHash is the cryptographic hash over the offending snippet.
	SnippetHash string `json:"snippet_hash"`

	// Message is the primary description of the issue.
	Message string `json:"message"`

	// Evidence contains concrete proof, match text, or context.
	Evidence FindingEvidence `json:"evidence"`

	// Remediation offers guidance on resolving the issue.
	Remediation Remediation `json:"remediation"`

	// Confidence captures confidence level and rationale.
	Confidence Confidence `json:"confidence"`

	// ChallengeStatus tracks triage state.
	ChallengeStatus ChallengeStatus `json:"challenge_status"`

	// Reviewer records the reviewer type and identity.
	Reviewer Reviewer `json:"reviewer"`

	// RelatedFindingIDs links findings related to this one.
	RelatedFindingIDs []string `json:"related_finding_ids"`

	// DuplicateFindingIDs tracks duplicate findings collapsed into this one.
	DuplicateFindingIDs []string `json:"duplicate_finding_ids"`

	// FixPatch references candidate or applied fixes.
	FixPatch *PatchReference `json:"fix_patch,omitempty"`

	// VerificationRuns lists targeted reruns verifying the fix.
	VerificationRuns []VerificationRun `json:"verification_runs"`

	// Disposition is the final resolution state.
	Disposition string `json:"disposition"`

	// Timestamps tracks detection and update times.
	Timestamps FindingTimestamps `json:"timestamps"`

	// RawArtifact references the raw tool output file and index.
	// REQUIRED: Normalization must never destroy source evidence.
	RawArtifact ArtifactReference `json:"raw_artifact"`

	// RawIndex is the index of this result within the raw tool results array.
	RawIndex int `json:"raw_index"`
}

// RunOutcome captures what happened when one adapter was invoked, whether
// or not it produced any findings. A tool that ran cleanly with zero
// findings and a tool that never ran at all must never be confused.
type RunOutcome struct {
	Tool        string             `json:"tool"`
	ToolVersion string             `json:"tool_version"`
	Command     string             `json:"command"`
	ExitCode    int                `json:"exit_code"`
	Duration    string             `json:"duration"`
	Status      RunStatus          `json:"status"`
	Findings    []Finding          `json:"findings"`
	StderrTail  string             `json:"stderr_tail,omitempty"`
	RawArtifact *ArtifactReference `json:"raw_artifact,omitempty"`
}

type RunStatus string

const (
	StatusOK           RunStatus = "ok"            // ran to completion, exit code within the tool's expected set
	StatusFindings     RunStatus = "ok-findings"   // ran to completion, exit code signals "findings present"
	StatusCrashed      RunStatus = "crashed"       // ran, exited with an unexpected code, or output failed to parse
	StatusTimedOut     RunStatus = "timed-out"     // killed after exceeding its timeout
	StatusNotInstalled RunStatus = "not-installed" // executable missing on PATH
	StatusSkipped      RunStatus = "skipped"       // check skipped (e.g. inapplicable files)
	StatusUnavailable  RunStatus = "unavailable"   // tool unavailable in environment
)

// NotAGitRepository is the explicit value used when the target directory
// is not inside a git repository.
const NotAGitRepository = "not-a-git-repository"

// CleanTreeFingerprint is the explicit fingerprint for a clean working tree.
const CleanTreeFingerprint = "clean"

// TargetBinding binds evidence to the repository, commit SHA, and
// working-tree state of the scanned target.
type TargetBinding struct {
	Repository  string `json:"repository"`
	Commit      string `json:"commit"`
	Dirty       bool   `json:"dirty"`
	Fingerprint string `json:"fingerprint"`
}

// UncoveredCheck records a check that did not run to completion.
type UncoveredCheck struct {
	Tool     string `json:"tool"`
	Command  string `json:"command,omitempty"`
	Reason   string `json:"reason"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

// UncoveredChecks categorizes checks that were not covered by non-pass category.
type UncoveredChecks struct {
	Skipped     []UncoveredCheck `json:"skipped"`
	Crashed     []UncoveredCheck `json:"crashed"`
	TimedOut    []UncoveredCheck `json:"timed_out"`
	Unavailable []UncoveredCheck `json:"unavailable"`
}

// CoverageReport summarizes the scope and tools that executed.
type CoverageReport struct {
	Scope        string   `json:"scope"`
	FilesChecked []string `json:"files_checked"`
	AdaptersRan  []string `json:"adapters_ran"`
	Summary      string   `json:"summary"`
}

// ResidualRiskItem captures an accepted risk rule or known limitation.
type ResidualRiskItem struct {
	FindingID  string   `json:"finding_id,omitempty"`
	RuleID     string   `json:"rule_id,omitempty"`
	Tool       string   `json:"tool,omitempty"`
	Severity   Severity `json:"severity"`
	Reason     string   `json:"reason"`
	AcceptedBy string   `json:"accepted_by,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
}

// ReportTimestamps tracks start and completion of the overall scan.
type ReportTimestamps struct {
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

// Report captures the full clearance scan run, binding all adapter outcomes
// and findings to the target tree state.
type Report struct {
	SchemaVersion string             `json:"schema_version"`
	Target        TargetBinding      `json:"target"`
	Outcome       ClearanceOutcome   `json:"outcome"`
	Runs          []RunOutcome       `json:"runs"`
	Findings      []Finding          `json:"findings"`
	Uncovered     UncoveredChecks    `json:"uncovered"`
	Coverage      CoverageReport     `json:"coverage"`
	ResidualRisk  []ResidualRiskItem `json:"residual_risk"`
	Timestamps    ReportTimestamps   `json:"timestamps"`
}

// Commit returns the commit SHA of the target, or "not-a-git-repository".
func (r Report) Commit() string {
	return r.Target.Commit
}

// Repository returns the repository identity of the target.
func (r Report) Repository() string {
	return r.Target.Repository
}

// Dirty returns true if the target working tree had uncommitted modifications.
func (r Report) Dirty() bool {
	return r.Target.Dirty
}

// Fingerprint returns the deterministic fingerprint of the working tree.
func (r Report) Fingerprint() string {
	return r.Target.Fingerprint
}

// ToolsForFinding returns all tools that detected or correlated into the finding
// identified by findingID. It checks the top-level report findings as well as
// raw run outcomes, returning a sorted list of unique tool names.
func (r Report) ToolsForFinding(findingID string) []string {
	seen := make(map[string]bool)
	var tools []string

	addTool := func(tool string) {
		for _, part := range strings.Split(tool, ",") {
			t := strings.TrimSpace(part)
			if t != "" && !seen[t] {
				seen[t] = true
				tools = append(tools, t)
			}
		}
	}

	// 1. Check top-level findings
	for _, f := range r.Findings {
		if f.ID == findingID || containsString(f.DuplicateFindingIDs, findingID) || containsString(f.RelatedFindingIDs, findingID) {
			addTool(f.Tool)
			if f.Reviewer.Identity != "" && f.Reviewer.Type == ReviewerTool {
				addTool(f.Reviewer.Identity)
			}
		}
	}

	// 2. Check run outcomes
	for _, run := range r.Runs {
		for _, f := range run.Findings {
			if f.ID == findingID || containsString(f.DuplicateFindingIDs, findingID) || containsString(f.RelatedFindingIDs, findingID) {
				if run.Tool != "" {
					addTool(run.Tool)
				}
				addTool(f.Tool)
			}
		}
	}

	sort.Strings(tools)
	return tools
}

// SourceRecordsForFinding returns all constituent raw finding records across all runs
// that correspond to the given findingID (either matching its ID, or listed in duplicate/related IDs).
func (r Report) SourceRecordsForFinding(findingID string) []Finding {
	var records []Finding
	seen := make(map[string]bool)

	// Collect matching finding IDs
	targetIDs := map[string]bool{findingID: true}
	for _, f := range r.Findings {
		if f.ID == findingID {
			for _, id := range f.DuplicateFindingIDs {
				targetIDs[id] = true
			}
			for _, id := range f.RelatedFindingIDs {
				targetIDs[id] = true
			}
		}
	}

	for _, run := range r.Runs {
		for _, f := range run.Findings {
			isMatch := targetIDs[f.ID]
			if !isMatch {
				for _, id := range f.DuplicateFindingIDs {
					if targetIDs[id] {
						isMatch = true
						break
					}
				}
			}
			if !isMatch {
				for _, id := range f.RelatedFindingIDs {
					if targetIDs[id] {
						isMatch = true
						break
					}
				}
			}

			if isMatch {
				key := fmt.Sprintf("%s:%s:%d", f.Tool, f.ID, f.RawIndex)
				if !seen[key] {
					seen[key] = true
					records = append(records, f)
				}
			}
		}
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Tool != records[j].Tool {
			return records[i].Tool < records[j].Tool
		}
		return records[i].ID < records[j].ID
	})
	return records
}

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
