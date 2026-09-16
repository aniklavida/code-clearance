// Package evidence defines the normalized, tool-agnostic finding model
// that Code Clearance ingests SARIF into. It is deliberately narrow,
// sized to what was needed to represent real
// gitleaks and osv-scanner output without losing information.
package evidence

// Severity is a normalized severity band. The mapping from tool-native
// severity to this band is adapter-specific (see internal/sarifing) and is
// deliberately narrow so that policy rules can compare across tools.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

// Location points at the file/region a finding concerns. Region fields are
// pointers because some tools (osv-scanner, for manifest-level findings)
// give a whole-file location with no line/column at all — a real observed
// divergence, not a hypothetical one.
type Location struct {
	URI         string
	StartLine   *int
	StartColumn *int
	EndLine     *int
	EndColumn   *int
	Snippet     string
}

// Finding is one normalized result, traceable back to exactly one raw
// SARIF result in exactly one tool run.
type Finding struct {
	// ID is a stable identifier derived deterministically from the
	// fields below (see Fingerprint), so the same underlying finding
	// gets the same ID across repeated runs against unchanged code.
	ID string

	Tool        string // adapter name, e.g. "gitleaks", "osv-scanner"
	ToolVersion string
	RuleID      string
	Message     string

	NativeSeverity     string // exactly what the tool/rule reported, if anything
	NormalizedSeverity Severity

	Locations []Location

	// RawIndex is the index of this result within the raw SARIF run's
	// results array, so raw evidence remains reachable without
	// re-parsing.
	RawIndex int
}

// RunOutcome captures what happened when one adapter was invoked, whether
// or not it produced any findings. A tool that ran cleanly with zero
// findings and a tool that never ran at all must never be confused.
type RunOutcome struct {
	Tool        string
	ToolVersion string
	Command     string
	ExitCode    int
	Duration    string // formatted for readability in the draft report
	Status      RunStatus
	Findings    []Finding
	StderrTail  string // last lines of stderr, for diagnosing a Crashed/TimedOut run
}

type RunStatus string

const (
	StatusOK           RunStatus = "ok"            // ran to completion, exit code within the tool's expected set
	StatusFindings     RunStatus = "ok-findings"   // ran to completion, exit code signals "findings present"
	StatusCrashed      RunStatus = "crashed"       // ran, exited with an unexpected code, or SARIF failed to parse
	StatusTimedOut     RunStatus = "timed-out"     // killed after exceeding its timeout
	StatusNotInstalled RunStatus = "not-installed" // executable missing on PATH
)

// NotAGitRepository is the explicit value used when the target directory
// is not inside a git repository.
const NotAGitRepository = "not-a-git-repository"

// CleanTreeFingerprint is the explicit fingerprint for a clean working tree.
const CleanTreeFingerprint = "clean"

// TargetBinding binds evidence to the repository, commit SHA, and
// working-tree state of the scanned target.
type TargetBinding struct {
	// Repository identifies the target repository (remote URL or normalized root directory name).
	// If the target is not a git repository, it explicitly reports NotAGitRepository.
	Repository string `json:"repository"`

	// Commit is the HEAD commit SHA. If the target is not a git repository,
	// it explicitly reports NotAGitRepository rather than emitting a blank field.
	Commit string `json:"commit"`

	// Dirty indicates whether the working tree had uncommitted modifications.
	Dirty bool `json:"dirty"`

	// Fingerprint distinguishes a clean checkout from a modified working tree.
	// For a clean tree, it is CleanTreeFingerprint ("clean").
	// For a dirty tree, it is a deterministic hash over the uncommitted changes.
	// For a non-git directory, it is NotAGitRepository.
	Fingerprint string `json:"fingerprint"`
}

// Report captures the full clearance scan run, binding all adapter outcomes
// to the target tree state.
type Report struct {
	Target TargetBinding `json:"target"`
	Runs   []RunOutcome  `json:"runs"`
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
