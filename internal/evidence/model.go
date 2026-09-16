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
