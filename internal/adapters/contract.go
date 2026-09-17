package adapters

import (
	"context"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Capability identifies the security analysis domain an adapter operates in.
type Capability string

const (
	CapabilitySecrets      Capability = "secrets"
	CapabilityDependencies Capability = "dependencies"
	CapabilitySAST         Capability = "sast"
	CapabilityContainer    Capability = "container"
	CapabilityPosture      Capability = "posture"
)

// InputScope defines what target entity an adapter expects as input.
type InputScope string

const (
	ScopeRepository InputScope = "repository" // whole repository or directory
	ScopeLockfile   InputScope = "lockfile"   // dependency manifest / lockfile
	ScopeDiff       InputScope = "diff"       // git diff or changed files
	ScopeFile       InputScope = "file"       // specific source files
)

// Availability represents whether an adapter can run in the current environment.
// Availability is a required field/declaration, not an optional one.
type Availability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	Path      string `json:"path,omitempty"`
}

// ExitSemantics defines how process exit codes map to clearance run outcomes.
type ExitSemantics struct {
	SuccessExitCodes  []int `json:"success_exit_codes"`
	FindingsExitCodes []int `json:"findings_exit_codes"`
}

// Descriptor summarizes the declared metadata of an adapter.
type Descriptor struct {
	Name          string        `json:"name"`
	Capability    Capability    `json:"capability"`
	Availability  Availability  `json:"availability"`
	Version       string        `json:"version"`
	InputScope    InputScope    `json:"input_scope"`
	Command       []string      `json:"command"`
	ExitSemantics ExitSemantics `json:"exit_semantics"`
}

// Adapter defines the contract all scanner and command adapters must implement.
// Each adapter declares its capability, availability, version, input scope,
// command invocation, exit semantics, raw output, and normalized findings.
type Adapter interface {
	// Name returns the unique identifier for the adapter.
	Name() string

	// Capability declares what analysis domain the adapter serves.
	Capability() Capability

	// Availability checks and declares whether the tool is runnable on this system.
	// Availability is a required field, not an optional one.
	Availability(ctx context.Context) Availability

	// Version returns the version of the underlying tool or adapter.
	Version() string

	// InputScope returns the required target scope for this adapter.
	InputScope() InputScope

	// Command returns the command and arguments for the given target.
	Command(target string) []string

	// ExitSemantics returns how exit codes should be interpreted.
	ExitSemantics() ExitSemantics

	// Descriptor returns the full declaration metadata for this adapter.
	Descriptor(ctx context.Context, target string) Descriptor

	// Run executes the adapter against target and returns a normalized RunOutcome
	// containing both raw output metadata and normalized findings.
	Run(ctx context.Context, target string) evidence.RunOutcome
}
