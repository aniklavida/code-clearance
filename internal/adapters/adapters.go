// Package adapters wires the process runner and the SARIF normalizer
// together for the first two tools. It provides concrete Adapter implementations
// declaring capability, availability, version, input scope, command,
// exit semantics, raw output, and normalized findings.
package adapters

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
)

// DefaultTimeout bounds a single adapter invocation.
const DefaultTimeout = 20 * time.Second

// Ensure GitleaksAdapter and OSVScannerAdapter satisfy the Adapter interface at compile time.
var (
	_ Adapter = (*GitleaksAdapter)(nil)
	_ Adapter = (*OSVScannerAdapter)(nil)
)

// GitleaksAdapter implements Adapter for the Gitleaks secrets scanner.
type GitleaksAdapter struct {
	version string
}

// NewGitleaksAdapter constructs a new Gitleaks adapter instance.
func NewGitleaksAdapter() *GitleaksAdapter {
	return &GitleaksAdapter{version: "v8.30.1"}
}

func (a *GitleaksAdapter) Name() string {
	return "gitleaks"
}

func (a *GitleaksAdapter) Capability() Capability {
	return CapabilitySecrets
}

func (a *GitleaksAdapter) Version() string {
	return a.version
}

func (a *GitleaksAdapter) InputScope() InputScope {
	return ScopeRepository
}

func (a *GitleaksAdapter) ExitSemantics() ExitSemantics {
	return ExitSemantics{
		SuccessExitCodes:  []int{0},
		FindingsExitCodes: []int{1},
	}
}

// Availability checks whether gitleaks is executable on PATH.
// Availability is a required field, not an optional one.
func (a *GitleaksAdapter) Availability(ctx context.Context) Availability {
	path, err := exec.LookPath("gitleaks")
	if err != nil {
		return Availability{
			Available: false,
			Reason:    "gitleaks executable missing on PATH",
		}
	}
	return Availability{
		Available: true,
		Reason:    "gitleaks is installed",
		Path:      path,
	}
}

func (a *GitleaksAdapter) Command(target string) []string {
	return []string{
		"gitleaks",
		"detect",
		"--no-git",
		"--source", target,
		"--report-format", "sarif",
		"--exit-code", "1",
	}
}

func (a *GitleaksAdapter) Descriptor(ctx context.Context, target string) Descriptor {
	return Descriptor{
		Name:          a.Name(),
		Capability:    a.Capability(),
		Availability:  a.Availability(ctx),
		Version:       a.Version(),
		InputScope:    a.InputScope(),
		Command:       a.Command(target),
		ExitSemantics: a.ExitSemantics(),
	}
}

// Run executes Gitleaks against targetDir.
func (a *GitleaksAdapter) Run(ctx context.Context, targetDir string) evidence.RunOutcome {
	avail := a.Availability(ctx)
	cmdStr := strings.Join(a.Command(targetDir), " ")

	if !avail.Available {
		return evidence.RunOutcome{
			Tool:        a.Name(),
			ToolVersion: a.Version(),
			Command:     cmdStr,
			ExitCode:    -1,
			Status:      evidence.StatusNotInstalled,
			StderrTail:  avail.Reason,
		}
	}

	reportDir, err := os.MkdirTemp("", "code-clearance-gitleaks-*")
	if err != nil {
		return evidence.RunOutcome{
			Tool:        a.Name(),
			ToolVersion: a.Version(),
			Command:     cmdStr,
			ExitCode:    -1,
			Status:      evidence.StatusCrashed,
			StderrTail:  "mkdtemp: " + err.Error(),
		}
	}
	defer os.RemoveAll(reportDir)
	sarifPath := filepath.Join(reportDir, "report.sarif")

	args := []string{
		"detect",
		"--no-git",
		"--source", targetDir,
		"--report-format", "sarif",
		"--report-path", sarifPath,
		"--exit-code", "1",
	}

	res := app.Run(ctx, app.Spec{
		Name:    a.Name(),
		Command: "gitleaks",
		Args:    args,
		Dir:     targetDir,
		Timeout: DefaultTimeout,
	})

	outcome := finishFromSarifFile(a.Name(), a.Version(), sarifPath, res, normalize.GitleaksSeverity, map[int]bool{0: true, 1: true})
	outcome.Command = cmdStr
	return outcome
}

// OSVScannerAdapter implements Adapter for the OSV-Scanner dependency scanner.
type OSVScannerAdapter struct {
	version string
}

// NewOSVScannerAdapter constructs a new OSV-Scanner adapter instance.
func NewOSVScannerAdapter() *OSVScannerAdapter {
	return &OSVScannerAdapter{version: "v2.5.1"}
}

func (a *OSVScannerAdapter) Name() string {
	return "osv-scanner"
}

func (a *OSVScannerAdapter) Capability() Capability {
	return CapabilityDependencies
}

func (a *OSVScannerAdapter) Version() string {
	return a.version
}

func (a *OSVScannerAdapter) InputScope() InputScope {
	return ScopeLockfile
}

func (a *OSVScannerAdapter) ExitSemantics() ExitSemantics {
	return ExitSemantics{
		SuccessExitCodes:  []int{0},
		FindingsExitCodes: []int{1},
	}
}

// Availability checks whether osv-scanner is executable on PATH.
// Availability is a required field, not an optional one.
func (a *OSVScannerAdapter) Availability(ctx context.Context) Availability {
	path, err := exec.LookPath("osv-scanner")
	if err != nil {
		return Availability{
			Available: false,
			Reason:    "osv-scanner executable missing on PATH",
		}
	}
	return Availability{
		Available: true,
		Reason:    "osv-scanner is installed",
		Path:      path,
	}
}

func (a *OSVScannerAdapter) Command(target string) []string {
	return []string{
		"osv-scanner",
		"scan",
		"source",
		"--format", "sarif",
		"-L", target,
	}
}

func (a *OSVScannerAdapter) Descriptor(ctx context.Context, target string) Descriptor {
	return Descriptor{
		Name:          a.Name(),
		Capability:    a.Capability(),
		Availability:  a.Availability(ctx),
		Version:       a.Version(),
		InputScope:    a.InputScope(),
		Command:       a.Command(target),
		ExitSemantics: a.ExitSemantics(),
	}
}

// Run executes OSV-Scanner against lockfilePath.
func (a *OSVScannerAdapter) Run(ctx context.Context, lockfilePath string) evidence.RunOutcome {
	avail := a.Availability(ctx)
	cmdStr := strings.Join(a.Command(lockfilePath), " ")

	if !avail.Available {
		return evidence.RunOutcome{
			Tool:        a.Name(),
			ToolVersion: a.Version(),
			Command:     cmdStr,
			ExitCode:    -1,
			Status:      evidence.StatusNotInstalled,
			StderrTail:  avail.Reason,
		}
	}

	res := app.Run(ctx, app.Spec{
		Name:    a.Name(),
		Command: "osv-scanner",
		Args: []string{
			"scan", "source",
			"--format", "sarif",
			"-L", lockfilePath,
		},
		Timeout: DefaultTimeout,
	})

	outcome := evidence.RunOutcome{
		Tool:        a.Name(),
		ToolVersion: a.Version(),
		Command:     cmdStr,
		ExitCode:    res.ExitCode,
		Duration:    res.Duration.String(),
		StderrTail:  tail(res.Stderr, 10),
	}

	switch {
	case res.Err != nil:
		outcome.Status = evidence.StatusNotInstalled
		return outcome
	case res.TimedOut:
		outcome.Status = evidence.StatusTimedOut
		return outcome
	case res.ExitCode != 0 && res.ExitCode != 1:
		outcome.Status = evidence.StatusCrashed
		return outcome
	}

	log, err := normalize.Parse(res.Stdout)
	if err != nil {
		outcome.Status = evidence.StatusCrashed
		outcome.StderrTail = outcome.StderrTail + "\nsarif parse error: " + err.Error()
		return outcome
	}

	outcome.Findings = normalize.Normalize(a.Name(), a.Version(), log, normalize.OSVScannerSeverity)
	outcome.RawArtifact = &evidence.ArtifactReference{
		URI:    fmt.Sprintf("sarif://%s/stdout", a.Name()),
		Format: "sarif",
		Index:  0,
	}

	if res.ExitCode == 0 {
		outcome.Status = evidence.StatusOK
	} else {
		outcome.Status = evidence.StatusFindings
	}
	return outcome
}

// Gitleaks runs the Gitleaks adapter against targetDir.
func Gitleaks(ctx context.Context, targetDir string) evidence.RunOutcome {
	return NewGitleaksAdapter().Run(ctx, targetDir)
}

// OSVScanner runs the OSV-Scanner adapter against lockfilePath.
func OSVScanner(ctx context.Context, lockfilePath string) evidence.RunOutcome {
	return NewOSVScannerAdapter().Run(ctx, lockfilePath)
}

func finishFromSarifFile(tool, version, sarifPath string, res app.Result, sev normalize.SeverityRule, okExit map[int]bool) evidence.RunOutcome {
	outcome := evidence.RunOutcome{
		Tool:        tool,
		ToolVersion: version,
		Command:     tool + " detect --no-git --report-format sarif",
		ExitCode:    res.ExitCode,
		Duration:    res.Duration.String(),
		StderrTail:  tail(res.Stderr, 10),
	}

	switch {
	case res.Err != nil:
		outcome.Status = evidence.StatusNotInstalled
		return outcome
	case res.TimedOut:
		outcome.Status = evidence.StatusTimedOut
		return outcome
	case !okExit[res.ExitCode]:
		outcome.Status = evidence.StatusCrashed
		return outcome
	}

	data, err := readFile(sarifPath)
	if err != nil {
		outcome.Status = evidence.StatusCrashed
		outcome.StderrTail = outcome.StderrTail + "\nsarif read error: " + err.Error()
		return outcome
	}
	log, err := normalize.Parse(data)
	if err != nil {
		outcome.Status = evidence.StatusCrashed
		outcome.StderrTail = outcome.StderrTail + "\nsarif parse error: " + err.Error()
		return outcome
	}
	outcome.Findings = normalize.Normalize(tool, version, log, sev)
	outcome.RawArtifact = &evidence.ArtifactReference{
		URI:    sarifPath,
		Format: "sarif",
		Index:  0,
	}

	if res.ExitCode == 0 {
		outcome.Status = evidence.StatusOK
	} else {
		outcome.Status = evidence.StatusFindings
	}
	return outcome
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func tail(b []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// DefaultAdapters returns the full suite of default concrete adapters.
func DefaultAdapters() []Adapter {
	return []Adapter{
		NewGitleaksAdapter(),
		NewOSVScannerAdapter(),
	}
}

// DefaultScanners returns the default adapter suite wired for clearance.
func DefaultScanners() []app.ScannerAdapter {
	g := NewGitleaksAdapter()
	o := NewOSVScannerAdapter()
	return []app.ScannerAdapter{
		func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			return []evidence.RunOutcome{g.Run(ctx, targetDir)}
		},
		func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			lockfile := filepath.Join(targetDir, "package-lock.json")
			if _, err := os.Stat(lockfile); err != nil {
				return nil
			}
			return []evidence.RunOutcome{o.Run(ctx, lockfile)}
		},
	}
}

func init() {
	for _, a := range DefaultScanners() {
		app.RegisterDefaultAdapter(a)
	}
}
