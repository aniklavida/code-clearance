// Package adapters wires the process runner and the SARIF normalizer
// together for the first real adapters. It provides concrete Adapter implementations
// declaring capability, availability, version, input scope, command,
// exit semantics, raw output, and normalized findings.
package adapters

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
)

// DefaultTimeout bounds a single adapter invocation.
const DefaultTimeout = 20 * time.Second

// Ensure all adapters satisfy the Adapter interface at compile time.
var (
	_ Adapter = (*GitleaksAdapter)(nil)
	_ Adapter = (*OSVScannerAdapter)(nil)
	_ Adapter = (*SemgrepAdapter)(nil)
	_ Adapter = (*TrivyAdapter)(nil)
)

// DetectToolVersion queries the tool's binary for its version string and validates it.
func DetectToolVersion(ctx context.Context, tool string) (string, error) {
	if _, err := exec.LookPath(tool); err != nil {
		return "", fmt.Errorf("tool %s: %w", tool, app.ErrNotInstalled)
	}

	var args []string
	switch strings.ToLower(tool) {
	case "gitleaks":
		args = []string{"version"}
	case "osv-scanner":
		args = []string{"--version"}
	case "semgrep", "semgrep-ce":
		args = []string{"--version"}
	case "trivy":
		args = []string{"--version"}
	default:
		return "", fmt.Errorf("tool %s: unsupported tool for version detection", tool)
	}

	res := app.Run(ctx, app.Spec{
		Name:    tool + "-version",
		Command: tool,
		Args:    args,
		Timeout: 5 * time.Second,
	})

	if res.Err != nil {
		return "", fmt.Errorf("tool %s: failed to execute version check: %w", tool, res.Err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("tool %s: version check exited with code %d: %s", tool, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}

	ver, err := parseVersionOutput(tool, string(res.Stdout))
	if err != nil {
		return "", err
	}

	if err := normalize.ValidateToolVersion(tool, ver); err != nil {
		return ver, err
	}

	return ver, nil
}

func parseVersionOutput(tool, output string) (string, error) {
	lines := strings.Split(output, "\n")
	re := regexp.MustCompile(`\b(?:v)?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9.]+)?)\b`)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if tool == "osv-scanner" && !strings.Contains(strings.ToLower(line), "osv-scanner") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			ver := matches[1]
			if !strings.HasPrefix(ver, "v") {
				ver = "v" + ver
			}
			return ver, nil
		}
	}
	return "", fmt.Errorf("tool %s: unable to parse version from output %q", tool, output)
}

// GitleaksAdapter implements Adapter for the Gitleaks secrets scanner.
type GitleaksAdapter struct {
	version           string
	versionOverridden bool
}

// NewGitleaksAdapter constructs a new Gitleaks adapter instance.
func NewGitleaksAdapter() *GitleaksAdapter {
	return &GitleaksAdapter{version: "v8.30.1"}
}

// SetVersion overrides the adapter version (e.g. for testing unsupported versions).
func (a *GitleaksAdapter) SetVersion(v string) {
	a.version = v
	a.versionOverridden = true
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
	if !a.versionOverridden {
		if ver, err := DetectToolVersion(ctx, "gitleaks"); err == nil && ver != "" {
			a.version = ver
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

	if err := normalize.ValidateToolVersion(a.Name(), a.Version()); err != nil {
		return evidence.RunOutcome{
			Tool:        a.Name(),
			ToolVersion: a.Version(),
			Command:     cmdStr,
			ExitCode:    -1,
			Status:      evidence.StatusUnavailable,
			StderrTail:  err.Error(),
		}
	}

	reportFile, err := os.CreateTemp("", "code-clearance-gitleaks-*.sarif")
	if err != nil {
		return evidence.RunOutcome{
			Tool:        a.Name(),
			ToolVersion: a.Version(),
			Command:     cmdStr,
			ExitCode:    -1,
			Status:      evidence.StatusCrashed,
			StderrTail:  "createtemp: " + err.Error(),
		}
	}
	sarifPath := reportFile.Name()
	_ = reportFile.Close()

	// Derive the executed argv from the declared command rather than building
	// a second one by hand. Two consequences of the old arrangement: the
	// no-shell check inspected Command() while something else ran, and the
	// recorded evidence omitted --report-path, so the command in the report
	// was not the command that ran. Evidence that misdescribes itself is the
	// one thing this product cannot ship.
	declared := a.Command(targetDir)
	args := append(append([]string{}, declared[1:]...), "--report-path", sarifPath)

	res := app.Run(ctx, app.Spec{
		Name:    a.Name(),
		Command: declared[0],
		Args:    args,
		Dir:     targetDir,
		Timeout: DefaultTimeout,
	})

	outcome := finishFromSarifFile(a.Name(), a.Version(), sarifPath, res, normalize.GitleaksSeverity, map[int]bool{0: true, 1: true})
	outcome.Command = strings.Join(append([]string{declared[0]}, args...), " ")
	return outcome
}

// OSVScannerAdapter implements Adapter for the OSV-Scanner dependency scanner.
type OSVScannerAdapter struct {
	version           string
	versionOverridden bool
}

// NewOSVScannerAdapter constructs a new OSV-Scanner adapter instance.
func NewOSVScannerAdapter() *OSVScannerAdapter {
	return &OSVScannerAdapter{version: "v2.5.1"}
}

// SetVersion overrides the adapter version (e.g. for testing unsupported versions).
func (a *OSVScannerAdapter) SetVersion(v string) {
	a.version = v
	a.versionOverridden = true
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
	if !a.versionOverridden {
		if ver, err := DetectToolVersion(ctx, "osv-scanner"); err == nil && ver != "" {
			a.version = ver
		}
	}
	return Availability{
		Available: true,
		Reason:    "osv-scanner is installed",
		Path:      path,
	}
}

func (a *OSVScannerAdapter) Command(target string) []string {
	fi, err := os.Stat(target)
	if err == nil && fi.IsDir() {
		return []string{
			"osv-scanner",
			"scan",
			"source",
			"--allow-no-lockfiles",
			"--format", "sarif",
			"-r", target,
		}
	}
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

// Run executes OSV-Scanner against lockfilePath or directory.
func (a *OSVScannerAdapter) Run(ctx context.Context, target string) evidence.RunOutcome {
	avail := a.Availability(ctx)
	cmd := a.Command(target)
	cmdStr := strings.Join(cmd, " ")

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

	if err := normalize.ValidateToolVersion(a.Name(), a.Version()); err != nil {
		return evidence.RunOutcome{
			Tool:        a.Name(),
			ToolVersion: a.Version(),
			Command:     cmdStr,
			ExitCode:    -1,
			Status:      evidence.StatusUnavailable,
			StderrTail:  err.Error(),
		}
	}

	args := cmd[1:]

	res := app.Run(ctx, app.Spec{
		Name:    a.Name(),
		Command: "osv-scanner",
		Args:    args,
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

	rawFile, _ := os.CreateTemp("", "code-clearance-osv-scanner-*.sarif")
	if rawFile != nil {
		_, _ = rawFile.Write(res.Stdout)
		_ = rawFile.Close()
		outcome.RawArtifact = &evidence.ArtifactReference{
			URI:    rawFile.Name(),
			Format: "sarif",
			Index:  0,
		}
	}
	outcome.RawData = res.Stdout

	log, err := normalize.Parse(res.Stdout)
	if err != nil {
		outcome.Status = evidence.StatusUnavailable
		outcome.StderrTail = outcome.StderrTail + "\nsarif parse error: " + err.Error()
		return outcome
	}

	outcome.Findings = normalize.Normalize(a.Name(), a.Version(), log, normalize.OSVScannerSeverity)
	for idx := range outcome.Findings {
		if outcome.RawArtifact != nil {
			outcome.Findings[idx].RawArtifact = *outcome.RawArtifact
			outcome.Findings[idx].RawIndex = idx
		}
		if outcome.Findings[idx].Command == "" {
			outcome.Findings[idx].Command = cmdStr
		}
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

// OSVScanner runs the OSV-Scanner adapter against lockfilePath or directory.
func OSVScanner(ctx context.Context, target string) evidence.RunOutcome {
	return NewOSVScannerAdapter().Run(ctx, target)
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
		outcome.Status = evidence.StatusUnavailable
		outcome.StderrTail = outcome.StderrTail + "\nsarif read error: " + err.Error()
		return outcome
	}
	outcome.RawData = data
	outcome.RawArtifact = &evidence.ArtifactReference{
		URI:    sarifPath,
		Format: "sarif",
		Index:  0,
	}

	log, err := normalize.Parse(data)
	if err != nil {
		outcome.Status = evidence.StatusUnavailable
		outcome.StderrTail = outcome.StderrTail + "\nsarif parse error: " + err.Error()
		return outcome
	}
	outcome.Findings = normalize.Normalize(tool, version, log, sev)
	for idx := range outcome.Findings {
		if outcome.RawArtifact != nil {
			outcome.Findings[idx].RawArtifact = *outcome.RawArtifact
			outcome.Findings[idx].RawIndex = idx
		}
		if outcome.Findings[idx].Command == "" {
			outcome.Findings[idx].Command = outcome.Command
		}
	}

	if res.ExitCode == 0 {
		outcome.Status = evidence.StatusOK
	} else {
		outcome.Status = evidence.StatusFindings
	}
	return outcome
}

// SemgrepAdapter implements Adapter for the Semgrep Community Edition SAST scanner.
type SemgrepAdapter struct {
	version           string
	versionOverridden bool
}

// NewSemgrepAdapter constructs a new Semgrep adapter instance.
func NewSemgrepAdapter() *SemgrepAdapter {
	return &SemgrepAdapter{version: "v1.90.0"}
}

// SetVersion overrides the adapter version (e.g. for testing unsupported versions).
func (a *SemgrepAdapter) SetVersion(v string) {
	a.version = v
	a.versionOverridden = true
}

func (a *SemgrepAdapter) Name() string {
	return "semgrep"
}

func (a *SemgrepAdapter) Capability() Capability {
	return CapabilitySAST
}

func (a *SemgrepAdapter) Version() string {
	return a.version
}

func (a *SemgrepAdapter) InputScope() InputScope {
	return ScopeRepository
}

func (a *SemgrepAdapter) ExitSemantics() ExitSemantics {
	return ExitSemantics{
		SuccessExitCodes:  []int{0},
		FindingsExitCodes: []int{1},
	}
}

func (a *SemgrepAdapter) Availability(ctx context.Context) Availability {
	path, err := exec.LookPath("semgrep")
	if err != nil {
		return Availability{
			Available: false,
			Reason:    "semgrep executable missing on PATH",
		}
	}
	if !a.versionOverridden {
		if ver, err := DetectToolVersion(ctx, "semgrep"); err == nil && ver != "" {
			a.version = ver
		}
	}
	return Availability{
		Available: true,
		Reason:    "semgrep is installed",
		Path:      path,
	}
}

func (a *SemgrepAdapter) Command(target string) []string {
	return []string{
		"semgrep",
		"scan",
		"--json",
		"--quiet",
		target,
	}
}

func (a *SemgrepAdapter) Descriptor(ctx context.Context, target string) Descriptor {
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

func (a *SemgrepAdapter) Run(ctx context.Context, targetDir string) evidence.RunOutcome {
	avail := a.Availability(ctx)
	cmd := a.Command(targetDir)
	cmdStr := strings.Join(cmd, " ")

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

	if err := normalize.ValidateToolVersion(a.Name(), a.Version()); err != nil {
		return evidence.RunOutcome{
			Tool:        a.Name(),
			ToolVersion: a.Version(),
			Command:     cmdStr,
			ExitCode:    -1,
			Status:      evidence.StatusUnavailable,
			StderrTail:  err.Error(),
		}
	}

	args := cmd[1:]

	res := app.Run(ctx, app.Spec{
		Name:    a.Name(),
		Command: "semgrep",
		Args:    args,
		Dir:     targetDir,
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

	rawFile, _ := os.CreateTemp("", "code-clearance-semgrep-*.json")
	if rawFile != nil {
		_, _ = rawFile.Write(res.Stdout)
		_ = rawFile.Close()
		outcome.RawArtifact = &evidence.ArtifactReference{
			URI:    rawFile.Name(),
			Format: "json",
			Index:  0,
		}
	}
	outcome.RawData = res.Stdout

	findings, err := normalize.Ingest(a.Name(), a.Version(), "json", res.Stdout)
	if err != nil {
		outcome.Status = evidence.StatusUnavailable
		outcome.StderrTail = outcome.StderrTail + "\nsemgrep parse error: " + err.Error()
		return outcome
	}

	for idx := range findings {
		if outcome.RawArtifact != nil {
			findings[idx].RawArtifact = *outcome.RawArtifact
			findings[idx].RawIndex = idx
		}
		findings[idx].Command = cmdStr
	}

	outcome.Findings = findings

	if len(findings) > 0 {
		outcome.Status = evidence.StatusFindings
	} else {
		outcome.Status = evidence.StatusOK
	}
	return outcome
}

// TrivyAdapter implements Adapter for the Trivy security scanner.
type TrivyAdapter struct {
	version           string
	versionOverridden bool
}

// NewTrivyAdapter constructs a new Trivy adapter instance.
func NewTrivyAdapter() *TrivyAdapter {
	return &TrivyAdapter{version: "v0.58.0"}
}

// SetVersion overrides the adapter version (e.g. for testing unsupported versions).
func (a *TrivyAdapter) SetVersion(v string) {
	a.version = v
	a.versionOverridden = true
}

func (a *TrivyAdapter) Name() string {
	return "trivy"
}

func (a *TrivyAdapter) Capability() Capability {
	return CapabilityDependencies
}

func (a *TrivyAdapter) Version() string {
	return a.version
}

func (a *TrivyAdapter) InputScope() InputScope {
	return ScopeRepository
}

func (a *TrivyAdapter) ExitSemantics() ExitSemantics {
	return ExitSemantics{
		SuccessExitCodes:  []int{0},
		FindingsExitCodes: []int{1},
	}
}

func (a *TrivyAdapter) Availability(ctx context.Context) Availability {
	path, err := exec.LookPath("trivy")
	if err != nil {
		return Availability{
			Available: false,
			Reason:    "trivy executable missing on PATH",
		}
	}
	if !a.versionOverridden {
		if ver, err := DetectToolVersion(ctx, "trivy"); err == nil && ver != "" {
			a.version = ver
		}
	}
	return Availability{
		Available: true,
		Reason:    "trivy is installed",
		Path:      path,
	}
}

func (a *TrivyAdapter) Command(target string) []string {
	return []string{
		"trivy",
		"fs",
		"-f", "json",
		target,
	}
}

func (a *TrivyAdapter) Descriptor(ctx context.Context, target string) Descriptor {
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

func (a *TrivyAdapter) Run(ctx context.Context, targetDir string) evidence.RunOutcome {
	avail := a.Availability(ctx)
	cmd := a.Command(targetDir)
	cmdStr := strings.Join(cmd, " ")

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

	if err := normalize.ValidateToolVersion(a.Name(), a.Version()); err != nil {
		return evidence.RunOutcome{
			Tool:        a.Name(),
			ToolVersion: a.Version(),
			Command:     cmdStr,
			ExitCode:    -1,
			Status:      evidence.StatusUnavailable,
			StderrTail:  err.Error(),
		}
	}

	args := cmd[1:]

	res := app.Run(ctx, app.Spec{
		Name:    a.Name(),
		Command: "trivy",
		Args:    args,
		Dir:     targetDir,
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

	rawFile, _ := os.CreateTemp("", "code-clearance-trivy-*.json")
	if rawFile != nil {
		_, _ = rawFile.Write(res.Stdout)
		_ = rawFile.Close()
		outcome.RawArtifact = &evidence.ArtifactReference{
			URI:    rawFile.Name(),
			Format: "json",
			Index:  0,
		}
	}
	outcome.RawData = res.Stdout

	findings, err := normalize.Ingest(a.Name(), a.Version(), "json", res.Stdout)
	if err != nil {
		outcome.Status = evidence.StatusUnavailable
		outcome.StderrTail = outcome.StderrTail + "\ntrivy parse error: " + err.Error()
		return outcome
	}

	for idx := range findings {
		if outcome.RawArtifact != nil {
			findings[idx].RawArtifact = *outcome.RawArtifact
			findings[idx].RawIndex = idx
		}
		findings[idx].Command = cmdStr
	}

	outcome.Findings = findings

	if len(findings) > 0 {
		outcome.Status = evidence.StatusFindings
	} else {
		outcome.Status = evidence.StatusOK
	}
	return outcome
}

// Semgrep runs the Semgrep adapter against targetDir.
func Semgrep(ctx context.Context, targetDir string) evidence.RunOutcome {
	return NewSemgrepAdapter().Run(ctx, targetDir)
}

// Trivy runs the Trivy adapter against targetDir.
func Trivy(ctx context.Context, targetDir string) evidence.RunOutcome {
	return NewTrivyAdapter().Run(ctx, targetDir)
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
		NewSemgrepAdapter(),
		NewTrivyAdapter(),
	}
}

// DefaultScanners returns the default adapter suite wired for clearance.
func DefaultScanners() []app.ScannerAdapter {
	g := NewGitleaksAdapter()
	o := NewOSVScannerAdapter()
	s := NewSemgrepAdapter()
	t := NewTrivyAdapter()
	return []app.ScannerAdapter{
		func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			return []evidence.RunOutcome{g.Run(ctx, targetDir)}
		},
		func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			lockfile := filepath.Join(targetDir, "package-lock.json")
			if _, err := os.Stat(lockfile); err == nil {
				return []evidence.RunOutcome{o.Run(ctx, lockfile)}
			}
			return []evidence.RunOutcome{o.Run(ctx, targetDir)}
		},
		// An unavailable scanner still reports. Returning nil here made a
		// missing tool vanish from the report entirely — not recorded as
		// passed, which the schema forbids, but not recorded at all, which
		// is worse: the policy layer turns an unavailable required adapter
		// into Incomplete and never saw one, because absence produced no
		// outcome to see. Gitleaks and OSV-Scanner already behaved this way;
		// these two did not, and the inconsistency was the bug.
		func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			return []evidence.RunOutcome{s.Run(ctx, targetDir)}
		},
		func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			return []evidence.RunOutcome{t.Run(ctx, targetDir)}
		},
	}
}

func init() {
	for _, a := range DefaultScanners() {
		app.RegisterDefaultAdapter(a)
	}
}
