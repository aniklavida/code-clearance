// Package adapters wires the process runner and the SARIF normalizer
// together for the first two tools. This is deliberately not a general
// adapter framework — it is just enough to prove the orchestration ->
// SARIF -> evidence pipeline end to end for the MCP tool call.
package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
)

// DefaultTimeout bounds a single adapter invocation. A configurable
// product would make this configurable per policy profile.
const DefaultTimeout = 20 * time.Second

// Adapter runs one external tool against targetDir and returns a
// normalized RunOutcome. Exit-code interpretation is tool-specific:
// gitleaks and osv-scanner both use "0 = clean, 1 = findings present" but
// a future adapter could differ, so each Adapter owns its own mapping.
type Adapter func(ctx context.Context, targetDir string) evidence.RunOutcome

// Gitleaks runs `gitleaks detect --no-git --report-format sarif` against
// targetDir. Exit code 0 means no leaks; exit code 1 means leaks were
// found (both are a completed run, not a crash); anything else is
// treated as Crashed.
func Gitleaks(ctx context.Context, targetDir string) evidence.RunOutcome {
	reportDir, err := os.MkdirTemp("", "code-clearance-gitleaks-*")
	if err != nil {
		return evidence.RunOutcome{Tool: "gitleaks", ToolVersion: "v8.30.1", Status: evidence.StatusCrashed, StderrTail: "mkdtemp: " + err.Error()}
	}
	defer os.RemoveAll(reportDir)
	sarifPath := reportDir + "/report.sarif"

	res := app.Run(ctx, app.Spec{
		Name:    "gitleaks",
		Command: "gitleaks",
		Args: []string{
			"detect",
			"--no-git",
			"--source", targetDir,
			"--report-format", "sarif",
			"--report-path", sarifPath,
			"--exit-code", "1",
		},
		Dir:     targetDir,
		Timeout: DefaultTimeout,
	})
	return finishFromSarifFile("gitleaks", "v8.30.1", sarifPath, res, normalize.GitleaksSeverity, map[int]bool{0: true, 1: true})
}

// OSVScanner runs `osv-scanner scan source --format sarif -L <lockfile>`.
// Exit code 0 means no vulnerabilities; exit code 1 means vulnerabilities
// were found; anything else is treated as Crashed.
func OSVScanner(ctx context.Context, lockfilePath string) evidence.RunOutcome {
	res := app.Run(ctx, app.Spec{
		Name:    "osv-scanner",
		Command: "osv-scanner",
		Args: []string{
			"scan", "source",
			"--format", "sarif",
			"-L", lockfilePath,
		},
		Timeout: DefaultTimeout,
	})

	outcome := evidence.RunOutcome{
		Tool:        "osv-scanner",
		ToolVersion: "v2.5.1",
		Command:     "osv-scanner scan source --format sarif -L " + lockfilePath,
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
	outcome.Findings = normalize.Normalize("osv-scanner", "v2.5.1", log, normalize.OSVScannerSeverity)
	if res.ExitCode == 0 {
		outcome.Status = evidence.StatusOK
	} else {
		outcome.Status = evidence.StatusFindings
	}
	return outcome
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

// DefaultScanners returns the default adapter suite wired for clearance.
func DefaultScanners() []app.ScannerAdapter {
	return []app.ScannerAdapter{
		func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			return []evidence.RunOutcome{Gitleaks(ctx, targetDir)}
		},
		func(ctx context.Context, targetDir string) []evidence.RunOutcome {
			lockfile := filepath.Join(targetDir, "package-lock.json")
			if _, err := os.Stat(lockfile); err != nil {
				return nil
			}
			return []evidence.RunOutcome{OSVScanner(ctx, lockfile)}
		},
	}
}

func init() {
	for _, a := range DefaultScanners() {
		app.RegisterDefaultAdapter(a)
	}
}
