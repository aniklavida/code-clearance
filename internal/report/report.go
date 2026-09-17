// Package report renders Code Clearance evidence.Report values as either
// human-readable terminal output or machine-readable JSON, and validates
// JSON reports against the versioned report schema.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/schema"
)

const maxCommandDisplay = 80

// WriteTerminal writes a human-readable clearance report to w.
//
// The output shows, in order:
//  1. Header: repository, commit, dirty state, fingerprint
//  2. Scope: scope name and files checked
//  3. Tools: each run's name, version, status, duration, exit code
//  4. Findings: all findings with severity, rule, message, location
//  5. Uncovered: separate labeled sections for skipped, crashed, timed-out
//     and unavailable checks — only non-empty sections appear
//  6. Coverage: adapters that ran
//  7. Residual risk items if any
//  8. Outcome and reason
func WriteTerminal(r evidence.Report, w io.Writer) error {
	sep := strings.Repeat("─", 60)

	// 1. Header
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, "Code Clearance Report")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "Repository:  %s\n", r.Target.Repository)
	fmt.Fprintf(w, "Commit:      %s\n", r.Target.Commit)
	fmt.Fprintf(w, "Dirty:       %v\n", r.Target.Dirty)
	fmt.Fprintf(w, "Fingerprint: %s\n", r.Target.Fingerprint)
	fmt.Fprintln(w)

	// 2. Scope
	if r.Coverage.Scope != "" || len(r.Coverage.FilesChecked) > 0 {
		fmt.Fprintln(w, "── Scope ──")
		if r.Coverage.Scope != "" {
			fmt.Fprintf(w, "  Scope:         %s\n", r.Coverage.Scope)
		}
		fmt.Fprintf(w, "  Files checked: %d\n", len(r.Coverage.FilesChecked))
		if len(r.Coverage.FilesChecked) > 0 && len(r.Coverage.FilesChecked) <= 20 {
			for _, f := range r.Coverage.FilesChecked {
				fmt.Fprintf(w, "    %s\n", f)
			}
		}
		fmt.Fprintln(w)
	}

	// 3. Tools
	if len(r.Runs) > 0 {
		fmt.Fprintln(w, "── Tools ──")
		for _, run := range r.Runs {
			cmd := run.Command
			if len(cmd) > maxCommandDisplay {
				cmd = cmd[:maxCommandDisplay] + "…"
			}
			fmt.Fprintf(w, "  %-20s  version=%-12s  status=%-14s  exit=%d  duration=%s\n",
				run.Tool, run.ToolVersion, run.Status, run.ExitCode, run.Duration)
			if cmd != "" {
				fmt.Fprintf(w, "    cmd: %s\n", cmd)
			}
		}
		fmt.Fprintln(w)
	}

	// 4. Findings
	fmt.Fprintln(w, "── Findings ──")
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  None.")
	} else {
		for _, f := range r.Findings {
			locStr := ""
			if len(f.Locations) > 0 {
				locStr = f.Locations[0].URI
				if f.Locations[0].StartLine != nil {
					locStr = fmt.Sprintf("%s:%d", locStr, *f.Locations[0].StartLine)
				}
			}
			fmt.Fprintf(w, "  [%s] %s: %s", f.NormalizedSeverity, f.RuleID, f.Message)
			if locStr != "" {
				fmt.Fprintf(w, " (%s)", locStr)
			}
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w)

	// 5. Uncovered checks
	var uncovBuf strings.Builder
	printUncoveredSection := func(label string, checks []evidence.UncoveredCheck) {
		if len(checks) > 0 {
			fmt.Fprintf(&uncovBuf, "  %s:\n", label)
			for _, c := range checks {
				fmt.Fprintf(&uncovBuf, "    %s: %s\n", c.Tool, c.Reason)
			}
		}
	}

	printUncoveredSection("Skipped", r.Uncovered.Skipped)
	printUncoveredSection("Crashed", r.Uncovered.Crashed)
	printUncoveredSection("Timed out", r.Uncovered.TimedOut)
	printUncoveredSection("Unavailable", r.Uncovered.Unavailable)

	if uncovBuf.Len() > 0 {
		fmt.Fprintln(w, "── Uncovered ──")
		fmt.Fprint(w, uncovBuf.String())
		fmt.Fprintln(w)
	}

	// 6. Coverage
	fmt.Fprintln(w, "── Coverage ──")
	if len(r.Coverage.AdaptersRan) == 0 {
		fmt.Fprintln(w, "  Adapters ran: none")
	} else {
		fmt.Fprintf(w, "  Adapters ran: %s\n", strings.Join(r.Coverage.AdaptersRan, ", "))
	}
	if r.Coverage.Summary != "" {
		fmt.Fprintf(w, "  %s\n", r.Coverage.Summary)
	}
	fmt.Fprintln(w)

	// 7. Residual risk
	if len(r.ResidualRisk) > 0 {
		fmt.Fprintln(w, "── Residual Risk ──")
		for _, item := range r.ResidualRisk {
			fmt.Fprintf(w, "  [%s] %s", item.Severity, item.Reason)
			if item.Tool != "" {
				fmt.Fprintf(w, " (tool: %s)", item.Tool)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}

	// 8. Outcome
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "Outcome: %s\n", r.Outcome)
	if r.Reason != "" {
		fmt.Fprintf(w, "Reason:  %s\n", r.Reason)
	}
	fmt.Fprintln(w, sep)

	return nil
}

// WriteJSON marshals the report to indented JSON and writes it to w.
func WriteJSON(r evidence.Report, w io.Writer) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// ValidateJSON validates the JSON bytes against the report schema.
func ValidateJSON(data []byte) error {
	return schema.ValidateReport(data)
}
