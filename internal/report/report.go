// Package report renders Code Clearance evidence.Report values as either
// human-readable terminal output or machine-readable JSON, and validates
// JSON reports against the versioned report schema.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
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
		if r.Coverage.Profile != "" {
			fmt.Fprintf(w, "  Policy preset:  %s\n", r.Coverage.Profile)
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
			if f.ChallengeStatus != "" && f.ChallengeStatus != evidence.ChallengeUnreviewed {
				fmt.Fprintf(w, "    status: %s\n", f.ChallengeStatus)
			}
			if f.SuppressedByBaseline {
				fmt.Fprintln(w, "    disclosure: suppressed by active baseline")
			}
			if f.FixPatch != nil {
				patchInfo := f.FixPatch.Path
				if patchInfo == "" {
					patchInfo = f.FixPatch.Commit
				}
				if patchInfo == "" && f.FixPatch.Diff != "" {
					patchInfo = "diff"
				}
				if patchInfo != "" {
					fmt.Fprintf(w, "    patch: %s\n", patchInfo)
				}
			}
			for _, vr := range f.VerificationRuns {
				fmt.Fprintf(w, "    verification: %s (%s, %s)\n", vr.RunID, vr.Status, vr.Outcome)
			}
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

	if r.Baseline != nil && r.Baseline.Active {
		fmt.Fprintln(w, "── Baseline ──")
		fmt.Fprintf(w, "  Source:            %s\n", r.Baseline.Source)
		fmt.Fprintf(w, "  Fingerprints:      %d\n", r.Baseline.FingerprintCount)
		fmt.Fprintf(w, "  Suppressed:        %d finding(s) disclosed above\n", r.Baseline.SuppressedCount)
		fmt.Fprintln(w)
	}

	// 7. Residual risk
	if len(r.ResidualRisk) > 0 {
		fmt.Fprintln(w, "── Residual Risk ──")
		for _, item := range r.ResidualRisk {
			fmt.Fprintf(w, "  [%s] %s", item.Severity, item.Reason)
			if item.Tool != "" {
				fmt.Fprintf(w, " (tool: %s)", item.Tool)
			}
			if item.AcceptedBy != "" || item.ExpiresAt != "" {
				fmt.Fprintf(w, " (owner: %s, expires: %s)", item.AcceptedBy, item.ExpiresAt)
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

var htmlTemplate = template.Must(template.New("clearance").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Code Clearance Report</title><style>
:root{color-scheme:light dark;font-family:system-ui,-apple-system,sans-serif;line-height:1.5}body{max-width:1100px;margin:0 auto;padding:2rem;color:#18202a;background:#f7f9fb}main{background:#fff;border:1px solid #d8dee6;border-radius:10px;padding:1.5rem;box-shadow:0 2px 8px #0000000d}h1{margin-top:0}h2{border-bottom:1px solid #d8dee6;padding-bottom:.35rem;margin-top:2rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.75rem}.metric{background:#eef3f8;border-radius:8px;padding:.8rem}.metric strong{display:block;font-size:1.5rem}.blocked{color:#a51d2d}.cleared{color:#176b3a}.incomplete{color:#8a4b00}.risk{border-left:4px solid #d38b00;padding:.6rem .8rem;background:#fff8e6}.finding{border:1px solid #d8dee6;border-radius:8px;padding:.8rem;margin:.65rem 0}code,pre{background:#f0f3f6;padding:.1rem .3rem;border-radius:4px}pre{white-space:pre-wrap;overflow:auto;padding:.7rem}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid #d8dee6;padding:.45rem}@media(prefers-color-scheme:dark){body{color:#e6edf3;background:#0d1117}main{background:#161b22;border-color:#30363d}.metric{background:#21262d}.finding{border-color:#30363d}code,pre{background:#21262d}td,th{border-color:#30363d}}
</style></head><body><main><h1>Code Clearance Report</h1><p class="{{.Outcome}}"><strong>Outcome:</strong> {{.Outcome}}</p>{{if .Reason}}<p>{{.Reason}}</p>{{end}}<section><h2>Coverage</h2><div class="grid"><div class="metric"><strong>{{len .Coverage.FilesChecked}}</strong>files checked</div><div class="metric"><strong>{{len .Runs}}</strong>checks executed</div><div class="metric"><strong>{{len .Findings}}</strong>findings disclosed</div><div class="metric"><strong>{{len .ResidualRisk}}</strong>residual risks</div></div><p>Scope: <strong>{{.Coverage.Scope}}</strong>{{if .Coverage.Profile}}; policy preset: <strong>{{.Coverage.Profile}}</strong>{{end}}</p><p>{{.Coverage.Summary}}</p></section>{{if .Baseline}}<section><h2>Baseline</h2><p>A baseline is active from <code>{{.Baseline.Source}}</code>. It contains {{.Baseline.FingerprintCount}} fingerprint(s) and discloses {{.Baseline.SuppressedCount}} finding(s) in this report. Suppressed findings remain below with their original evidence.</p></section>{{end}}{{if .Provenance}}<section><h2>Provenance</h2><p>Verified: <strong>{{.Provenance.Verified}}</strong>; commit: <code>{{.Provenance.Commit}}</code></p><table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>{{range .Provenance.Checks}}<tr><td>{{.Name}}</td><td>{{.Status}}</td><td>{{.Detail}}</td></tr>{{end}}</table></section>{{end}}<section><h2>Findings and evidence</h2>{{if .Findings}}{{range .Findings}}<article class="finding"><strong>{{.NormalizedSeverity}} · {{.RuleID}}</strong> — {{.Message}}{{if .SuppressedByBaseline}} <em>(suppressed by baseline)</em>{{end}}<p>Fingerprint: <code>{{.Fingerprint}}</code>; status: <code>{{.ChallengeStatus}}</code></p><pre>{{.Evidence.Details}}</pre>{{if .Evidence.Snippet}}<pre>{{.Evidence.Snippet}}</pre>{{end}}</article>{{end}}{{else}}<p>No findings.</p>{{end}}</section><section><h2>Residual risk</h2>{{if .ResidualRisk}}{{range .ResidualRisk}}<div class="risk"><strong>{{.Severity}}</strong> {{.Reason}}<br>Owner: {{.AcceptedBy}}; expires: {{.ExpiresAt}}</div>{{end}}{{else}}<p>No accepted residual risk.</p>{{end}}</section></main></body></html>`))

func WriteHTML(r evidence.Report, w io.Writer) error {
	return htmlTemplate.Execute(w, r)
}
