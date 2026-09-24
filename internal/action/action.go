package action

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/normalize"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// Options configures a GitHub Action clearance run.
type Options struct {
	// TargetDir is the checkout to analyse. Required.
	TargetDir string
	// Scope is quick, full or release. Empty defaults to quick.
	Scope string
	// Config overrides the configuration loaded from TargetDir. Tests use it
	// to inject a fixed policy; production leaves it nil so the checkout's own
	// clearance config is honoured.
	Config *policy.Config
	// DiffPath points at a unified diff file (e.g. `gh pr diff` output). When
	// set it is parsed directly and BaseRef is ignored.
	DiffPath string
	// BaseRef and HeadRef let the action compute the diff itself with git.
	BaseRef string
	HeadRef string
	// ChangedOnly restricts annotations to changed lines when a diff exists.
	ChangedOnly bool
	// AllowNetwork mirrors app.ScanOptions.AllowNetwork (default false).
	AllowNetwork bool
}

// Result is the complete output of an Action run.
type Result struct {
	Report      evidence.Report
	Diff        *Diff
	DiffSource  string
	Annotations []Annotation
	Skipped     int
	Summary     string
	SARIF       []byte
	ChangedOnly bool
}

// Run executes the shared clearance core for one checkout and adds the
// CI-specific projections (changed-line annotations and SARIF). When engine is
// nil the shared default engine is used. It performs no network I/O and never
// writes outside TargetDir and the caller-provided output paths.
func Run(ctx context.Context, engine *app.Engine, opts Options) (Result, error) {
	if strings.TrimSpace(opts.TargetDir) == "" {
		return Result{}, fmt.Errorf("action: target directory is required")
	}
	absDir, err := filepath.Abs(opts.TargetDir)
	if err != nil {
		absDir = opts.TargetDir
	}

	scope := strings.ToLower(strings.TrimSpace(opts.Scope))
	if scope == "" {
		scope = "quick"
	}

	cfg := opts.Config
	if cfg == nil {
		loaded, loadErr := app.LoadTargetConfig(absDir)
		if loadErr != nil {
			return Result{}, loadErr
		}
		cfg = loaded
	}

	diff, diffSource, err := resolveDiff(ctx, absDir, opts)
	if err != nil {
		return Result{}, err
	}

	report, err := app.ScanWithEngine(ctx, engine, absDir, app.ScanOptions{
		Scope:        scope,
		BaseCommit:   opts.BaseRef,
		AllowNetwork: opts.AllowNetwork,
		Config:       cfg,
	})
	if err != nil {
		return Result{}, fmt.Errorf("action: scan: %w", err)
	}

	annotations, skipped := BuildAnnotations(report, diff, opts.ChangedOnly)

	sarifLog, err := normalize.Export(report)
	if err != nil {
		return Result{}, fmt.Errorf("action: export SARIF: %w", err)
	}
	sarifBytes, err := json.MarshalIndent(sarifLog, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("action: marshal SARIF: %w", err)
	}

	return Result{
		Report:      report,
		Diff:        diff,
		DiffSource:  diffSource,
		Annotations: annotations,
		Skipped:     skipped,
		Summary:     BuildSummary(report, diff, diffSource, annotations, skipped, opts.ChangedOnly),
		SARIF:       sarifBytes,
		ChangedOnly: opts.ChangedOnly,
	}, nil
}

// resolveDiff obtains the change set the annotations are scoped to. A provided
// diff file wins; otherwise git computes the diff for BaseRef; otherwise no
// diff is available and annotations are not changed-restricted.
func resolveDiff(ctx context.Context, absDir string, opts Options) (*Diff, string, error) {
	if opts.DiffPath != "" {
		data, err := os.ReadFile(opts.DiffPath)
		if err != nil {
			return nil, "", fmt.Errorf("action: read diff %s: %w", opts.DiffPath, err)
		}
		return ParseUnifiedDiff(data), "file:" + opts.DiffPath, nil
	}
	if opts.BaseRef == "" {
		return nil, "none", nil
	}

	head := opts.HeadRef
	if head == "" {
		head = "HEAD"
	}
	rangeSpec := opts.BaseRef + "..." + head
	if head == "HEAD" {
		rangeSpec = opts.BaseRef
	}

	res := app.Run(ctx, app.Spec{
		Name:    "git-diff",
		Command: "git",
		Args:    []string{"diff", "--unified=0", rangeSpec},
		Dir:     absDir,
		Timeout: 30 * time.Second,
	})
	if res.Err != nil || res.ExitCode != 0 {
		return nil, "git:" + rangeSpec, fmt.Errorf("action: git diff %s: %v (exit %d): %s",
			rangeSpec, res.Err, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return ParseUnifiedDiff(res.Stdout), "git:" + rangeSpec, nil
}

// BuildSummary renders the human-readable check summary. It names the scope,
// the tools and versions that ran, the coverage and the residual risk so a
// reviewer sees evidence rather than a bare pass/fail.
func BuildSummary(rep evidence.Report, diff *Diff, diffSource string, annotations []Annotation, skipped int, changedOnly bool) string {
	var b strings.Builder

	title := rep.Outcome
	if title == "" {
		title = "(no outcome)"
	}
	fmt.Fprintf(&b, "## Code Clearance: %s\n\n", title)

	if rep.Reason != "" {
		fmt.Fprintf(&b, "**Reason:** %s\n\n", rep.Reason)
	}

	fmt.Fprintf(&b, "**Scope:** %s — %d file(s) checked\n", rep.Coverage.Scope, len(rep.Coverage.FilesChecked))
	if diffSource != "" {
		fmt.Fprintf(&b, "**Change set:** %s", diffSource)
		if diff != nil {
			fmt.Fprintf(&b, " — %d changed file(s)", len(diff.ChangedFiles()))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "**Commit:** %s (dirty: %v, fingerprint: %s)\n\n",
		rep.Target.Commit, rep.Target.Dirty, rep.Target.Fingerprint)

	b.WriteString("### Tools\n\n")
	if len(rep.Runs) == 0 {
		b.WriteString("_No tools ran._\n\n")
	} else {
		b.WriteString("| Tool | Version | Status | Exit |\n|---|---|---|---|\n")
		for _, run := range sortedRuns(rep.Runs) {
			fmt.Fprintf(&b, "| %s | %s | %s | %d |\n", run.Tool, run.ToolVersion, run.Status, run.ExitCode)
		}
		b.WriteString("\n")
	}

	b.WriteString("### Coverage and residual risk\n\n")
	if len(rep.Coverage.AdaptersRan) == 0 {
		b.WriteString("- Adapters ran: none\n")
	} else {
		fmt.Fprintf(&b, "- Adapters ran: %s\n", strings.Join(rep.Coverage.AdaptersRan, ", "))
	}
	unavailable := uncoveredNames(rep.Uncovered.Unavailable)
	crashed := uncoveredNames(rep.Uncovered.Crashed)
	timedOut := uncoveredNames(rep.Uncovered.TimedOut)
	skippedChecks := uncoveredNames(rep.Uncovered.Skipped)
	if len(unavailable) > 0 {
		fmt.Fprintf(&b, "- Unavailable: %s\n", strings.Join(unavailable, ", "))
	}
	if len(crashed) > 0 {
		fmt.Fprintf(&b, "- Crashed: %s\n", strings.Join(crashed, ", "))
	}
	if len(timedOut) > 0 {
		fmt.Fprintf(&b, "- Timed out: %s\n", strings.Join(timedOut, ", "))
	}
	if len(skippedChecks) > 0 {
		fmt.Fprintf(&b, "- Skipped: %s\n", strings.Join(skippedChecks, ", "))
	}
	if len(rep.ResidualRisk) == 0 {
		b.WriteString("- Residual risk: none declared\n")
	} else {
		for _, item := range rep.ResidualRisk {
			fmt.Fprintf(&b, "- Residual risk: [%s] %s (expires %s)\n", item.Severity, item.Reason, item.ExpiresAt)
		}
	}

	b.WriteString("\n### Annotations\n\n")
	if changedOnly && diff != nil {
		fmt.Fprintf(&b, "- %d finding(s) annotated on changed lines; %d finding(s) outside the change were not annotated\n",
			len(annotations), skipped)
	} else {
		fmt.Fprintf(&b, "- %d finding(s) annotated (change set not restricted)\n", len(annotations))
	}
	for _, a := range annotations {
		loc := a.Path
		if a.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", a.Path, a.StartLine)
		}
		fmt.Fprintf(&b, "- `%s` — %s\n", loc, a.Message)
	}

	return b.String()
}

func sortedRuns(runs []evidence.RunOutcome) []evidence.RunOutcome {
	out := append([]evidence.RunOutcome(nil), runs...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		return out[i].Command < out[j].Command
	})
	return out
}

func uncoveredNames(checks []evidence.UncoveredCheck) []string {
	var names []string
	seen := map[string]bool{}
	for _, c := range checks {
		if c.Tool != "" && !seen[c.Tool] {
			seen[c.Tool] = true
			names = append(names, c.Tool)
		}
	}
	sort.Strings(names)
	return names
}
