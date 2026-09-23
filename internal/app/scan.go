package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aniklavida/code-clearance/internal/correlate"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/store"
)

// ScannerAdapter runs security checks against targetDir and returns
// one or more RunOutcome values.
type ScannerAdapter func(ctx context.Context, targetDir string) []evidence.RunOutcome

// ScanOptions configures a clearance scan run.
type ScanOptions struct {
	Scope        string // "quick", "full", "release" (default: "quick")
	BaseCommit   string // optional base commit for diff calculations
	StoreRoot    string // optional override for artifact store directory
	AllowNetwork bool   // whether network access is permitted (default: false)

	// Config is the clearance policy to evaluate against. When nil the
	// default is used.
	//
	// Without this the engine always evaluated DefaultConfig, so a caller
	// could not declare which adapters are required — and `required` is the
	// field the whole Incomplete-never-a-pass guarantee rests on. The schema
	// defined it and the policy layer enforced it, but nothing could reach
	// the engine to say so.
	Config *policy.Config

	// TargetTools, if non-empty, restricts execution to only the named tools/adapters/commands.
	TargetTools []string

	// TargetFiles, if non-empty, restricts execution scope to the specified files.
	TargetFiles []string
}

type adapterEntry struct {
	name string
	fn   ScannerAdapter
}

// Engine coordinates scope planning, parallel execution, artifact persistence,
// and report assembly.
type Engine struct {
	mu       sync.RWMutex
	adapters []adapterEntry
}

// NewEngine constructs an Engine with the provided scanner adapters.
func NewEngine(adapters ...ScannerAdapter) *Engine {
	eng := &Engine{}
	for _, a := range adapters {
		eng.adapters = append(eng.adapters, adapterEntry{fn: a})
	}
	return eng
}

// AddAdapter appends an unnamed scanner adapter to the engine.
func (e *Engine) AddAdapter(adapter ScannerAdapter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.adapters = append(e.adapters, adapterEntry{fn: adapter})
}

// AddNamedAdapter appends a named scanner adapter to the engine.
func (e *Engine) AddNamedAdapter(name string, adapter ScannerAdapter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.adapters = append(e.adapters, adapterEntry{name: name, fn: adapter})
}

// ScanWithOptions executes clearance checks on targetDir using the specified options.
func (e *Engine) ScanWithOptions(ctx context.Context, targetDir string, opts ScanOptions) (evidence.Report, error) {
	startTime := time.Now().UTC().Format(time.RFC3339)

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	cfg := policy.DefaultConfig()
	if opts.Config != nil {
		cfg = *opts.Config
	}

	// 1. Scope Planner: Resolve concrete files and checks bound to target state
	plan, err := PlanScope(ctx, absDir, ScopeOptions{
		Scope:      opts.Scope,
		BaseCommit: opts.BaseCommit,
	}, cfg)
	if err != nil {
		return evidence.Report{}, fmt.Errorf("scope planning: %w", err)
	}

	// 2. Initialize raw artifact store
	storePath := opts.StoreRoot
	if storePath == "" {
		storePath = filepath.Join(absDir, ".clearance")
	}
	st, err := store.New(storePath)
	if err != nil {
		return evidence.Report{}, fmt.Errorf("init artifact store: %w", err)
	}

	session, err := st.CreateRun("")
	if err != nil {
		return evidence.Report{}, fmt.Errorf("init run session: %w", err)
	}
	defer func() {
		if ctx.Err() != nil {
			session.Discard()
		}
	}()

	e.mu.RLock()
	adapters := append([]adapterEntry(nil), e.adapters...)
	e.mu.RUnlock()

	// 3. Parallel Execution: run adapters and repository commands concurrently
	prof := cfg.ActiveProfile(opts.Scope)
	maxConcurrency := prof.Limits.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}

	type executionTask struct {
		name string
		fn   func(context.Context) []evidence.RunOutcome
	}

	var tasks []executionTask

	// Adapter tasks
	for idx, a := range adapters {
		if len(opts.TargetTools) > 0 && a.name != "" && !containsString(opts.TargetTools, a.name) {
			continue
		}
		entryFn := a.fn
		taskName := a.name
		if taskName == "" {
			taskName = fmt.Sprintf("adapter-%d", idx)
		}
		tasks = append(tasks, executionTask{
			name: taskName,
			fn: func(c context.Context) []evidence.RunOutcome {
				outcomes := entryFn(c, absDir)
				if len(opts.TargetTools) > 0 {
					var filtered []evidence.RunOutcome
					for _, o := range outcomes {
						if containsString(opts.TargetTools, o.Tool) {
							filtered = append(filtered, o)
						}
					}
					return filtered
				}
				return outcomes
			},
		})
	}

	// Repository command tasks (from clearance.yaml). A repository command is
	// untrusted: it runs with an explicit argument vector, and its executable
	// must be on the command allowlist. A refused command is recorded as a
	// non-pass so a required check cannot silently disappear.
	for _, cmdRule := range plan.Commands {
		rule := cmdRule
		cmdName := "command:" + rule.Name
		if len(opts.TargetTools) > 0 && !containsString(opts.TargetTools, cmdName) && !containsString(opts.TargetTools, rule.Name) {
			continue
		}
		allow := prof.Commands.Allow
		tasks = append(tasks, executionTask{
			name: cmdName,
			fn: func(c context.Context) []evidence.RunOutcome {
				if bin, _, perr := ParseCommand(rule.Run, absDir); perr == nil && !CommandAllowed(bin, allow) {
					return []evidence.RunOutcome{DisallowedCommandOutcome(rule, bin)}
				}
				outcome, _, _ := RunRepositoryCommand(c, rule, absDir)
				return []evidence.RunOutcome{outcome}
			},
		})
	}

	taskResults := make([][]evidence.RunOutcome, len(tasks))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i, t := range tasks {
		wg.Add(1)
		go func(idx int, task executionTask) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					taskResults[idx] = []evidence.RunOutcome{
						{
							Tool:        task.name,
							ToolVersion: "v1.0.0",
							Command:     task.name,
							ExitCode:    -1,
							Status:      evidence.StatusCrashed,
							StderrTail:  fmt.Sprintf("adapter panicked: %v", r),
						},
					}
				}
			}()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				taskResults[idx] = []evidence.RunOutcome{
					{
						Tool:        task.name,
						ToolVersion: "v1.0.0",
						Command:     task.name,
						ExitCode:    -1,
						Status:      evidence.StatusUnavailable,
						StderrTail:  "cancelled before execution",
					},
				}
				return
			}

			taskResults[idx] = task.fn(ctx)
		}(i, t)
	}

	wg.Wait()

	if ctx.Err() != nil {
		session.Discard()
		return evidence.Report{}, ctx.Err()
	}

	// 4. Assemble outcomes, persist raw artifacts, and link findings
	var runs []evidence.RunOutcome
	var adaptersRan []string
	var allFindings []evidence.Finding

	for _, outcomes := range taskResults {
		for _, o := range outcomes {
			// Persist raw artifact if not already saved to this session
			var rawBytes []byte
			if len(o.RawData) > 0 {
				rawBytes = o.RawData
			} else if o.RawArtifact != nil && o.RawArtifact.URI != "" {
				rawBytes, _ = os.ReadFile(o.RawArtifact.URI)
			}

			if len(rawBytes) > 0 {
				format := "raw"
				if o.RawArtifact != nil && o.RawArtifact.Format != "" {
					format = o.RawArtifact.Format
				}
				ref, saveErr := session.SaveArtifact(o.Tool, format, rawBytes)
				if saveErr == nil {
					o.RawArtifact = &ref
				}
			} else {
				// Save diagnostic output as raw artifact
				payload := []byte(fmt.Sprintf("tool: %s\nstatus: %s\nexit_code: %d\nstderr: %s\n",
					o.Tool, o.Status, o.ExitCode, o.StderrTail))
				ref, saveErr := session.SaveArtifact(o.Tool, "log", payload)
				if saveErr == nil {
					o.RawArtifact = &ref
				}
			}

			// Ensure all findings reference this raw artifact and command
			for fIdx := range o.Findings {
				if o.RawArtifact != nil {
					o.Findings[fIdx].RawArtifact = *o.RawArtifact
					o.Findings[fIdx].RawIndex = fIdx
				}
				if o.Command != "" && o.Findings[fIdx].Command == "" {
					o.Findings[fIdx].Command = o.Command
				}
			}

			// Filter out internal store artifacts from scanner findings
			var filteredFindings []evidence.Finding
			for _, f := range o.Findings {
				isExcluded := false
				for _, loc := range f.Locations {
					cleanURI := filepath.ToSlash(loc.URI)
					if strings.HasPrefix(cleanURI, ".clearance/") || strings.Contains(cleanURI, "/.clearance/") {
						isExcluded = true
						break
					}
				}
				if isExcluded {
					continue
				}
				filteredFindings = append(filteredFindings, f)
			}
			o.Findings = filteredFindings
			if len(o.Findings) == 0 && o.Status == evidence.StatusFindings {
				o.Status = evidence.StatusOK
			}

			runs = append(runs, o)
			if o.Tool != "" && o.Status != evidence.StatusNotInstalled && o.Status != evidence.StatusSkipped {
				adaptersRan = append(adaptersRan, o.Tool)
			}
			allFindings = append(allFindings, o.Findings...)
		}
	}

	sort.Strings(adaptersRan)
	adaptersRan = dedupeStrings(adaptersRan)

	endTime := time.Now().UTC().Format(time.RFC3339)

	report := evidence.Report{
		SchemaVersion: "v1",
		Target:        plan.Target,
		Runs:          runs,
		Findings:      allFindings,
		Uncovered: evidence.UncoveredChecks{
			Skipped:     []evidence.UncoveredCheck{},
			Crashed:     []evidence.UncoveredCheck{},
			TimedOut:    []evidence.UncoveredCheck{},
			Unavailable: []evidence.UncoveredCheck{},
		},
		Coverage: evidence.CoverageReport{
			Scope:        plan.Scope,
			FilesChecked: plan.FilesChecked,
			AdaptersRan:  adaptersRan,
			Summary: fmt.Sprintf("Clearance scan completed (%s): %d files checked, %d checks ran",
				plan.Scope, len(plan.FilesChecked), len(runs)),
		},
		ResidualRisk: []evidence.ResidualRiskItem{},
		Timestamps: evidence.ReportTimestamps{
			StartedAt:   startTime,
			CompletedAt: endTime,
		},
	}

	// 5. Correlate and deduplicate findings across runs
	correlate.CorrelateReport(&report)

	if reviews, err := st.GetReviews(); err == nil && len(reviews) > 0 {
		for i := range report.Findings {
			if rec, ok := reviews[report.Findings[i].Fingerprint]; ok {
				// Invariant: A finding becomes fixed ONLY through new recorded evidence from a verification run.
				// An agent or reviewer asserting it fixed something changes nothing about the finding's state.
				if rec.ChallengeStatus == evidence.ChallengeFixed {
					hasValidVerification := false
					for _, vr := range rec.VerificationRuns {
						if (vr.Status == evidence.StatusOK || vr.Status == evidence.StatusFindings) && vr.Outcome == "cleared" {
							hasValidVerification = true
							break
						}
					}
					if !hasValidVerification {
						continue
					}
				}
				report.Findings[i].ChallengeStatus = rec.ChallengeStatus
				report.Findings[i].ChallengeRationale = rec.Reason
				report.Findings[i].Reviewer = evidence.Reviewer{
					Type:     rec.ReviewerType,
					Identity: rec.ReviewerIdentity,
				}
				if rec.FixPatch != nil {
					report.Findings[i].FixPatch = rec.FixPatch
				}
				if len(rec.VerificationRuns) > 0 {
					report.Findings[i].VerificationRuns = rec.VerificationRuns
				}
				if rec.Disposition != "" {
					report.Findings[i].Disposition = rec.Disposition
				}
			}
		}
	}

	// 6. Apply deterministic policy verdict
	// Deriving the required set from the runs that happened makes the
	// requirement circular: whatever ran is what was required, so nothing can
	// ever be missing and "required adapter did not run" is unreachable. The
	// required set is configuration, and configuration is the caller's.
	//
	// It is still derived when the caller supplied adapters and declared no
	// requirement of their own, because an explicitly supplied adapter is
	// evidently wanted — but only from the adapters that were *asked for*,
	// never from the ones that happened to succeed.
	if e != defaultEngine && len(adapters) > 0 && len(cfg.Adapters.Required) == 0 {
		var reqs []string
		for _, r := range runs {
			if r.Tool != "" {
				reqs = append(reqs, r.Tool)
			}
		}
		if len(reqs) > 0 {
			cfg.Adapters.Required = dedupeStrings(reqs)
		}
	}

	policy.ApplyVerdict(cfg, &report)
	_ = st.SaveLatestReport(session, report)
	return report, nil
}

// Scan executes clearance checks on targetDir using default options (quick scope).
func (e *Engine) Scan(ctx context.Context, targetDir string) (evidence.Report, error) {
	return e.ScanWithOptions(ctx, targetDir, ScanOptions{Scope: "quick"})
}

var defaultEngine = &Engine{}

// RegisterDefaultAdapter registers an unnamed adapter to run during default scans.
func RegisterDefaultAdapter(adapter ScannerAdapter) {
	defaultEngine.AddAdapter(adapter)
}

// RegisterNamedAdapter registers a named adapter to run during default scans.
func RegisterNamedAdapter(name string, adapter ScannerAdapter) {
	defaultEngine.AddNamedAdapter(name, adapter)
}

// Scan executes clearance checks on targetDir using the default engine.
func Scan(ctx context.Context, targetDir string) (evidence.Report, error) {
	return defaultEngine.Scan(ctx, targetDir)
}

// ScanWithOptions executes clearance checks on targetDir using the default engine with options.
func ScanWithOptions(ctx context.Context, targetDir string, opts ScanOptions) (evidence.Report, error) {
	return defaultEngine.ScanWithOptions(ctx, targetDir, opts)
}

// DefaultEngine returns the shared default engine.
func DefaultEngine() *Engine {
	return defaultEngine
}
