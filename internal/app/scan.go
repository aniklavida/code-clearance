package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
}

// Engine coordinates scope planning, parallel execution, artifact persistence,
// and report assembly.
type Engine struct {
	mu       sync.RWMutex
	adapters []ScannerAdapter
}

// NewEngine constructs an Engine with the provided scanner adapters.
func NewEngine(adapters ...ScannerAdapter) *Engine {
	return &Engine{
		adapters: append([]ScannerAdapter(nil), adapters...),
	}
}

// AddAdapter appends a scanner adapter to the engine.
func (e *Engine) AddAdapter(adapter ScannerAdapter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.adapters = append(e.adapters, adapter)
}

// ScanWithOptions executes clearance checks on targetDir using the specified options.
func (e *Engine) ScanWithOptions(ctx context.Context, targetDir string, opts ScanOptions) (evidence.Report, error) {
	startTime := time.Now().UTC().Format(time.RFC3339)

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	cfg := policy.DefaultConfig()

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
	adapters := append([]ScannerAdapter(nil), e.adapters...)
	e.mu.RUnlock()

	// 3. Parallel Execution: run adapters and repository commands concurrently
	maxConcurrency := cfg.Limits.MaxConcurrency
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
		taskFn := a
		taskName := fmt.Sprintf("adapter-%d", idx)
		tasks = append(tasks, executionTask{
			name: taskName,
			fn: func(c context.Context) []evidence.RunOutcome {
				return taskFn(c, absDir)
			},
		})
	}

	// Repository command tasks (from clearance.yaml)
	for _, cmdRule := range plan.Commands {
		rule := cmdRule
		tasks = append(tasks, executionTask{
			name: "command:" + rule.Name,
			fn: func(c context.Context) []evidence.RunOutcome {
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

	// 6. Apply deterministic policy verdict
	if e != defaultEngine && len(adapters) > 0 {
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
	return report, nil
}

// Scan executes clearance checks on targetDir using default options (quick scope).
func (e *Engine) Scan(ctx context.Context, targetDir string) (evidence.Report, error) {
	return e.ScanWithOptions(ctx, targetDir, ScanOptions{Scope: "quick"})
}

var defaultEngine = &Engine{}

// RegisterDefaultAdapter registers an adapter to run during default scans.
func RegisterDefaultAdapter(adapter ScannerAdapter) {
	defaultEngine.AddAdapter(adapter)
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
