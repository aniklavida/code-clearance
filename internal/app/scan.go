package app

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// ScannerAdapter runs security checks against targetDir and returns
// one or more RunOutcome values.
type ScannerAdapter func(ctx context.Context, targetDir string) []evidence.RunOutcome

// Engine coordinates target resolution, adapter execution, and report assembly.
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

// Scan executes clearance checks on targetDir using this engine, binding
// findings to the repository, commit SHA, and dirty-tree fingerprint.
func (e *Engine) Scan(ctx context.Context, targetDir string) (evidence.Report, error) {
	startTime := time.Now().UTC().Format(time.RFC3339)

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	target := DetectTarget(ctx, absDir)

	e.mu.RLock()
	adapters := append([]ScannerAdapter(nil), e.adapters...)
	e.mu.RUnlock()

	var runs []evidence.RunOutcome
	var adaptersRan []string
	var allFindings []evidence.Finding

	for _, a := range adapters {
		outcomes := a(ctx, absDir)
		for _, o := range outcomes {
			runs = append(runs, o)
			if o.Tool != "" {
				adaptersRan = append(adaptersRan, o.Tool)
			}
			allFindings = append(allFindings, o.Findings...)
		}
	}

	endTime := time.Now().UTC().Format(time.RFC3339)

	report := evidence.Report{
		SchemaVersion: "v1",
		Target:        target,
		Runs:          runs,
		Findings:      allFindings,
		Uncovered: evidence.UncoveredChecks{
			Skipped:     []evidence.UncoveredCheck{},
			Crashed:     []evidence.UncoveredCheck{},
			TimedOut:    []evidence.UncoveredCheck{},
			Unavailable: []evidence.UncoveredCheck{},
		},
		Coverage: evidence.CoverageReport{
			Scope:        "quick",
			FilesChecked: []string{absDir},
			AdaptersRan:  adaptersRan,
			Summary:      "Clearance scan completed",
		},
		ResidualRisk: []evidence.ResidualRiskItem{},
		Timestamps: evidence.ReportTimestamps{
			StartedAt:   startTime,
			CompletedAt: endTime,
		},
	}

	// Apply deterministic policy verdict
	cfg := policy.DefaultConfig()
	// If custom engine has non-default adapters, only require adapters present in engine
	if len(adapters) > 0 {
		var reqs []string
		for _, tool := range adaptersRan {
			if tool == "gitleaks" {
				reqs = append(reqs, tool)
			}
		}
		if len(reqs) > 0 {
			cfg.Adapters.Required = reqs
		} else {
			cfg.Adapters.Required = []string{}
		}
	}

	policy.ApplyVerdict(cfg, &report)
	return report, nil
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

// DefaultEngine returns the shared default engine.
func DefaultEngine() *Engine {
	return defaultEngine
}
