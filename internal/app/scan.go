package app

import (
	"context"
	"path/filepath"
	"sync"

	"github.com/aniklavida/code-clearance/internal/evidence"
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
	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	target := DetectTarget(ctx, absDir)

	e.mu.RLock()
	adapters := append([]ScannerAdapter(nil), e.adapters...)
	e.mu.RUnlock()

	var runs []evidence.RunOutcome
	for _, a := range adapters {
		runs = append(runs, a(ctx, absDir)...)
	}

	return evidence.Report{
		Target: target,
		Runs:   runs,
	}, nil
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
