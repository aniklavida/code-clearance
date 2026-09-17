// Package runner spawns external analyser processes and captures their
// exit behaviour. This is the Code Clearance foundation
// validation: it proves that Go's os/exec plus context cancellation gives
// enough control to run third-party scanners safely (bounded time, clean
// kill on timeout, full stdout/stderr capture, real exit codes) on every
// v1.0 platform (Linux, macOS and Windows).
//
// Process-tree containment (killing a hung scanner's whole subtree, not
// just its direct child) is platform-specific and lives in runner_unix.go
// (POSIX process groups) and runner_windows.go (Windows job objects),
// behind the small processTree interface below.
package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Spec describes one external process to run.
type Spec struct {
	// Name is a short label for the tool being run (e.g. "gitleaks").
	Name string
	// Command is the executable to invoke. It is resolved via PATH.
	Command string
	// Args are passed to the command as-is. No shell is involved, so
	// there is no shell-injection surface even if Args are built from
	// repository-controlled configuration.
	Args []string
	// Dir is the working directory the process runs in.
	Dir string
	// Env specifies additional environment variables in KEY=VALUE format.
	Env []string
	// Timeout bounds total wall-clock time. Zero means no bound beyond
	// the caller's context.
	Timeout time.Duration
}

// Result captures everything the orchestrator needs to decide what
// happened, independent of whether the tool "succeeded" in a domain sense.
type Result struct {
	Name     string
	Stdout   []byte
	Stderr   []byte
	ExitCode int // -1 when the process never produced an exit code
	Duration time.Duration
	// TimedOut is true when the process was killed because it exceeded
	// Spec.Timeout.
	TimedOut bool
	// Killed is true when the process was killed for any reason
	// (timeout or parent context cancellation), as opposed to exiting
	// on its own (including with a non-zero exit code).
	Killed bool
	// Err carries a Go-level failure to start/wait on the process
	// (e.g. "executable not found"). A non-zero exit code alone is NOT
	// reported here — that is a normal, expected outcome for scanners
	// that use exit codes to signal "findings present".
	Err error
}

// State returns a distinct, visible state name for this process execution:
// "ok", "timed-out", "crashed", or "cancelled". None of the non-zero/non-ok
// states can be confused with a pass.
func (r Result) State() string {
	if r.TimedOut {
		return "timed-out"
	}
	if r.Killed {
		return "cancelled"
	}
	if r.Err != nil || (r.ExitCode != 0 && r.ExitCode != 1) {
		return "crashed"
	}
	return "ok"
}

// ErrNotInstalled is returned (wrapped) when the target executable cannot
// be found on PATH. Callers use this to distinguish "tool missing" from
// "tool ran and failed", which the product must report as Incomplete
// rather than a false pass or a crash.
var ErrNotInstalled = errors.New("executable not found on PATH")

// processTree abstracts platform-specific process-tree containment so Run
// can terminate a hung scanner's entire process tree — not only its direct
// child — identically on every supported platform. A scanner that wraps a
// JVM/Node/Python runtime and forks its own children is the motivating
// case: killing only the wrapper PID would leave the real work running as
// an orphan.
//
//   - runner_unix.go (Linux, macOS): a POSIX process group, killed with
//     SIGKILL against the negated PID.
//   - runner_windows.go (Windows): a job object, killed with
//     TerminateJobObject; child processes join the same job automatically
//     unless they explicitly opt out, which Code Clearance's own adapters
//     never do.
type processTree interface {
	// Kill terminates every process in the tree.
	Kill() error
	// Close releases any OS resources the tracking held (a Windows job
	// object handle; a no-op on POSIX).
	Close()
}

// beforeStart applies whatever SysProcAttr the platform's containment
// mechanism needs before the child process is created, and afterStart
// begins tracking cmd's process tree once it has started. Both are
// implemented once per platform, in runner_unix.go and runner_windows.go.

// Run spawns the process described by s and blocks until it exits, the
// timeout elapses, or ctx is cancelled — whichever comes first.
//
// On timeout or cancellation the entire process tree is killed so that a
// scanner which has spawned its own children cannot survive as an orphan.
func Run(ctx context.Context, s Spec) Result {
	start := time.Now()
	res := Result{Name: s.Name, ExitCode: -1}

	if _, err := exec.LookPath(s.Command); err != nil {
		res.Err = fmt.Errorf("%s: %w: %v", s.Name, ErrNotInstalled, err)
		return res
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if s.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	cmd := exec.Command(s.Command, s.Args...)
	cmd.Dir = s.Dir
	if len(s.Env) > 0 {
		cmd.Env = append(os.Environ(), s.Env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	beforeStart(cmd)

	if err := cmd.Start(); err != nil {
		res.Err = fmt.Errorf("%s: start: %w", s.Name, err)
		res.Duration = time.Since(start)
		return res
	}

	tree, err := afterStart(cmd)
	if err != nil {
		// The process is already running but we failed to attach
		// tree-containment (e.g. a Windows job object). Best-effort
		// kill the direct process so we do not leak it, then report
		// this as a start failure — an orchestrator must not run a
		// scanner it cannot guarantee it can stop.
		_ = cmd.Process.Kill()
		<-waitFor(cmd)
		res.Err = fmt.Errorf("%s: attach process tree: %w", s.Name, err)
		res.Duration = time.Since(start)
		return res
	}
	defer tree.Close()

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	select {
	case err := <-waitErr:
		res.Duration = time.Since(start)
		res.Stdout = stdout.Bytes()
		res.Stderr = stderr.Bytes()
		res.ExitCode = exitCodeOf(cmd, err)
		return res

	case <-runCtx.Done():
		_ = tree.Kill()
		<-waitErr // reap; ignore the error, the kill caused it
		res.Duration = time.Since(start)
		res.Stdout = stdout.Bytes()
		res.Stderr = stderr.Bytes()
		res.Killed = true
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			res.TimedOut = true
		}
		return res
	}
}

func waitFor(cmd *exec.Cmd) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- cmd.Wait() }()
	return ch
}

func exitCodeOf(cmd *exec.Cmd, waitErr error) int {
	if waitErr == nil {
		return cmd.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// RunParallel runs multiple Specs concurrently with bounded concurrency.
//
// Each child process is invoked with an explicit working directory, argument
// arrays (no shell strings), bounded timeouts, and cancellation. One optional
// adapter crashing or panicking cannot corrupt another adapter's results.
func RunParallel(ctx context.Context, specs []Spec, maxConcurrency int) []Result {
	if len(specs) == 0 {
		return nil
	}
	if maxConcurrency <= 0 {
		maxConcurrency = len(specs)
	}

	results := make([]Result, len(specs))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i, s := range specs {
		wg.Add(1)
		go func(idx int, spec Spec) {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					results[idx] = Result{
						Name:     spec.Name,
						ExitCode: -1,
						Err:      fmt.Errorf("panic in runner goroutine: %v", rec),
					}
				}
			}()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = Result{
					Name:     spec.Name,
					ExitCode: -1,
					Killed:   true,
					Err:      ctx.Err(),
				}
				return
			}

			results[idx] = Run(ctx, spec)
		}(i, s)
	}

	wg.Wait()
	return results
}
