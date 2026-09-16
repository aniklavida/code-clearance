package app

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests run identically on Linux, macOS and Windows: every helper
// below picks the platform-appropriate command instead of assuming a POSIX
// shell exists. Linux/macOS use "sh"; Windows uses "cmd" or "powershell",
// which are always present on a Windows host without any extra install.

// shellExit returns a Spec that runs and exits with the given code,
// without printing anything.
func shellExit(code int) (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/C", "exit " + strconv.Itoa(code)}
	}
	return "sh", []string{"-c", "exit " + strconv.Itoa(code)}
}

// shellEchoStdoutExit prints s to stdout, then exits with the given code.
func shellEchoStdoutExit(s string, code int) (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/C", fmt.Sprintf("echo %s&exit %d", s, code)}
	}
	return "sh", []string{"-c", fmt.Sprintf("echo %s; exit %d", s, code)}
}

// shellEchoStdoutStderrExit prints out to stdout, err to stderr, then
// exits with the given code.
func shellEchoStdoutStderrExit(out, errText string, code int) (string, []string) {
	if runtime.GOOS == "windows" {
		script := fmt.Sprintf("Write-Output '%s'; [Console]::Error.WriteLine('%s'); exit %d", out, errText, code)
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", script}
	}
	return "sh", []string{"-c", fmt.Sprintf("echo %s; echo %s 1>&2; exit %d", out, errText, code)}
}

// sleepSpec returns a Spec that just sleeps for the given duration,
// simulating a hung scanner.
func sleepSpec(seconds int) (string, []string) {
	if runtime.GOOS == "windows" {
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf("Start-Sleep -Seconds %d", seconds)}
	}
	return "sleep", []string{strconv.Itoa(seconds)}
}

// parentPrintsChildPidThenSleeps starts a detached grandchild that sleeps
// for seconds, prints the grandchild's PID to stdout, then itself sleeps
// for seconds too — mirroring a scanner wrapper (JVM/Node/Python launcher)
// that forks the real work and stays alive alongside it.
func parentPrintsChildPidThenSleeps(seconds int) (string, []string) {
	if runtime.GOOS == "windows" {
		script := fmt.Sprintf(
			`$p = Start-Process powershell -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds %d' -WindowStyle Hidden -PassThru; Write-Output $p.Id; Start-Sleep -Seconds %d`,
			seconds, seconds,
		)
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", script}
	}
	// "$!" is the PID of the just-backgrounded job in POSIX sh.
	return "sh", []string{"-c", fmt.Sprintf("sleep %d & echo $!; wait", seconds)}
}

// processAlive reports whether the grandchild process with the given PID
// (as printed to stdout by parentPrintsChildPidThenSleeps) is still
// running.
func processAlive(t *testing.T, pidText string) bool {
	t.Helper()
	pidText = strings.TrimSpace(pidText)
	if pidText == "" {
		t.Fatalf("no child PID captured from helper process stdout")
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf("(Get-Process -Id %s -ErrorAction SilentlyContinue).Id", pidText)).Output()
		if err != nil {
			// Get-Process itself failing to run is an environment
			// problem, not evidence either way; fail loudly rather
			// than silently treating it as "process gone".
			t.Fatalf("could not query process state: %v", err)
		}
		return strings.TrimSpace(string(out)) != ""
	}
	if _, err := strconv.Atoi(pidText); err != nil {
		t.Fatalf("could not parse child pid %q: %v", pidText, err)
	}
	// "kill -0" sends no signal; it only reports whether the PID still
	// exists and is signalable, which is exactly "is this process
	// still alive" without needing pgrep to be installed.
	return exec.Command("kill", "-0", pidText).Run() == nil
}

func TestRun_Success(t *testing.T) {
	cmdName, args := shellEchoStdoutExit("hello-stdout", 0)
	res := Run(context.Background(), Spec{Name: "echo", Command: cmdName, Args: args})
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello-stdout" {
		t.Fatalf("stdout = %q", got)
	}
	if res.Killed || res.TimedOut {
		t.Fatalf("expected clean exit, got killed=%v timedOut=%v", res.Killed, res.TimedOut)
	}
}

func TestRun_NonZeroExitCode(t *testing.T) {
	// Scanners routinely use non-zero exit codes to mean "findings
	// present", not "crashed". The orchestrator must preserve the exact
	// code rather than collapsing it to a boolean.
	cmdName, args := shellExit(3)
	res := Run(context.Background(), Spec{Name: "exit3", Command: cmdName, Args: args})
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", res.ExitCode)
	}
}

func TestRun_StderrCaptured(t *testing.T) {
	cmdName, args := shellEchoStdoutStderrExit("out-line", "err-line", 1)
	res := Run(context.Background(), Spec{Name: "stderr", Command: cmdName, Args: args})
	if res.ExitCode != 1 {
		t.Fatalf("exit code = %d, want 1", res.ExitCode)
	}
	if got := strings.TrimSpace(string(res.Stderr)); got != "err-line" {
		t.Fatalf("stderr = %q", got)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "out-line" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestRun_NotInstalled(t *testing.T) {
	res := Run(context.Background(), Spec{
		Name:    "ghost",
		Command: "code-clearance-tool-that-does-not-exist",
	})
	if res.Err == nil {
		t.Fatal("expected error for missing executable")
	}
}

func TestRun_TimeoutKillsHungProcess(t *testing.T) {
	// A process that ignores nothing but simply runs long (simulating a
	// hung scanner). Timeout is far shorter than the sleep so we can
	// measure that the kill actually happens promptly rather than the
	// process running to completion.
	cmdName, args := sleepSpec(30)
	start := time.Now()
	res := Run(context.Background(), Spec{
		Name:    "hung",
		Command: cmdName,
		Args:    args,
		Timeout: 300 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true, got result=%+v", res)
	}
	if !res.Killed {
		t.Fatalf("expected Killed=true, got result=%+v", res)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("kill took %v, expected well under the 30s sleep duration", elapsed)
	}
	t.Logf("hung process killed after %v (sleep 30s, timeout 300ms)", elapsed)
}

func TestRun_ParentCancellationKillsProcess(t *testing.T) {
	cmdName, args := sleepSpec(30)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result, 1)
	go func() {
		done <- Run(ctx, Spec{
			Name:    "cancellable",
			Command: cmdName,
			Args:    args,
		})
	}()

	time.Sleep(150 * time.Millisecond)
	cancelStart := time.Now()
	cancel()

	res := <-done
	elapsed := time.Since(cancelStart)

	if !res.Killed {
		t.Fatalf("expected Killed=true after parent cancellation, got %+v", res)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("cancellation took %v to take effect", elapsed)
	}
	t.Logf("process killed %v after context cancellation", elapsed)
}

func TestRun_ProcessTreeKillsChildren(t *testing.T) {
	// Simulate a scanner that spawns a subprocess (common for JVM/Node
	// wrappers). Killing only the parent PID would orphan the child;
	// killing the whole process tree (POSIX process group, or Windows
	// job object) must not.
	//
	// The timeout must be long enough for the parent to actually launch
	// the grandchild and flush its PID to stdout before being killed.
	// On POSIX, "sh -c" backgrounding a "sleep" is near-instant, so
	// 300ms (as used by TestRun_TimeoutKillsHungProcess) is plenty. On
	// Windows the parent itself is a PowerShell process that has to
	// start a second PowerShell process via Start-Process — two .NET
	// runtime starts in sequence — which routinely takes longer than
	// 300ms on a CI runner; a real first attempt at this test on
	// windows-latest measured "no child PID captured" because the
	// timeout fired before Start-Process's child had even launched, not
	// because job-object termination failed. A generous but still
	// short-relative-to-the-30s-sleep timeout avoids that false
	// negative without weakening what the test proves.
	timeout := 300 * time.Millisecond
	if runtime.GOOS == "windows" {
		timeout = 5 * time.Second
	}

	cmdName, args := parentPrintsChildPidThenSleeps(30)
	start := time.Now()
	res := Run(context.Background(), Spec{
		Name:    "parent-with-child",
		Command: cmdName,
		Args:    args,
		Timeout: timeout,
	})
	elapsed := time.Since(start)

	if !res.Killed || !res.TimedOut {
		t.Fatalf("expected killed+timedOut, got %+v", res)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("tree kill took %v", elapsed)
	}

	// Give the OS a moment to finish tearing the tree down, then prove
	// the grandchild did not survive as an orphan.
	time.Sleep(500 * time.Millisecond)
	if processAlive(t, string(res.Stdout)) {
		t.Fatal("orphaned child process still running after process-tree kill")
	}
}
