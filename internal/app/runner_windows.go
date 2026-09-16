//go:build windows

// Windows has no equivalent of a POSIX process group signal, so this file
// uses the platform's own primitive for "kill this process and everything
// it spawned": a job object. Any process assigned to a job, and by default
// any child process that process creates, is terminated in one call to
// TerminateJobObject — the same guarantee runner_unix.go gets from
// SIGKILL against a negated process-group PID.
package app

import (
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// beforeStart has no Windows-specific process-creation flags to set:
// job-object containment is attached after the process starts (see
// afterStart), which is the standard approach for processes launched
// through os/exec — os/exec does not expose the raw thread handle needed
// to start a process suspended and assign it to a job before its first
// instruction runs. In exchange there is a narrow window, between process
// creation and the AssignProcessToJobObject call below, during which a
// pathological scanner that forks an immediate grandchild could escape
// containment for that one grandchild. JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
// (set in afterStart) still guarantees the job itself cannot outlive this
// process, which bounds the blast radius even in that case.
func beforeStart(cmd *exec.Cmd) {}

// windowsJob kills a Windows job object, which terminates every process
// assigned to it.
type windowsJob struct {
	handle windows.Handle
}

func afterStart(cmd *exec.Cmd) (processTree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}

	// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: if this process exits or
	// crashes without explicitly killing the job (e.g. a panic that
	// skips the deferred Close/Kill), Windows itself tears down every
	// process still in the job when the last handle to it closes. This
	// is the Windows-side belt-and-braces equivalent of never leaving an
	// orphaned scanner running.
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}

	procHandle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(procHandle)

	if err := windows.AssignProcessToJobObject(job, procHandle); err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}

	return &windowsJob{handle: job}, nil
}

func (j *windowsJob) Kill() error {
	// Exit code 1: matches this runner's convention of exit code -1
	// only ever meaning "no exit code observed"; 1 here just needs to be
	// a value TerminateJobObject accepts, since Run() reports Killed by
	// its own field rather than by inspecting this code.
	return windows.TerminateJobObject(j.handle, 1)
}

func (j *windowsJob) Close() {
	windows.CloseHandle(j.handle)
}
