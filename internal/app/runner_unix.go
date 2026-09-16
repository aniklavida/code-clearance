//go:build !windows

package app

import (
	"os/exec"
	"syscall"
)

// beforeStart puts the child in its own process group so a timeout/cancel
// kill can take the whole subtree, not just the direct child PID.
func beforeStart(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// unixProcessGroup kills a POSIX process group by sending SIGKILL to the
// negated PID, which the kernel treats as "every process in this group".
type unixProcessGroup struct {
	pid int
}

func afterStart(cmd *exec.Cmd) (processTree, error) {
	// Setpgid: true (see beforeStart) already made the child the leader
	// of its own process group, with group ID equal to its PID, so no
	// further OS call is needed to start tracking it.
	return unixProcessGroup{pid: cmd.Process.Pid}, nil
}

func (g unixProcessGroup) Kill() error {
	return syscall.Kill(-g.pid, syscall.SIGKILL)
}

func (g unixProcessGroup) Close() {}
