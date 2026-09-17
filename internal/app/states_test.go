package app

import (
	"context"
	"testing"
	"time"
)

// Constraint 2: Timeout, crash and cancellation each produce a distinct, visible state.
// None of them is a pass.

func TestState_TimeoutProducesDistinctVisibleStateNeverPass(t *testing.T) {
	cmdName, args := sleepSpec(10)
	res := Run(context.Background(), Spec{
		Name:    "hung-command",
		Command: cmdName,
		Args:    args,
		Timeout: 50 * time.Millisecond,
	})

	state := res.State()

	// 1. Must NOT be a pass
	if state == "ok" {
		t.Fatal("SECURITY VIOLATION: timed-out command reported state 'ok' (pass)!")
	}

	// 2. Must be timed-out
	if state != "timed-out" {
		t.Fatalf("expected state 'timed-out', got %q", state)
	}

	// 3. Must be distinct from crash and cancellation
	if state == "crashed" {
		t.Fatal("timed-out command was conflated with crashed state")
	}
	if state == "cancelled" {
		t.Fatal("timed-out command was conflated with cancelled state")
	}

	if !res.TimedOut {
		t.Fatal("res.TimedOut must be true")
	}
}

func TestState_CrashProducesDistinctVisibleStateNeverPass(t *testing.T) {
	cmdName, args := shellExit(2)
	res := Run(context.Background(), Spec{
		Name:    "crashed-command",
		Command: cmdName,
		Args:    args,
	})

	state := res.State()

	// 1. Must NOT be a pass
	if state == "ok" {
		t.Fatal("SECURITY VIOLATION: crashed command reported state 'ok' (pass)!")
	}

	// 2. Must be crashed
	if state != "crashed" {
		t.Fatalf("expected state 'crashed', got %q", state)
	}

	// 3. Must be distinct from timeout and cancellation
	if state == "timed-out" {
		t.Fatal("crashed command was conflated with timed-out state")
	}
	if state == "cancelled" {
		t.Fatal("crashed command was conflated with cancelled state")
	}

	if res.TimedOut {
		t.Fatal("res.TimedOut must be false for crash")
	}
	if res.Killed {
		t.Fatal("res.Killed must be false for crash")
	}
}

func TestState_CancellationProducesDistinctVisibleStateNeverPass(t *testing.T) {
	cmdName, args := sleepSpec(10)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan Result, 1)
	go func() {
		done <- Run(ctx, Spec{
			Name:    "cancelled-command",
			Command: cmdName,
			Args:    args,
		})
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	res := <-done
	state := res.State()

	// 1. Must NOT be a pass
	if state == "ok" {
		t.Fatal("SECURITY VIOLATION: cancelled command reported state 'ok' (pass)!")
	}

	// 2. Must be cancelled
	if state != "cancelled" {
		t.Fatalf("expected state 'cancelled', got %q", state)
	}

	// 3. Must be distinct from timeout and crash
	if state == "timed-out" {
		t.Fatal("cancelled command was conflated with timed-out state")
	}
	if state == "crashed" {
		t.Fatal("cancelled command was conflated with crashed state")
	}

	if res.TimedOut {
		t.Fatal("res.TimedOut must be false for cancellation")
	}
	if !res.Killed {
		t.Fatal("res.Killed must be true for cancellation")
	}
}
