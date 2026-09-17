package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
)

func TestScopePlanner_QuickDirtyTree_RecordsExactFilesCommitFingerprint(t *testing.T) {
	ctx := context.Background()
	dir := initTestGitRepo(t)

	// In clean tree, commit exists, dirty is false
	cfg := policy.DefaultConfig()

	// Add dirty modifications: modify tracked file.txt, add untracked new.go
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("modified content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := PlanScope(ctx, dir, ScopeOptions{Scope: "quick"}, cfg)
	if err != nil {
		t.Fatalf("PlanScope: %v", err)
	}

	// 1. Commit must be recorded
	if plan.Target.Commit == "" || plan.Target.Commit == evidence.NotAGitRepository {
		t.Fatalf("expected real commit SHA, got %q", plan.Target.Commit)
	}

	// 2. Dirty tree fingerprint must be recorded
	if !plan.Target.Dirty {
		t.Fatal("expected target.Dirty=true for modified tree")
	}
	if plan.Target.Fingerprint == "" || plan.Target.Fingerprint == evidence.CleanTreeFingerprint {
		t.Fatalf("expected dirty-tree fingerprint, got %q", plan.Target.Fingerprint)
	}

	// 3. Exact file set must be recorded
	if len(plan.FilesChecked) != 2 {
		t.Fatalf("expected 2 files checked, got %d: %v", len(plan.FilesChecked), plan.FilesChecked)
	}

	hasFileTxt := false
	hasNewGo := false
	for _, f := range plan.FilesChecked {
		if f == "file.txt" {
			hasFileTxt = true
		}
		if f == "new.go" {
			hasNewGo = true
		}
	}
	if !hasFileTxt || !hasNewGo {
		t.Fatalf("expected exact files file.txt and new.go, got %v", plan.FilesChecked)
	}
}

func TestScopePlanner_FullScope_RecordsAllFiles(t *testing.T) {
	ctx := context.Background()
	dir := initTestGitRepo(t)
	cfg := policy.DefaultConfig()

	if err := os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("extra\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := PlanScope(ctx, dir, ScopeOptions{Scope: "full"}, cfg)
	if err != nil {
		t.Fatalf("PlanScope: %v", err)
	}

	if plan.Scope != "full" {
		t.Fatalf("plan.Scope = %q, want full", plan.Scope)
	}

	if len(plan.FilesChecked) < 2 {
		t.Fatalf("expected at least 2 files in full scope, got %v", plan.FilesChecked)
	}
}
