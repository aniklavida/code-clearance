package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

func TestCLI_ScanJSONOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runScan(context.Background(), []string{"--json", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 on clean target, got %d, stderr: %s", code, stderr.String())
	}

	var report evidence.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v\noutput: %s", err, stdout.String())
	}

	if report.Target.Commit != evidence.NotAGitRepository {
		t.Fatalf("expected non-git target commit, got %q", report.Target.Commit)
	}
}

func TestCLI_ScanHumanOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runScan(context.Background(), []string{dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 on clean target, got %d, stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Repository:") {
		t.Fatalf("expected output to contain 'Repository:', got: %s", out)
	}
	if !strings.Contains(out, "Commit:") {
		t.Fatalf("expected output to contain 'Commit:', got: %s", out)
	}
	if !strings.Contains(out, "Clearance:") {
		t.Fatalf("expected output to contain 'Clearance:', got: %s", out)
	}
}

func TestCLI_Usage(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	if !strings.Contains(buf.String(), "code-clearance <command>") {
		t.Fatalf("unexpected usage output: %s", buf.String())
	}
}
