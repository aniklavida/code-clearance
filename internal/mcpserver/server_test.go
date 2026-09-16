package mcpserver_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/mcpserver"
)

func TestEntryPoints_ReachIdenticalResultsThroughCore(t *testing.T) {
	ctx := context.Background()

	// Clean directory with a benign file
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Run through core engine entry point (as used by CLI)
	coreReport, err := app.Scan(ctx, dir)
	if err != nil {
		t.Fatalf("app.Scan failed: %v", err)
	}

	// 2. Run through MCP tool entry point
	args := mcpserver.ScanArgs{TargetDir: dir}
	_, mcpReport, err := mcpserver.RunClearanceScan(ctx, nil, args)
	if err != nil {
		t.Fatalf("mcpserver.RunClearanceScan failed: %v", err)
	}

	// 3. Verify target binding is identical
	if coreReport.Target.Repository != mcpReport.Target.Repository {
		t.Fatalf("repository mismatch: core=%q, mcp=%q", coreReport.Target.Repository, mcpReport.Target.Repository)
	}
	if coreReport.Target.Commit != mcpReport.Target.Commit {
		t.Fatalf("commit mismatch: core=%q, mcp=%q", coreReport.Target.Commit, mcpReport.Target.Commit)
	}
	if coreReport.Target.Dirty != mcpReport.Target.Dirty {
		t.Fatalf("dirty mismatch: core=%v, mcp=%v", coreReport.Target.Dirty, mcpReport.Target.Dirty)
	}
	if coreReport.Target.Fingerprint != mcpReport.Target.Fingerprint {
		t.Fatalf("fingerprint mismatch: core=%q, mcp=%q", coreReport.Target.Fingerprint, mcpReport.Target.Fingerprint)
	}

	// 4. Verify adapter run outcomes are identical
	if len(coreReport.Runs) != len(mcpReport.Runs) {
		t.Fatalf("runs count mismatch: core=%d, mcp=%d", len(coreReport.Runs), len(mcpReport.Runs))
	}

	for i := range coreReport.Runs {
		coreRun := coreReport.Runs[i]
		mcpRun := mcpReport.Runs[i]

		if coreRun.Tool != mcpRun.Tool {
			t.Fatalf("run[%d] tool mismatch: core=%q, mcp=%q", i, coreRun.Tool, mcpRun.Tool)
		}
		if coreRun.Status != mcpRun.Status {
			t.Fatalf("run[%d] status mismatch: core=%s, mcp=%s", i, coreRun.Status, mcpRun.Status)
		}
		if coreRun.ExitCode != mcpRun.ExitCode {
			t.Fatalf("run[%d] exit code mismatch: core=%d, mcp=%d", i, coreRun.ExitCode, mcpRun.ExitCode)
		}
		if len(coreRun.Findings) != len(mcpRun.Findings) {
			t.Fatalf("run[%d] findings count mismatch: core=%d, mcp=%d", i, len(coreRun.Findings), len(mcpRun.Findings))
		}
		for j := range coreRun.Findings {
			if coreRun.Findings[j].ID != mcpRun.Findings[j].ID {
				t.Fatalf("run[%d] finding[%d] ID mismatch: core=%q, mcp=%q", i, j, coreRun.Findings[j].ID, mcpRun.Findings[j].ID)
			}
		}
	}
}

func TestServer_RegistersClearanceTool(t *testing.T) {
	server := mcpserver.NewServer()
	if server == nil {
		t.Fatal("expected non-nil server")
	}
}
