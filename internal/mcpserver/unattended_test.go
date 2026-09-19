package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"os/exec"
	"github.com/aniklavida/code-clearance/internal/store"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
)

func requireTool(t *testing.T, tool string) {
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("skipping test because %s is not installed", tool)
	}
}

func TestUnattendedAgentLoopReal(t *testing.T) {
	requireTool(t, "gitleaks")

	ctx := context.Background()

	tmpDir := t.TempDir()

	fixtureRepo := "../../testdata/fixtures/go"
	entries, err := os.ReadDir(fixtureRepo)
	if err != nil {
		t.Fatalf("read fixture repo: %v", err)
	}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(fixtureRepo, e.Name()))
		os.WriteFile(filepath.Join(tmpDir, e.Name()), data, 0644)
	}

	// Need to configure git user for commits to work on CI/Test envs

	configJSON := `{
		"version": "v1",
		"adapters": {
			"required": ["gitleaks"],
			"optional": []
		},
		"paths": { "include": ["**/*"], "exclude": ["**/.clearance/**"] },
		"scopes": { "quick": { "adapters": [], "commands": [], "allow_dirty": true }, "full": { "adapters": [], "commands": [], "allow_dirty": true }, 
			"release": { 
			    "adapters": ["gitleaks"], 
			    "commands": [], 
			    "allow_dirty": true,
			    "policy": {
			        "blocking_severities": ["critical", "high", "medium"],
			        "allow_dirty": true,
			        "accepted_risks": []
			    }
			}
		},
		"policy": {
			"blocking_severities": ["critical", "high", "medium"],
			"allow_dirty": true,
			"accepted_risks": []
		},
		"commands": { "required": [], "optional": [] },
		"limits": { "timeout_seconds": 30, "max_concurrency": 4 },
		"outcomes": {
			"minimum_evidence": {
				"cleared": { "required_adapters_must_pass": true, "zero_blocking_findings": true, "clean_tree_required": false },
				"cleared_with_residual_risk": { "accepted_risks_unexpired": true },
				"blocked": { "blocking_finding_present": true },
				"incomplete": { "missing_required_adapter": true, "crashed_or_timed_out": true }
			}
		}
	}`
	os.WriteFile(filepath.Join(tmpDir, "clearance.json"), []byte(configJSON), 0644)

	os.WriteFile(filepath.Join(tmpDir, ".gitleaksignore"), []byte(".clearance/"), 0644)

	os.WriteFile(filepath.Join(tmpDir, "secret.go"), []byte("package main\n\nconst token = \"-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCqGKukO1De7zhZj6+\"\n"), 0644)
	

	_, rep1, err := ClearanceRun(ctx, nil, ClearanceRunArgs{
		TargetDir: tmpDir,
		Profile:   "release",
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if rep1.Outcome != evidence.OutcomeBlocked {
		t.Fatalf("Expected Blocked, got %s. Reason: %s", rep1.Outcome, rep1.Reason)
	}

	if len(rep1.Findings) == 0 {
		t.Fatalf("Expected findings from gitleaks")
	}
	fp := rep1.Findings[0].Fingerprint

	_, _, err = RecordReview(ctx, nil, app.RecordReviewArgs{
		TargetDir:       tmpDir,
		Fingerprint:     fp,
		ChallengeStatus: string(evidence.ChallengeFixed),
		Reason:          "I removed the token",
		ReviewerType:    "human",
	})
	if err != nil {
		t.Fatalf("record review error: %v", err)
	}

	os.WriteFile(filepath.Join(tmpDir, ".gitleaksignore"), []byte(".clearance/"), 0644)

	os.WriteFile(filepath.Join(tmpDir, "secret.go"), []byte("package main\n\nconst token = \"\"\n"), 0644)
	
	

	os.RemoveAll(filepath.Join(tmpDir, ".clearance", "runs"))

	_, rep2, err := ClearanceRun(ctx, nil, ClearanceRunArgs{
		TargetDir: tmpDir,
		Profile:   "release",
	})
	if err != nil {
		t.Fatalf("scan 2 error: %v", err)
	}

	if rep2.Outcome != evidence.OutcomeCleared {
		t.Logf("rep1 FP: %s, rep2 FP: %s", fp, rep2.Findings[0].Fingerprint); t.Logf("Finding: %+v", rep2.Findings[0]); t.Fatalf("Expected Cleared, got %s. Reason: %s", rep2.Outcome, rep2.Reason)
	}

	_, rep3, err := ClearanceReport(ctx, nil, ClearanceReportArgs{TargetDir: tmpDir})
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if rep3.Outcome != evidence.OutcomeCleared {
		t.Fatalf("Expected reported outcome Cleared, got %s", rep3.Outcome)
	}
	
	// Test regression probe: The agent MUST NOT launder its reviewer type
	// the `RecordReview` forces it to be `agent`. Let's verify it actually wrote `agent`.
	st, _ := store.New(filepath.Join(tmpDir, ".clearance"))
	reviews, _ := st.GetReviews()
	rev, ok := reviews[fp]
	if !ok {
	    t.Fatalf("Review missing for %s", fp)
	}
	if string(rev.ReviewerType) != "agent" {
	    t.Fatalf("ReviewerType was %s, expected agent - laundering occurred!", rev.ReviewerType)
	}
}
