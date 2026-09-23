package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aniklavida/code-clearance/internal/adapters"
	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/mcpserver"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/schema"
	"github.com/aniklavida/code-clearance/internal/store"
)

// CheckStatus represents the status of a single diagnostic check.
type CheckStatus string

const (
	StatusCheckPass CheckStatus = "PASS"
	StatusCheckFail CheckStatus = "FAIL"
	StatusCheckWarn CheckStatus = "WARN"
	StatusCheckInfo CheckStatus = "INFO"
)

// CheckResult records the outcome of a single doctor check.
type CheckResult struct {
	Category string      `json:"category"`
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Message  string      `json:"message"`
	Remedy   string      `json:"remedy,omitempty"`
}

// DoctorOptions specifies parameters for code-clearance doctor.
type DoctorOptions struct {
	TargetDir      string
	InstallMissing bool
	Approve        bool
	MCPConfigPath  string
}

// DoctorReport contains all check results and the overall verdict.
type DoctorReport struct {
	TargetDir string        `json:"target_dir"`
	Checks    []CheckResult `json:"checks"`
	Passed    bool          `json:"passed"`
}

// ScannerInstallGuide provides platform-specific install command and documentation URL for scanners.
type ScannerInstallGuide struct {
	Tool        string
	Command     string
	DocsURL     string
	CanAutoExec bool
}

// GetScannerInstallGuide returns installation instructions for a given scanner on the current OS.
func GetScannerInstallGuide(tool string) ScannerInstallGuide {
	lower := strings.ToLower(tool)
	switch lower {
	case "gitleaks":
		switch runtime.GOOS {
		case "darwin":
			return ScannerInstallGuide{
				Tool:        "gitleaks",
				Command:     "brew install gitleaks",
				DocsURL:     "https://github.com/gitleaks/gitleaks",
				CanAutoExec: true,
			}
		case "windows":
			return ScannerInstallGuide{
				Tool:        "gitleaks",
				Command:     "scoop install gitleaks",
				DocsURL:     "https://github.com/gitleaks/gitleaks",
				CanAutoExec: false,
			}
		default:
			return ScannerInstallGuide{
				Tool:        "gitleaks",
				Command:     "go install github.com/zricethezav/gitleaks/v8@latest",
				DocsURL:     "https://github.com/gitleaks/gitleaks",
				CanAutoExec: true,
			}
		}

	case "osv-scanner":
		switch runtime.GOOS {
		case "darwin":
			return ScannerInstallGuide{
				Tool:        "osv-scanner",
				Command:     "brew install osv-scanner",
				DocsURL:     "https://google.github.io/osv-scanner/installation/",
				CanAutoExec: true,
			}
		default:
			return ScannerInstallGuide{
				Tool:        "osv-scanner",
				Command:     "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest",
				DocsURL:     "https://google.github.io/osv-scanner/installation/",
				CanAutoExec: true,
			}
		}

	case "semgrep":
		switch runtime.GOOS {
		case "darwin":
			return ScannerInstallGuide{
				Tool:        "semgrep",
				Command:     "brew install semgrep",
				DocsURL:     "https://semgrep.dev/docs/getting-started/",
				CanAutoExec: true,
			}
		default:
			return ScannerInstallGuide{
				Tool:        "semgrep",
				Command:     "pip install semgrep",
				DocsURL:     "https://semgrep.dev/docs/getting-started/",
				CanAutoExec: true,
			}
		}

	case "trivy":
		switch runtime.GOOS {
		case "darwin":
			return ScannerInstallGuide{
				Tool:        "trivy",
				Command:     "brew install trivy",
				DocsURL:     "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
				CanAutoExec: true,
			}
		default:
			return ScannerInstallGuide{
				Tool:        "trivy",
				Command:     "",
				DocsURL:     "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
				CanAutoExec: false,
			}
		}

	default:
		return ScannerInstallGuide{
			Tool:    tool,
			DocsURL: "https://codeclearance.dev/docs/adapters",
		}
	}
}

// RunDoctor performs self-checks on the engine, verifies all configured adapters
// with real minimal invocations, validates repository commands against the allowlist
// and executes them, and verifies any configured MCP registrations.
func RunDoctor(ctx context.Context, opts DoctorOptions) (DoctorReport, error) {
	targetDir := opts.TargetDir
	if targetDir == "" {
		targetDir = "."
	}

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	var checks []CheckResult

	// 1. Engine Health: Git detection
	if res := app.Run(ctx, app.Spec{
		Name:    "git-check",
		Command: "git",
		Args:    []string{"rev-parse", "--is-inside-work-tree"},
		Dir:     absDir,
		Timeout: 5 * time.Second,
	}); res.Err != nil || res.ExitCode != 0 {
		checks = append(checks, CheckResult{
			Category: "engine",
			Name:     "git",
			Status:   StatusCheckWarn,
			Message:  "target directory is not a git repository",
			Remedy:   "run 'git init' or run clearance inside a git repository to enable commit-bound evidence, then rerun",
		})
	} else {
		checks = append(checks, CheckResult{
			Category: "engine",
			Name:     "git",
			Status:   StatusCheckPass,
			Message:  "git working tree detected",
		})
	}

	// 1b. Engine Health: Store directory access
	storeDir := filepath.Join(absDir, ".clearance")
	st, storeErr := store.New(storeDir)
	if storeErr != nil {
		checks = append(checks, CheckResult{
			Category: "engine",
			Name:     "store",
			Status:   StatusCheckFail,
			Message:  fmt.Sprintf("cannot initialize store directory %s: %v", storeDir, storeErr),
			Remedy:   "ensure the directory is writable, then rerun",
		})
	} else {
		checks = append(checks, CheckResult{
			Category: "engine",
			Name:     "store",
			Status:   StatusCheckPass,
			Message:  fmt.Sprintf("store directory accessible at %s", st.RootDir()),
		})
	}

	// 1c. Engine Health: Schema validation check
	if _, err := schema.FindSchemaPath("clearance.schema.json"); err != nil {
		checks = append(checks, CheckResult{
			Category: "engine",
			Name:     "schemas",
			Status:   StatusCheckWarn,
			Message:  fmt.Sprintf("configuration schema lookup warning: %v", err),
			Remedy:   "set CODE_CLEARANCE_SCHEMAS_DIR or ensure schemas/ directory is present, then rerun",
		})
	} else {
		checks = append(checks, CheckResult{
			Category: "engine",
			Name:     "schemas",
			Status:   StatusCheckPass,
			Message:  "JSON schemas verified",
		})
	}

	// 2. Configuration check
	cfgFile := policy.FindConfigFile(absDir)
	var loadedCfg *policy.Config
	if cfgFile == "" {
		checks = append(checks, CheckResult{
			Category: "configuration",
			Name:     "config-file",
			Status:   StatusCheckWarn,
			Message:  "no clearance.yaml or clearance.json found",
			Remedy:   "run 'code-clearance init --approve' to generate a configuration file, then rerun",
		})
	} else {
		data, readErr := os.ReadFile(cfgFile)
		if readErr != nil {
			checks = append(checks, CheckResult{
				Category: "configuration",
				Name:     filepath.Base(cfgFile),
				Status:   StatusCheckFail,
				Message:  fmt.Sprintf("read configuration file: %v", readErr),
				Remedy:   "ensure the configuration file is readable, then rerun",
			})
		} else {
			if valErr := schema.ValidateClearance(data); valErr != nil {
				checks = append(checks, CheckResult{
					Category: "configuration",
					Name:     filepath.Base(cfgFile),
					Status:   StatusCheckFail,
					Message:  fmt.Sprintf("invalid configuration schema: %v", valErr),
					Remedy:   "fix configuration syntax to match schemas/clearance.schema.json, then rerun",
				})
			} else {
				cfg, loadErr := policy.Load(cfgFile)
				if loadErr != nil {
					checks = append(checks, CheckResult{
						Category: "configuration",
						Name:     filepath.Base(cfgFile),
						Status:   StatusCheckFail,
						Message:  fmt.Sprintf("load configuration: %v", loadErr),
						Remedy:   "fix configuration errors, then rerun",
					})
				} else {
					loadedCfg = &cfg
					checks = append(checks, CheckResult{
						Category: "configuration",
						Name:     filepath.Base(cfgFile),
						Status:   StatusCheckPass,
						Message:  fmt.Sprintf("valid %s configuration (schema %s)", filepath.Base(cfgFile), cfg.Version),
					})
				}
			}
		}
	}

	// 3. Adapter checks (minimal invocation)
	var missingRequiredScanners []string

	requiredAdapters := []string{"gitleaks"}
	var optionalAdapters []string
	if loadedCfg != nil {
		requiredAdapters = loadedCfg.Adapters.Required
		optionalAdapters = loadedCfg.Adapters.Optional
	}

	for _, tool := range requiredAdapters {
		if _, pathErr := exec.LookPath(tool); pathErr != nil {
			guide := GetScannerInstallGuide(tool)
			remedy := fmt.Sprintf("%s not found on PATH; install it or move it to adapters.optional, then rerun", tool)
			if guide.Command != "" {
				remedy += fmt.Sprintf(" (install: '%s', or see %s)", guide.Command, guide.DocsURL)
			} else if guide.DocsURL != "" {
				remedy += fmt.Sprintf(" (docs: %s)", guide.DocsURL)
			}
			checks = append(checks, CheckResult{
				Category: "adapter",
				Name:     tool,
				Status:   StatusCheckFail,
				Message:  fmt.Sprintf("%s executable missing on PATH", tool),
				Remedy:   remedy,
			})
			missingRequiredScanners = append(missingRequiredScanners, tool)
		} else {
			ver, verErr := adapters.DetectToolVersion(ctx, tool)
			if verErr != nil {
				checks = append(checks, CheckResult{
					Category: "adapter",
					Name:     tool,
					Status:   StatusCheckFail,
					Message:  fmt.Sprintf("%s minimal invocation failed: %v", tool, verErr),
					Remedy:   fmt.Sprintf("verify %s installation or move it to adapters.optional, then rerun", tool),
				})
			} else {
				checks = append(checks, CheckResult{
					Category: "adapter",
					Name:     tool,
					Status:   StatusCheckPass,
					Message:  fmt.Sprintf("%s verified (version %s)", tool, ver),
				})
			}
		}
	}

	for _, tool := range optionalAdapters {
		if _, pathErr := exec.LookPath(tool); pathErr != nil {
			guide := GetScannerInstallGuide(tool)
			checks = append(checks, CheckResult{
				Category: "adapter",
				Name:     tool,
				Status:   StatusCheckWarn,
				Message:  fmt.Sprintf("optional scanner %s not found on PATH", tool),
				Remedy:   fmt.Sprintf("install %s to enable optional checks (docs: %s)", tool, guide.DocsURL),
			})
		} else {
			ver, verErr := adapters.DetectToolVersion(ctx, tool)
			if verErr != nil {
				checks = append(checks, CheckResult{
					Category: "adapter",
					Name:     tool,
					Status:   StatusCheckWarn,
					Message:  fmt.Sprintf("optional %s minimal invocation warning: %v", tool, verErr),
				})
			} else {
				checks = append(checks, CheckResult{
					Category: "adapter",
					Name:     tool,
					Status:   StatusCheckPass,
					Message:  fmt.Sprintf("optional %s verified (version %s)", tool, ver),
				})
			}
		}
	}

	// 4. Repository commands check
	if loadedCfg != nil {
		for _, cmdRule := range loadedCfg.Commands.Required {
			bin, _, parseErr := app.ParseCommand(cmdRule.Run, absDir)
			if parseErr != nil {
				checks = append(checks, CheckResult{
					Category: "command",
					Name:     cmdRule.Name,
					Status:   StatusCheckFail,
					Message:  fmt.Sprintf("command %q rejected: %v", cmdRule.Run, parseErr),
					Remedy:   "fix command syntax in clearance.yaml or remove it from clearance commands, then rerun",
				})
				continue
			}

			if !app.CommandAllowed(bin, loadedCfg.Commands.Allow) {
				checks = append(checks, CheckResult{
					Category: "command",
					Name:     cmdRule.Name,
					Status:   StatusCheckFail,
					Message:  fmt.Sprintf("command %q invokes %q which is not on the command allowlist", cmdRule.Run, bin),
					Remedy:   fmt.Sprintf("command %q is not on the command allowlist; review it and add %q to commands.allow, or remove it from clearance commands, then rerun", cmdRule.Run, bin),
				})
				continue
			}

			timeout := 15 * time.Second
			if cmdRule.TimeoutSeconds > 0 && cmdRule.TimeoutSeconds < 15 {
				timeout = time.Duration(cmdRule.TimeoutSeconds) * time.Second
			}
			outcome, _, runErr := app.RunRepositoryCommand(ctx, policy.CommandRule{
				Name:           cmdRule.Name,
				Run:            cmdRule.Run,
				TimeoutSeconds: int(timeout.Seconds()),
			}, absDir)

			if runErr != nil || outcome.Status != evidence.StatusOK {
				checks = append(checks, CheckResult{
					Category: "command",
					Name:     cmdRule.Name,
					Status:   StatusCheckFail,
					Message:  fmt.Sprintf("command %q failed execution (exit code %d, status %s): %s", cmdRule.Run, outcome.ExitCode, outcome.Status, strings.TrimSpace(outcome.StderrTail)),
					Remedy:   fmt.Sprintf("command %q exited with code %d; fix the command in clearance.yaml or ensure dependencies are installed, then rerun", cmdRule.Run, outcome.ExitCode),
				})
			} else {
				checks = append(checks, CheckResult{
					Category: "command",
					Name:     cmdRule.Name,
					Status:   StatusCheckPass,
					Message:  fmt.Sprintf("command %q verified", cmdRule.Run),
				})
			}
		}

		for _, cmdRule := range loadedCfg.Commands.Optional {
			bin, _, parseErr := app.ParseCommand(cmdRule.Run, absDir)
			if parseErr != nil {
				checks = append(checks, CheckResult{
					Category: "command",
					Name:     cmdRule.Name,
					Status:   StatusCheckWarn,
					Message:  fmt.Sprintf("optional command %q rejected: %v", cmdRule.Run, parseErr),
				})
				continue
			}
			if !app.CommandAllowed(bin, loadedCfg.Commands.Allow) {
				checks = append(checks, CheckResult{
					Category: "command",
					Name:     cmdRule.Name,
					Status:   StatusCheckWarn,
					Message:  fmt.Sprintf("optional command %q invokes %q which is not on the command allowlist", cmdRule.Run, bin),
				})
				continue
			}
			checks = append(checks, CheckResult{
				Category: "command",
				Name:     cmdRule.Name,
				Status:   StatusCheckPass,
				Message:  fmt.Sprintf("optional command %q allowlist verified", cmdRule.Run),
			})
		}
	}

	// 5. MCP Registration check
	mcpPath := opts.MCPConfigPath
	if mcpPath == "" {
		localMCP := filepath.Join(absDir, ".mcp.json")
		if _, statErr := os.Stat(localMCP); statErr == nil {
			mcpPath = localMCP
		}
	}

	if mcpPath != "" {
		toolNames, mcpErr := mcpserver.VerifyRegistration(ctx, mcpPath)
		if mcpErr != nil {
			checks = append(checks, CheckResult{
				Category: "mcp",
				Name:     filepath.Base(mcpPath),
				Status:   StatusCheckFail,
				Message:  fmt.Sprintf("unreachable MCP registration at %s: %v", mcpPath, mcpErr),
				Remedy:   fmt.Sprintf("unreachable MCP registration at %s: %v; update host configuration with valid path to code-clearance binary, then rerun", mcpPath, mcpErr),
			})
		} else {
			checks = append(checks, CheckResult{
				Category: "mcp",
				Name:     filepath.Base(mcpPath),
				Status:   StatusCheckPass,
				Message:  fmt.Sprintf("MCP registration verified (%d tools responsive: %s)", len(toolNames), strings.Join(toolNames, ", ")),
			})
		}
	} else {
		checks = append(checks, CheckResult{
			Category: "mcp",
			Name:     "registration",
			Status:   StatusCheckInfo,
			Message:  "no MCP host registration found (.mcp.json)",
			Remedy:   "run 'code-clearance mcp register' to configure Code Clearance in an MCP host, then rerun",
		})
	}

	// 6. Guided installer execution if requested
	if opts.InstallMissing && len(missingRequiredScanners) > 0 {
		if !opts.Approve {
			checks = append(checks, CheckResult{
				Category: "installer",
				Name:     "approval",
				Status:   StatusCheckFail,
				Message:  "--install-missing requires explicit approval before modifying the machine",
				Remedy:   "rerun with 'code-clearance doctor --install-missing --approve' to confirm execution of install commands",
			})
		} else {
			for _, tool := range missingRequiredScanners {
				guide := GetScannerInstallGuide(tool)
				if guide.Command == "" {
					checks = append(checks, CheckResult{
						Category: "installer",
						Name:     tool,
						Status:   StatusCheckWarn,
						Message:  fmt.Sprintf("no automated install command available for %s on %s; install manually from %s", tool, runtime.GOOS, guide.DocsURL),
					})
					continue
				}

				parts := strings.Fields(guide.Command)
				cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
				out, runErr := cmd.CombinedOutput()
				if runErr != nil {
					checks = append(checks, CheckResult{
						Category: "installer",
						Name:     tool,
						Status:   StatusCheckFail,
						Message:  fmt.Sprintf("failed to install %s via %q: %v\n%s", tool, guide.Command, runErr, string(out)),
						Remedy:   fmt.Sprintf("install %s manually following %s, then rerun", tool, guide.DocsURL),
					})
				} else {
					checks = append(checks, CheckResult{
						Category: "installer",
						Name:     tool,
						Status:   StatusCheckPass,
						Message:  fmt.Sprintf("successfully installed %s via %q", tool, guide.Command),
					})
				}
			}
		}
	}

	allPassed := true
	for _, c := range checks {
		if c.Status == StatusCheckFail {
			allPassed = false
			break
		}
	}

	return DoctorReport{
		TargetDir: absDir,
		Checks:    checks,
		Passed:    allPassed,
	}, nil
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	installMissing := fs.Bool("install-missing", false, "attempt guided installation of missing required scanners")
	approve := fs.Bool("approve", false, "approve execution of machine-modifying install commands")
	fs.BoolVar(approve, "y", false, "alias for --approve")
	mcpConfig := fs.String("mcp-config", "", "path to specific MCP host config to verify")
	jsonOut := fs.Bool("json", false, "output report as JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := "."
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	report, err := RunDoctor(ctx, DoctorOptions{
		TargetDir:      targetDir,
		InstallMissing: *installMissing,
		Approve:        *approve,
		MCPConfigPath:  *mcpConfig,
	})
	if err != nil {
		fmt.Fprintf(stderr, "doctor error: %v\n", err)
		return 1
	}

	if *jsonOut {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Fprintln(stdout, string(data))
		if !report.Passed {
			return 1
		}
		return 0
	}

	// Human-readable terminal output
	fmt.Fprintf(stdout, "Code Clearance Doctor — %s\n\n", report.TargetDir)

	failCount := 0
	for _, c := range report.Checks {
		tag := fmt.Sprintf("[%s]", c.Status)
		fmt.Fprintf(stdout, "%-7s %-14s %s\n", tag, c.Category+":"+c.Name, c.Message)
		if c.Remedy != "" && (c.Status == StatusCheckFail || c.Status == StatusCheckWarn) {
			fmt.Fprintf(stdout, "        Remedy: %s\n", c.Remedy)
		}
		if c.Status == StatusCheckFail {
			failCount++
		}
	}

	fmt.Fprintln(stdout)
	if report.Passed {
		fmt.Fprintf(stdout, "All required checks passed. Code Clearance is ready.\n")
		return 0
	}

	fmt.Fprintf(stdout, "Doctor found %d problem(s). Review the remedies above and rerun 'code-clearance doctor'.\n", failCount)
	return 1
}
