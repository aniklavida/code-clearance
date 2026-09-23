package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aniklavida/code-clearance/internal/adapters"
	"github.com/aniklavida/code-clearance/internal/discovery"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/schema"
)

// InitOptions contains options for initializing Code Clearance in a repository.
type InitOptions struct {
	TargetDir string
	Approve   bool
	Force     bool
}

// InitResult records the stack discovery, available adapters, and proposed configuration.
type InitResult struct {
	TargetDir       string
	StackInfo       discovery.StackInfo
	AdapterStatuses []discovery.AdapterStatus
	ProposedConfig  policy.Config
	ProposedYAML    string
	ConfigPath      string
	ConfigWritten   bool
	AlreadyExisted  bool
}

// RunInit detects the repository stack and available scanners, proposes a clearance.yaml
// matching the versioned configuration schema, and writes it only when explicit approval is given.
func RunInit(ctx context.Context, opts InitOptions) (InitResult, error) {
	targetDir := opts.TargetDir
	if targetDir == "" {
		targetDir = "."
	}

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	configPath := filepath.Join(absDir, "clearance.yaml")
	alreadyExisted := false
	if existing := policy.FindConfigFile(absDir); existing != "" {
		alreadyExisted = true
		if !opts.Force && opts.Approve {
			return InitResult{
				TargetDir:      absDir,
				ConfigPath:     existing,
				AlreadyExisted: true,
			}, fmt.Errorf("configuration file %s already exists; use --force to overwrite", filepath.Base(existing))
		}
	}

	// 1. Detect repository stack
	stackInfo := discovery.DetectStack(absDir)

	// 2. Probe available scanner adapters
	adapterStatuses := discovery.DiscoverAdapters(ctx, adapters.DefaultAdapters())

	// 3. Synthesize proposed configuration
	cfg := ProposeConfig(stackInfo, adapterStatuses)

	// 4. Encode to 2-space indented JSON (valid YAML 1.2)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return InitResult{}, fmt.Errorf("marshal proposed configuration: %w", err)
	}

	// 5. Validate against schemas/clearance.schema.json
	if err := schema.ValidateClearance(data); err != nil {
		return InitResult{}, fmt.Errorf("proposed configuration failed schema validation: %w", err)
	}

	yamlStr := string(data) + "\n"

	result := InitResult{
		TargetDir:       absDir,
		StackInfo:       stackInfo,
		AdapterStatuses: adapterStatuses,
		ProposedConfig:  cfg,
		ProposedYAML:    yamlStr,
		ConfigPath:      configPath,
		AlreadyExisted:  alreadyExisted,
	}

	// 6. Write only with explicit approval
	if opts.Approve {
		if err := os.WriteFile(configPath, []byte(yamlStr), 0644); err != nil {
			return result, fmt.Errorf("write %s: %w", configPath, err)
		}
		result.ConfigWritten = true
	}

	return result, nil
}

// ProposeConfig synthesizes a schema-valid policy.Config based on detected stack and adapters.
func ProposeConfig(stack discovery.StackInfo, adapterStatuses []discovery.AdapterStatus) policy.Config {
	availMap := make(map[string]bool)
	for _, a := range adapterStatuses {
		if a.Available {
			availMap[a.Name] = true
		}
	}

	hasLockfiles := len(stack.Lockfiles) > 0 || len(stack.Manifests) > 0
	hasCode := len(stack.Languages) > 0

	var requiredAdapters []string
	var optionalAdapters []string

	// Gitleaks (secrets scanning is universal)
	if availMap["gitleaks"] {
		requiredAdapters = append(requiredAdapters, "gitleaks")
	}

	// OSV-Scanner (dependencies)
	if availMap["osv-scanner"] && hasLockfiles {
		requiredAdapters = append(requiredAdapters, "osv-scanner")
	}

	// Semgrep (static analysis)
	if availMap["semgrep"] && hasCode {
		requiredAdapters = append(requiredAdapters, "semgrep")
	}

	// If no scanners are currently installed, suggest gitleaks as required
	// so doctor can provide guided installation.
	if len(requiredAdapters) == 0 {
		requiredAdapters = append(requiredAdapters, "gitleaks")
	}

	// Place other relevant but uninstalled scanners into optional
	candidateOptional := []string{"osv-scanner", "semgrep", "trivy"}
	for _, name := range candidateOptional {
		if !containsString(requiredAdapters, name) {
			optionalAdapters = append(optionalAdapters, name)
		}
	}

	sort.Strings(requiredAdapters)
	sort.Strings(optionalAdapters)

	// Synthesize repository commands based on stack
	var requiredCommands []policy.CommandRule
	var optionalCommands []policy.CommandRule

	langSet := make(map[string]bool)
	for _, l := range stack.Languages {
		langSet[l] = true
	}

	if langSet["go"] {
		requiredCommands = append(requiredCommands, policy.CommandRule{
			Name:           "test",
			Run:            "go test ./...",
			TimeoutSeconds: 120,
		})
		optionalCommands = append(optionalCommands, policy.CommandRule{
			Name:           "build",
			Run:            "go build ./...",
			TimeoutSeconds: 60,
		})
	} else if langSet["javascript"] || langSet["typescript"] {
		requiredCommands = append(requiredCommands, policy.CommandRule{
			Name:           "test",
			Run:            "npm test",
			TimeoutSeconds: 60,
		})
	} else if langSet["python"] {
		requiredCommands = append(requiredCommands, policy.CommandRule{
			Name:           "test",
			Run:            "pytest",
			TimeoutSeconds: 60,
		})
	} else if langSet["rust"] {
		requiredCommands = append(requiredCommands, policy.CommandRule{
			Name:           "test",
			Run:            "cargo test",
			TimeoutSeconds: 60,
		})
	}

	if requiredCommands == nil {
		requiredCommands = []policy.CommandRule{}
	}
	if optionalCommands == nil {
		optionalCommands = []policy.CommandRule{}
	}

	bTrue := true
	bFalse := false

	return policy.Config{
		Version: policy.CurrentConfigVersion,
		Adapters: policy.AdaptersConfig{
			Required: requiredAdapters,
			Optional: optionalAdapters,
		},
		Paths: policy.PathsConfig{
			Include: []string{"**/*"},
			Exclude: []string{".git/**", "vendor/**", "node_modules/**"},
		},
		Scopes: policy.ScopesConfig{
			Quick: policy.ScopeRule{
				AllowDirty: &bTrue,
			},
			Full: policy.ScopeRule{
				AllowDirty: &bFalse,
			},
			Release: policy.ScopeRule{
				AllowDirty: &bFalse,
			},
		},
		Policy: policy.PolicyRules{
			BlockingSeverities: []evidence.Severity{
				evidence.SeverityCritical,
				evidence.SeverityHigh,
			},
			AllowDirty:           false,
			AcceptedRisks:        []policy.AcceptedRiskRule{},
			HumanRequiredClasses: []policy.HumanRequiredClass{},
		},
		Commands: policy.CommandsConfig{
			Required: requiredCommands,
			Optional: optionalCommands,
		},
		Limits: policy.LimitsConfig{
			TimeoutSeconds: 30,
			MaxConcurrency: 4,
		},
		Outcomes: policy.OutcomesConfig{
			MinimumEvidence: policy.MinimumEvidence{
				Cleared: policy.ClearedEvidenceRequirements{
					RequiredAdaptersMustPass: true,
					ZeroBlockingFindings:     true,
					CleanTreeRequired:        true,
				},
				ClearedWithResidualRisk: policy.ResidualRiskRequirements{
					AcceptedRisksUnexpired: true,
				},
				Blocked: policy.BlockedRequirements{
					BlockingFindingPresent: true,
				},
				Incomplete: policy.IncompleteRequirements{
					MissingRequiredAdapter: true,
					CrashedOrTimedOut:      true,
				},
			},
		},
	}
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func runInit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	approve := fs.Bool("approve", false, "approve and write proposed clearance.yaml")
	fs.BoolVar(approve, "y", false, "alias for --approve")
	force := fs.Bool("force", false, "overwrite existing clearance.yaml if present")
	jsonOut := fs.Bool("json", false, "output result as JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := "."
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	result, err := RunInit(ctx, InitOptions{
		TargetDir: targetDir,
		Approve:   *approve,
		Force:     *force,
	})
	if err != nil {
		fmt.Fprintf(stderr, "init error: %v\n", err)
		return 1
	}

	if *jsonOut {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(stdout, string(data))
		return 0
	}

	// Human-readable output
	fmt.Fprintf(stdout, "Detected repository stack:\n")
	if len(result.StackInfo.Languages) > 0 {
		fmt.Fprintf(stdout, "  Languages: %s\n", strings.Join(result.StackInfo.Languages, ", "))
	} else {
		fmt.Fprintf(stdout, "  Languages: (none detected)\n")
	}
	if len(result.StackInfo.Manifests) > 0 {
		fmt.Fprintf(stdout, "  Manifests: %s\n", strings.Join(result.StackInfo.Manifests, ", "))
	}
	if len(result.StackInfo.Lockfiles) > 0 {
		fmt.Fprintf(stdout, "  Lockfiles: %s\n", strings.Join(result.StackInfo.Lockfiles, ", "))
	}

	fmt.Fprintf(stdout, "\nDetected scanner adapters on host:\n")
	for _, a := range result.AdapterStatuses {
		if a.Available {
			fmt.Fprintf(stdout, "  %s: installed (version %s)\n", a.Name, a.Version)
		} else {
			fmt.Fprintf(stdout, "  %s: missing\n", a.Name)
		}
	}

	if result.ConfigWritten {
		fmt.Fprintf(stdout, "\nSuccessfully wrote %s.\n", filepath.Base(result.ConfigPath))
		fmt.Fprintf(stdout, "Run 'code-clearance doctor' to verify adapters and commands.\n")
	} else {
		fmt.Fprintf(stdout, "\nProposed %s:\n", filepath.Base(result.ConfigPath))
		fmt.Fprintf(stdout, "----------------------------------------\n")
		fmt.Fprintf(stdout, "%s", result.ProposedYAML)
		fmt.Fprintf(stdout, "----------------------------------------\n\n")
		fmt.Fprintf(stdout, "Review the proposed configuration above.\n")
		fmt.Fprintf(stdout, "To write this configuration to %s, rerun with --approve:\n", filepath.Base(result.ConfigPath))
		fmt.Fprintf(stdout, "  code-clearance init --approve\n")
	}

	return 0
}
