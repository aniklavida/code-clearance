package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Config models the clearance.yaml configuration file.
//
// Schema versioning: the configuration contract is versioned by Config.Version
// and by schemas/clearance.schema.json ($id .../v1/clearance.schema.json).
// Any change that breaks an existing consumer MUST bump that version and add a
// migration entry in MigrateConfig and a note in schemas/COMPATIBILITY.md.
// Purely optional additions do not bump the version.
type Config struct {
	Version  string         `json:"version" yaml:"version"`
	Adapters AdaptersConfig `json:"adapters" yaml:"adapters"`
	Paths    PathsConfig    `json:"paths" yaml:"paths"`
	Scopes   ScopesConfig   `json:"scopes" yaml:"scopes"`
	Policy   PolicyRules    `json:"policy" yaml:"policy"`
	Commands CommandsConfig `json:"commands" yaml:"commands"`
	Limits   LimitsConfig   `json:"limits" yaml:"limits"`
	Outcomes OutcomesConfig `json:"outcomes" yaml:"outcomes"`
}

type AdaptersConfig struct {
	Required []string `json:"required" yaml:"required"`
	Optional []string `json:"optional" yaml:"optional"`
}

type PathsConfig struct {
	Include []string `json:"include" yaml:"include"`
	Exclude []string `json:"exclude" yaml:"exclude"`
}

type ScopeRule struct {
	AdaptersRaw json.RawMessage `json:"adapters,omitempty" yaml:"adapters,omitempty"`
	CommandsRaw json.RawMessage `json:"commands,omitempty" yaml:"commands,omitempty"`
	AllowDirty  *bool           `json:"allow_dirty,omitempty" yaml:"allow_dirty,omitempty"`

	// Set by DefaultConfig
	AdaptersLegacy   []string `json:"-" yaml:"-"`
	CommandsLegacy   []string `json:"-" yaml:"-"`
	AllowDirtyLegacy *bool    `json:"-" yaml:"-"`

	Paths    *PathsConfig    `json:"paths,omitempty" yaml:"paths,omitempty"`
	Policy   *PolicyRules    `json:"policy,omitempty" yaml:"policy,omitempty"`
	Limits   *LimitsConfig   `json:"limits,omitempty" yaml:"limits,omitempty"`
	Outcomes *OutcomesConfig `json:"outcomes,omitempty" yaml:"outcomes,omitempty"`
}

type ScopesConfig struct {
	Quick   ScopeRule `json:"quick" yaml:"quick"`
	Full    ScopeRule `json:"full" yaml:"full"`
	Release ScopeRule `json:"release" yaml:"release"`
}

type AcceptedRiskRule struct {
	FindingID string `json:"finding_id,omitempty" yaml:"finding_id,omitempty"`
	RuleID    string `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	Tool      string `json:"tool,omitempty" yaml:"tool,omitempty"`
	Reason    string `json:"reason" yaml:"reason"`
	ExpiresAt string `json:"expires_at" yaml:"expires_at"`
	Owner     string `json:"owner,omitempty" yaml:"owner,omitempty"`
}

type HumanRequiredClass struct {
	RuleID   string            `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	Tool     string            `json:"tool,omitempty" yaml:"tool,omitempty"`
	Severity evidence.Severity `json:"severity,omitempty" yaml:"severity,omitempty"`
}

type PolicyRules struct {
	BlockingSeverities   []evidence.Severity  `json:"blocking_severities" yaml:"blocking_severities"`
	AllowDirty           bool                 `json:"allow_dirty" yaml:"allow_dirty"`
	AcceptedRisks        []AcceptedRiskRule   `json:"accepted_risks" yaml:"accepted_risks"`
	HumanRequiredClasses []HumanRequiredClass `json:"human_required_classes" yaml:"human_required_classes"`
}

type CommandRule struct {
	Name           string `json:"name" yaml:"name"`
	Run            string `json:"run" yaml:"run"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" yaml:"timeout_seconds,omitempty"`
}

type CommandsConfig struct {
	Required []CommandRule `json:"required" yaml:"required"`
	Optional []CommandRule `json:"optional" yaml:"optional"`
	// Allow lists extra executable names a repository command may invoke,
	// beyond the built-in default allowlist. It is additive, never a way to
	// permit shell invocation, and it is an optional field so adding it did
	// not require a schema version bump.
	Allow []string `json:"allow,omitempty" yaml:"allow,omitempty"`
}

type LimitsConfig struct {
	TimeoutSeconds int `json:"timeout_seconds" yaml:"timeout_seconds"`
	MaxConcurrency int `json:"max_concurrency" yaml:"max_concurrency"`
}

type ClearedEvidenceRequirements struct {
	RequiredAdaptersMustPass bool `json:"required_adapters_must_pass" yaml:"required_adapters_must_pass"`
	ZeroBlockingFindings     bool `json:"zero_blocking_findings" yaml:"zero_blocking_findings"`
	CleanTreeRequired        bool `json:"clean_tree_required" yaml:"clean_tree_required"`
}

type ResidualRiskRequirements struct {
	AcceptedRisksUnexpired bool `json:"accepted_risks_unexpired" yaml:"accepted_risks_unexpired"`
}

type BlockedRequirements struct {
	BlockingFindingPresent bool `json:"blocking_finding_present" yaml:"blocking_finding_present"`
}

type IncompleteRequirements struct {
	MissingRequiredAdapter bool `json:"missing_required_adapter" yaml:"missing_required_adapter"`
	CrashedOrTimedOut      bool `json:"crashed_or_timed_out" yaml:"crashed_or_timed_out"`
}

type MinimumEvidence struct {
	Cleared                 ClearedEvidenceRequirements `json:"cleared" yaml:"cleared"`
	ClearedWithResidualRisk ResidualRiskRequirements    `json:"cleared_with_residual_risk" yaml:"cleared_with_residual_risk"`
	Blocked                 BlockedRequirements         `json:"blocked" yaml:"blocked"`
	Incomplete              IncompleteRequirements      `json:"incomplete" yaml:"incomplete"`
}

type OutcomesConfig struct {
	MinimumEvidence MinimumEvidence `json:"minimum_evidence" yaml:"minimum_evidence"`
}

// DefaultConfig returns a strict default configuration where gitleaks is required.
func DefaultConfig() Config {
	return Config{
		Version: "v1",
		Adapters: AdaptersConfig{
			Required: []string{"gitleaks"},
			Optional: []string{"osv-scanner"},
		},
		Paths: PathsConfig{
			Include: []string{"**/*"},
			Exclude: []string{".git/**", "vendor/**", "node_modules/**"},
		},
		Scopes: ScopesConfig{
			Quick: ScopeRule{
				AllowDirtyLegacy: boolPtr(true),
			},
			Full: ScopeRule{
				AllowDirtyLegacy: boolPtr(false),
			},
			Release: ScopeRule{
				AllowDirtyLegacy: boolPtr(false),
			},
		},
		Policy: PolicyRules{
			BlockingSeverities: []evidence.Severity{
				evidence.SeverityCritical,
				evidence.SeverityHigh,
			},
			AllowDirty:           false,
			AcceptedRisks:        []AcceptedRiskRule{},
			HumanRequiredClasses: []HumanRequiredClass{},
		},
		Commands: CommandsConfig{
			Required: []CommandRule{},
			Optional: []CommandRule{},
		},
		Limits: LimitsConfig{
			TimeoutSeconds: 30,
			MaxConcurrency: 4,
		},
		Outcomes: OutcomesConfig{
			MinimumEvidence: MinimumEvidence{
				Cleared: ClearedEvidenceRequirements{
					RequiredAdaptersMustPass: true,
					ZeroBlockingFindings:     true,
					CleanTreeRequired:        true,
				},
				ClearedWithResidualRisk: ResidualRiskRequirements{
					AcceptedRisksUnexpired: true,
				},
				Blocked: BlockedRequirements{
					BlockingFindingPresent: true,
				},
				Incomplete: IncompleteRequirements{
					MissingRequiredAdapter: true,
					CrashedOrTimedOut:      true,
				},
			},
		},
	}
}

func boolPtr(b bool) *bool { return &b }

// Profile represents a fully resolved configuration profile for a specific scope.
type Profile struct {
	Name       string
	Adapters   AdaptersConfig
	Paths      PathsConfig
	Policy     PolicyRules
	Commands   CommandsConfig
	Limits     LimitsConfig
	Outcomes   OutcomesConfig
	AllowDirty bool
}

// ActiveProfile resolves the active profile fields for a given scope,
// falling back to global fields where not set.
func (c Config) ActiveProfile(scopeName string) Profile {
	p := Profile{
		Name:       scopeName,
		Adapters:   c.Adapters,
		Paths:      c.Paths,
		Policy:     c.Policy,
		Commands:   c.Commands,
		Limits:     c.Limits,
		Outcomes:   c.Outcomes,
		AllowDirty: c.Policy.AllowDirty,
	}

	var sr *ScopeRule
	switch scopeName {
	case "quick":
		sr = &c.Scopes.Quick
	case "full":
		sr = &c.Scopes.Full
	case "release":
		sr = &c.Scopes.Release
	}

	if sr == nil {
		return p
	}

	if sr.Paths != nil {
		p.Paths = *sr.Paths
	}
	if sr.Policy != nil {
		p.Policy = *sr.Policy
		// If the profile sets its own Policy, we should also update AllowDirty
		p.AllowDirty = sr.Policy.AllowDirty
	}
	if sr.Limits != nil {
		p.Limits = *sr.Limits
	}
	if sr.Outcomes != nil {
		p.Outcomes = *sr.Outcomes
	}

	if sr.AllowDirty != nil {
		p.AllowDirty = *sr.AllowDirty
	} else if sr.AllowDirtyLegacy != nil {
		p.AllowDirty = *sr.AllowDirtyLegacy
	}

	// Resolve Adapters
	if len(sr.AdaptersRaw) > 0 {
		var arr []string
		if err := json.Unmarshal(sr.AdaptersRaw, &arr); err == nil {
			p.Adapters = AdaptersConfig{Required: arr}
		} else {
			var obj AdaptersConfig
			if err := json.Unmarshal(sr.AdaptersRaw, &obj); err == nil {
				p.Adapters = obj
			}
		}
	} else if len(sr.AdaptersLegacy) > 0 {
		p.Adapters = AdaptersConfig{Required: sr.AdaptersLegacy}
	}

	// Resolve Commands
	if len(sr.CommandsRaw) > 0 {
		var arr []string
		if err := json.Unmarshal(sr.CommandsRaw, &arr); err == nil {
			var rules []CommandRule
			for _, c := range arr {
				rules = append(rules, CommandRule{Name: c, Run: c})
			}
			p.Commands = CommandsConfig{Required: rules}
		} else {
			var obj CommandsConfig
			if err := json.Unmarshal(sr.CommandsRaw, &obj); err == nil {
				p.Commands = obj
			}
		}
	} else if len(sr.CommandsLegacy) > 0 {
		var rules []CommandRule
		for _, c := range sr.CommandsLegacy {
			rules = append(rules, CommandRule{Name: c, Run: c})
		}
		p.Commands = CommandsConfig{Required: rules}
	}

	return p
}

// Load loads a clearance configuration from a JSON file, migrating it to the
// current schema generation first. An unsupported version is rejected with a
// clear message rather than being accepted on a guess.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	migrated, err := MigrateConfig(data)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(migrated, &c); err != nil {
		return Config{}, fmt.Errorf("parse migrated clearance configuration: %w", err)
	}
	return c, nil
}
