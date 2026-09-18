package policy

import (
	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Config models the clearance.yaml configuration file.
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
	Adapters   []string `json:"adapters" yaml:"adapters"`
	Commands   []string `json:"commands" yaml:"commands"`
	AllowDirty bool     `json:"allow_dirty" yaml:"allow_dirty"`
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
				Adapters:   []string{"gitleaks", "osv-scanner"},
				Commands:   []string{},
				AllowDirty: true,
			},
			Full: ScopeRule{
				Adapters:   []string{"gitleaks", "osv-scanner"},
				Commands:   []string{},
				AllowDirty: false,
			},
			Release: ScopeRule{
				Adapters:   []string{"gitleaks", "osv-scanner"},
				Commands:   []string{},
				AllowDirty: false,
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
