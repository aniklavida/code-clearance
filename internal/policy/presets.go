package policy

import (
	"fmt"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

var PresetNames = []string{"individual", "team", "release"}

func ApplyPreset(cfg Config, name string) (Config, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return cfg, nil
	}
	switch normalized {
	case "individual":
		cfg.Policy.BlockingSeverities = []evidence.Severity{evidence.SeverityCritical, evidence.SeverityHigh}
		cfg.Policy.AllowDirty = true
		cfg.Scopes.Quick.AllowDirty = boolPtr(true)
		cfg.Scopes.Full.AllowDirty = boolPtr(false)
		cfg.Scopes.Release.AllowDirty = boolPtr(false)
	case "team":
		cfg.Policy.BlockingSeverities = []evidence.Severity{evidence.SeverityCritical, evidence.SeverityHigh, evidence.SeverityMedium}
		cfg.Policy.AllowDirty = false
		cfg.Scopes.Quick.AllowDirty = boolPtr(false)
		cfg.Scopes.Full.AllowDirty = boolPtr(false)
		cfg.Scopes.Release.AllowDirty = boolPtr(false)
	case "release":
		cfg.Policy.BlockingSeverities = []evidence.Severity{evidence.SeverityCritical, evidence.SeverityHigh, evidence.SeverityMedium, evidence.SeverityLow}
		cfg.Policy.AllowDirty = false
		cfg.Scopes.Quick.AllowDirty = boolPtr(false)
		cfg.Scopes.Full.AllowDirty = boolPtr(false)
		cfg.Scopes.Release.AllowDirty = boolPtr(false)
	default:
		return Config{}, fmt.Errorf("unknown policy preset %q; choose individual, team, or release", name)
	}
	return cfg, nil
}

func Preset(name string) (Config, error) {
	return ApplyPreset(DefaultConfig(), name)
}
