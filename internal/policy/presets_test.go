package policy

import (
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

func TestNamedPolicyPresetsHaveIncreasingStrictness(t *testing.T) {
	individual, err := Preset("individual")
	if err != nil {
		t.Fatal(err)
	}
	team, err := Preset("team")
	if err != nil {
		t.Fatal(err)
	}
	release, err := Preset("release")
	if err != nil {
		t.Fatal(err)
	}
	if len(individual.Policy.BlockingSeverities) >= len(team.Policy.BlockingSeverities) || len(team.Policy.BlockingSeverities) >= len(release.Policy.BlockingSeverities) {
		t.Fatalf("preset strictness did not increase: individual=%v team=%v release=%v", individual.Policy.BlockingSeverities, team.Policy.BlockingSeverities, release.Policy.BlockingSeverities)
	}
	if !containsSeverity(release.Policy.BlockingSeverities, evidence.SeverityLow) {
		t.Fatal("release preset must block low-severity findings")
	}
	if _, err := Preset("unknown"); err == nil {
		t.Fatal("unknown preset was accepted")
	}
}

func containsSeverity(values []evidence.Severity, want evidence.Severity) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
