package action

import (
	"encoding/json"
	"fmt"

	"github.com/aniklavida/code-clearance/internal/normalize"
)

// ValidateSARIF structurally validates a Code Clearance SARIF 2.1.0 export.
//
// No SARIF JSON Schema is vendored in this repository, so this checks the
// fields the 2.1.0 specification marks required for the subset Code Clearance
// emits: log.version, log.runs[], run.tool.driver.name, run.results, and each
// result's message.text, ruleId and physical location. It also round-trips the
// document through the repository's own tolerant SARIF parser, which rejects a
// malformed version or a document with no runs. A structural failure here means
// the export is not safe to hand to a code-scanning consumer.
func ValidateSARIF(data []byte) error {
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(data, &log); err != nil {
		return fmt.Errorf("sarif: invalid JSON: %w", err)
	}
	if log.Version != "2.1.0" {
		return fmt.Errorf("sarif: version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) == 0 {
		return fmt.Errorf("sarif: no runs present")
	}
	for i, run := range log.Runs {
		if run.Tool.Driver.Name == "" {
			return fmt.Errorf("sarif: runs[%d].tool.driver.name is required", i)
		}
		for j, res := range run.Results {
			if res.RuleID == "" {
				return fmt.Errorf("sarif: runs[%d].results[%d].ruleId is required", i, j)
			}
			if res.Message.Text == "" {
				return fmt.Errorf("sarif: runs[%d].results[%d].message.text is required", i, j)
			}
			if len(res.Locations) == 0 {
				return fmt.Errorf("sarif: runs[%d].results[%d].locations is required", i, j)
			}
			for k, loc := range res.Locations {
				if loc.PhysicalLocation.ArtifactLocation.URI == "" {
					return fmt.Errorf("sarif: runs[%d].results[%d].locations[%d] uri is required", i, j, k)
				}
			}
		}
	}

	// The repository's own parser must also accept the document.
	if _, err := normalize.Parse(data); err != nil {
		return fmt.Errorf("sarif: failed parser round-trip: %w", err)
	}
	return nil
}
