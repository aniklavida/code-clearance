// Package normalize parses real-world SARIF 2.1.0 output from external
// scanners into the normalized internal evidence model and exports normalized
// clearance evidence back into SARIF 2.1.0.
package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Log is a minimal SARIF 2.1.0 top-level log object.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	SemanticVer    string `json:"semanticVersion"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Result struct {
	RuleID     string         `json:"ruleId"`
	RuleIndex  *int           `json:"ruleIndex,omitempty"`
	Level      string         `json:"level,omitempty"`
	Message    Message        `json:"message"`
	Locations  []ResLoc       `json:"locations"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type ResLoc struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   *int     `json:"startLine,omitempty"`
	StartColumn *int     `json:"startColumn,omitempty"`
	EndLine     *int     `json:"endLine,omitempty"`
	EndColumn   *int     `json:"endColumn,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

type Snippet struct {
	Text string `json:"text"`
}

// Parse decodes a raw SARIF document. It returns an error for malformed
// JSON or a missing "runs" array, but deliberately tolerates every field
// being absent within a run/result.
func Parse(data []byte) (*Log, error) {
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("sarif: invalid JSON: %w", err)
	}
	if log.Version == "" {
		return nil, fmt.Errorf("sarif: missing version field")
	}
	if len(log.Runs) == 0 {
		return nil, fmt.Errorf("sarif: no runs present")
	}
	return &log, nil
}

// SeverityRule tells Normalize how to derive a normalized severity for a
// given adapter.
type SeverityRule func(toolName string, result Result, ruleByID map[string]Rule) evidence.Severity

// GitleaksSeverity assigns every gitleaks finding a fixed Critical band.
func GitleaksSeverity(_ string, _ Result, _ map[string]Rule) evidence.Severity {
	return evidence.SeverityCritical
}

// OSVScannerSeverity reads the CVSS-like score osv-scanner attaches to the
// rule as properties["security-severity"] and buckets it into our normalized band.
func OSVScannerSeverity(_ string, result Result, ruleByID map[string]Rule) evidence.Severity {
	rule, ok := ruleByID[result.RuleID]
	if !ok {
		return evidence.SeverityUnknown
	}
	raw, ok := rule.Properties["security-severity"]
	if !ok {
		return evidence.SeverityUnknown
	}
	s, ok := raw.(string)
	if !ok {
		return evidence.SeverityUnknown
	}
	score, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return evidence.SeverityUnknown
	}
	switch {
	case score >= 9.0:
		return evidence.SeverityCritical
	case score >= 7.0:
		return evidence.SeverityHigh
	case score >= 4.0:
		return evidence.SeverityMedium
	default:
		return evidence.SeverityLow
	}
}

// Normalize converts every result in every run of a parsed SARIF log into
// evidence.Finding, deduplicating results that are byte-identical after
// normalization.
func Normalize(toolName, toolVersion string, log *Log, sev SeverityRule) []evidence.Finding {
	var out []evidence.Finding
	seen := map[string]bool{}

	for _, run := range log.Runs {
		ruleByID := map[string]Rule{}
		for _, r := range run.Tool.Driver.Rules {
			ruleByID[r.ID] = r
		}

		for i, res := range run.Results {
			f := evidence.Finding{
				Tool:                toolName,
				ToolVersion:         toolVersion,
				RuleID:              res.RuleID,
				Message:             res.Message.Text,
				NativeSeverity:      res.Level,
				NormalizedSeverity:  sev(toolName, res, ruleByID),
				RawIndex:            i,
				RelatedFindingIDs:   []string{},
				DuplicateFindingIDs: []string{},
				VerificationRuns:    []evidence.VerificationRun{},
				Disposition:         "open",
				ChallengeStatus:     evidence.ChallengeUnreviewed,
				Reviewer: evidence.Reviewer{
					Type:     evidence.ReviewerTool,
					Identity: toolName,
				},
				Confidence: evidence.Confidence{
					Level:     evidence.ConfidenceHigh,
					Rationale: fmt.Sprintf("Reported directly by %s scanner", toolName),
				},
				Remediation: evidence.Remediation{
					Recommendation: fmt.Sprintf("Review finding %s and apply recommended remediation", res.RuleID),
				},
				Timestamps: evidence.FindingTimestamps{
					DetectedAt: "2026-09-17T12:00:00Z",
				},
				RawArtifact: evidence.ArtifactReference{
					URI:    fmt.Sprintf("sarif://%s/results.sarif", toolName),
					Format: "sarif",
					Index:  i,
				},
			}

			var primaryPath string
			for _, loc := range res.Locations {
				fl := evidence.Location{
					URI: loc.PhysicalLocation.ArtifactLocation.URI,
				}
				if primaryPath == "" {
					primaryPath = fl.URI
				}
				if r := loc.PhysicalLocation.Region; r != nil {
					fl.StartLine = r.StartLine
					fl.StartColumn = r.StartColumn
					fl.EndLine = r.EndLine
					fl.EndColumn = r.EndColumn
					if r.Snippet != nil {
						fl.Snippet = r.Snippet.Text
						h := sha256.Sum256([]byte(r.Snippet.Text))
						fl.SnippetHash = hex.EncodeToString(h[:])
						if f.SnippetHash == "" {
							f.SnippetHash = fl.SnippetHash
						}
					}
				}
				f.Locations = append(f.Locations, fl)
			}

			if primaryPath == "" {
				primaryPath = "target"
			}
			f.Scope = evidence.FindingScope{
				Commit: "HEAD",
				Path:   primaryPath,
			}
			f.Evidence = evidence.FindingEvidence{
				Details: res.Message.Text,
			}
			if len(f.Locations) > 0 && f.Locations[0].Snippet != "" {
				f.Evidence.Snippet = f.Locations[0].Snippet
			}

			f.ID = fingerprint(f)
			f.Fingerprint = f.ID
			if seen[f.ID] {
				continue // exact duplicate within this run; keep the first
			}
			seen[f.ID] = true
			out = append(out, f)
		}
	}
	return out
}

// fingerprint derives a stable ID from fields that identify "the same
// finding" independent of RawIndex or tool-internal ordering: tool, rule,
// primary location and message. Two byte-identical SARIF results collapse
// to the same fingerprint by design.
func fingerprint(f evidence.Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00", f.Tool, f.RuleID, f.Message)
	for _, loc := range f.Locations {
		fmt.Fprintf(h, "%s\x00", loc.URI)
		if loc.StartLine != nil {
			fmt.Fprintf(h, "%d\x00", *loc.StartLine)
		}
	}
	sum := h.Sum(nil)
	return strings.ToLower(hex.EncodeToString(sum))[:16]
}

// SarifLevel maps normalized severity to SARIF 2.1.0 level strings.
func SarifLevel(sev evidence.Severity) string {
	switch sev {
	case evidence.SeverityCritical, evidence.SeverityHigh:
		return "error"
	case evidence.SeverityMedium:
		return "warning"
	case evidence.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// Export converts a Code Clearance Report into a valid SARIF 2.1.0 Log.
func Export(report evidence.Report) (*Log, error) {
	log := &Log{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []Run{},
	}

	// Group findings by tool if runs are not populated, otherwise process by run
	findingsByTool := map[string][]evidence.Finding{}
	versionByTool := map[string]string{}

	for _, run := range report.Runs {
		toolName := run.Tool
		if toolName == "" {
			toolName = "code-clearance"
		}
		versionByTool[toolName] = run.ToolVersion
		findingsByTool[toolName] = append(findingsByTool[toolName], run.Findings...)
	}

	// Also account for top-level findings if any weren't captured in runs
	for _, f := range report.Findings {
		toolName := f.Tool
		if toolName == "" {
			toolName = "code-clearance"
		}
		if _, ok := versionByTool[toolName]; !ok {
			versionByTool[toolName] = f.ToolVersion
		}
		// Check if already in findingsByTool
		alreadyPresent := false
		for _, existing := range findingsByTool[toolName] {
			if existing.ID == f.ID {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			findingsByTool[toolName] = append(findingsByTool[toolName], f)
		}
	}

	if len(findingsByTool) == 0 {
		// Emit at least one run representing the scan run
		log.Runs = append(log.Runs, Run{
			Tool: Tool{
				Driver: Driver{
					Name:        "code-clearance",
					SemanticVer: "1.0.0",
					Rules:       []Rule{},
				},
			},
			Results: []Result{},
		})
		return log, nil
	}

	for toolName, findings := range findingsByTool {
		toolVer := versionByTool[toolName]
		if toolVer == "" {
			toolVer = "1.0.0"
		}

		rulesMap := map[string]bool{}
		var rules []Rule
		var results []Result

		for _, f := range findings {
			if !rulesMap[f.RuleID] {
				rulesMap[f.RuleID] = true
				rules = append(rules, Rule{ID: f.RuleID})
			}

			res := Result{
				RuleID:  f.RuleID,
				Level:   SarifLevel(f.NormalizedSeverity),
				Message: Message{Text: f.Message},
			}

			for _, loc := range f.Locations {
				resLoc := ResLoc{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{URI: loc.URI},
					},
				}
				if loc.StartLine != nil || loc.Snippet != "" {
					reg := &Region{
						StartLine:   loc.StartLine,
						StartColumn: loc.StartColumn,
						EndLine:     loc.EndLine,
						EndColumn:   loc.EndColumn,
					}
					if loc.Snippet != "" {
						reg.Snippet = &Snippet{Text: loc.Snippet}
					}
					resLoc.PhysicalLocation.Region = reg
				}
				res.Locations = append(res.Locations, resLoc)
			}
			results = append(results, res)
		}

		log.Runs = append(log.Runs, Run{
			Tool: Tool{
				Driver: Driver{
					Name:        toolName,
					SemanticVer: toolVer,
					Rules:       rules,
				},
			},
			Results: results,
		})
	}

	return log, nil
}
