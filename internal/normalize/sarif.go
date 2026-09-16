// Package sarifing parses real-world SARIF 2.1.0 output from external
// scanners into the normalized internal evidence model. It only models
// the subset of the SARIF object model actually observed in gitleaks
// v8.30.1 and osv-scanner v2.5.1 output —
// see FOUNDATION_RESULTS.md for the full list of spec fields those tools
// omit or use unusually.
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
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties"`
}

type Result struct {
	RuleID     string         `json:"ruleId"`
	RuleIndex  *int           `json:"ruleIndex"`
	Level      string         `json:"level"`
	Message    Message        `json:"message"`
	Locations  []ResLoc       `json:"locations"`
	Properties map[string]any `json:"properties"`
}

type Message struct {
	Text string `json:"text"`
}

type ResLoc struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   *int     `json:"startLine"`
	StartColumn *int     `json:"startColumn"`
	EndLine     *int     `json:"endLine"`
	EndColumn   *int     `json:"endColumn"`
	Snippet     *Snippet `json:"snippet"`
}

type Snippet struct {
	Text string `json:"text"`
}

// Parse decodes a raw SARIF document. It returns an error for malformed
// JSON or a missing "runs" array, but deliberately tolerates every field
// being absent within a run/result — real tool output omits fields the
// spec makes optional, and ingestion must not treat that as corruption.
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
// given adapter, since the two tools encode severity completely
// differently: gitleaks supplies none at all (a secret finding gets a
// fixed band), osv-scanner supplies a CVSS-like score as a string rule
// property that must be looked up by ruleId and parsed.
type SeverityRule func(toolName string, result Result, ruleByID map[string]Rule) evidence.Severity

// GitleaksSeverity assigns every gitleaks finding a fixed Critical band.
// gitleaks' SARIF output carries no per-rule or per-result severity of any
// kind (verified against real tool output) — a live secret is
// always high-impact regardless of rule, so a fixed band is the honest
// choice rather than inventing a false gradient.
func GitleaksSeverity(_ string, _ Result, _ map[string]Rule) evidence.Severity {
	return evidence.SeverityCritical
}

// OSVScannerSeverity reads the CVSS-like score osv-scanner attaches to the
// *rule* (not the result) as properties["security-severity"], a string
// float, and buckets it into our normalized band. Absence of the property
// yields Unknown rather than a guessed default.
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
// normalization (observed for real in osv-scanner output: the same CVE
// against the same package appeared twice in one run with an otherwise
// identical result object).
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
				Tool:               toolName,
				ToolVersion:        toolVersion,
				RuleID:             res.RuleID,
				Message:            res.Message.Text,
				NativeSeverity:     res.Level,
				NormalizedSeverity: sev(toolName, res, ruleByID),
				RawIndex:           i,
			}

			for _, loc := range res.Locations {
				fl := evidence.Location{
					URI: loc.PhysicalLocation.ArtifactLocation.URI,
				}
				if r := loc.PhysicalLocation.Region; r != nil {
					fl.StartLine = r.StartLine
					fl.StartColumn = r.StartColumn
					fl.EndLine = r.EndLine
					fl.EndColumn = r.EndColumn
					if r.Snippet != nil {
						fl.Snippet = r.Snippet.Text
					}
				}
				f.Locations = append(f.Locations, fl)
			}

			f.ID = fingerprint(f)
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
