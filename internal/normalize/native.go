package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// IngestNativeJSON parses native JSON output for tools whose SARIF output
// is lossy or absent, validating tool versions and returning normalized findings.
func IngestNativeJSON(toolName, toolVersion string, data []byte) ([]evidence.Finding, error) {
	if err := ValidateToolVersion(toolName, toolVersion); err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("%s: malformed native JSON: empty input", toolName)
	}

	switch strings.ToLower(toolName) {
	case "semgrep", "semgrep-ce":
		return parseSemgrepNative(toolName, toolVersion, data)
	case "gitleaks":
		return parseGitleaksNative(toolName, toolVersion, data)
	case "osv-scanner":
		return parseOSVScannerNative(toolName, toolVersion, data)
	case "trivy":
		return parseTrivyNative(toolName, toolVersion, data)
	default:
		return nil, fmt.Errorf("tool %s: unsupported tool for native JSON ingestion", toolName)
	}
}

// Semgrep native JSON types
type semgrepOutput struct {
	Version string          `json:"version"`
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Lines    string `json:"lines"`
}

func parseSemgrepNative(toolName, toolVersion string, data []byte) ([]evidence.Finding, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("semgrep: malformed native JSON: %w", err)
	}
	if _, ok := raw["results"]; !ok {
		return nil, fmt.Errorf("semgrep: malformed native JSON: missing results array")
	}

	var out semgrepOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("semgrep: malformed native JSON: %w", err)
	}

	var findings []evidence.Finding
	seen := map[string]bool{}

	for i, res := range out.Results {
		nativeSev := res.Extra.Severity
		if nativeSev == "" {
			nativeSev = "WARNING"
		}

		normSev := evidence.SeverityMedium
		switch strings.ToUpper(nativeSev) {
		case "ERROR", "CRITICAL":
			normSev = evidence.SeverityHigh
		case "WARNING":
			normSev = evidence.SeverityMedium
		case "INFO", "LOW":
			normSev = evidence.SeverityLow
		}

		startLine := res.Start.Line
		startCol := res.Start.Col
		endLine := res.End.Line
		endCol := res.End.Col

		loc := evidence.Location{
			URI:         res.Path,
			StartLine:   &startLine,
			StartColumn: &startCol,
			EndLine:     &endLine,
			EndColumn:   &endCol,
			Snippet:     res.Extra.Lines,
		}
		if res.Extra.Lines != "" {
			h := sha256.Sum256([]byte(res.Extra.Lines))
			loc.SnippetHash = hex.EncodeToString(h[:])
		}

		f := evidence.Finding{
			Tool:               toolName,
			ToolVersion:        toolVersion,
			RuleID:             res.CheckID,
			NativeSeverity:     nativeSev,
			NormalizedSeverity: normSev,
			Locations:          []evidence.Location{loc},
			Scope: evidence.FindingScope{
				Commit: "HEAD",
				Path:   res.Path,
			},
			SnippetHash: loc.SnippetHash,
			Message:     res.Extra.Message,
			Evidence: evidence.FindingEvidence{
				Details: res.Extra.Message,
				Snippet: res.Extra.Lines,
			},
			Remediation: evidence.Remediation{
				Recommendation: fmt.Sprintf("Review Semgrep rule %s and apply recommended fix", res.CheckID),
			},
			Confidence: evidence.Confidence{
				Level:     evidence.ConfidenceHigh,
				Rationale: fmt.Sprintf("Semgrep AST rule match for %s", res.CheckID),
			},
			ChallengeStatus:     evidence.ChallengeUnreviewed,
			Reviewer:            evidence.Reviewer{Type: evidence.ReviewerTool, Identity: toolName},
			RelatedFindingIDs:   []string{},
			DuplicateFindingIDs: []string{},
			VerificationRuns:    []evidence.VerificationRun{},
			Disposition:         "open",
			Timestamps:          evidence.FindingTimestamps{DetectedAt: "2026-09-17T12:00:00Z"},
			RawArtifact: evidence.ArtifactReference{
				URI:    fmt.Sprintf("json://%s/results.json", toolName),
				Format: "json",
				Index:  i,
			},
			RawIndex: i,
		}

		RedactFinding(&f)
		f.ID = fingerprint(f)
		f.Fingerprint = f.ID

		if !seen[f.ID] {
			seen[f.ID] = true
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// Gitleaks native JSON types
type gitleaksResult struct {
	Description string  `json:"Description"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	StartColumn int     `json:"StartColumn"`
	EndColumn   int     `json:"EndColumn"`
	Match       string  `json:"Match"`
	Secret      string  `json:"Secret"`
	File        string  `json:"File"`
	RuleID      string  `json:"RuleID"`
	Entropy     float64 `json:"Entropy"`
}

func parseGitleaksNative(toolName, toolVersion string, data []byte) ([]evidence.Finding, error) {
	var items []gitleaksResult
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("gitleaks: malformed native JSON: expected array of findings: %w", err)
	}

	var findings []evidence.Finding
	seen := map[string]bool{}

	for i, item := range items {
		startLine := item.StartLine
		startCol := item.StartColumn
		endLine := item.EndLine
		endCol := item.EndColumn

		loc := evidence.Location{
			URI:         item.File,
			StartLine:   &startLine,
			StartColumn: &startCol,
			EndLine:     &endLine,
			EndColumn:   &endCol,
			Snippet:     item.Match,
		}
		if item.Match != "" {
			h := sha256.Sum256([]byte(item.Match))
			loc.SnippetHash = hex.EncodeToString(h[:])
		}

		f := evidence.Finding{
			Tool:               toolName,
			ToolVersion:        toolVersion,
			RuleID:             item.RuleID,
			NativeSeverity:     "CRITICAL",
			NormalizedSeverity: evidence.SeverityCritical,
			Locations:          []evidence.Location{loc},
			Scope: evidence.FindingScope{
				Commit: "HEAD",
				Path:   item.File,
			},
			SnippetHash: loc.SnippetHash,
			Message:     item.Description,
			Evidence: evidence.FindingEvidence{
				Details: fmt.Sprintf("Gitleaks secret detection rule %s (entropy: %.2f)", item.RuleID, item.Entropy),
				Snippet: item.Match,
				Match:   item.Secret,
			},
			Remediation: evidence.Remediation{
				Recommendation: fmt.Sprintf("Revoke exposed secret and purge from history: %s", item.RuleID),
			},
			Confidence: evidence.Confidence{
				Level:     evidence.ConfidenceHigh,
				Rationale: fmt.Sprintf("Gitleaks regex pattern match for secret type %s with entropy %.2f", item.RuleID, item.Entropy),
			},
			ChallengeStatus:     evidence.ChallengeUnreviewed,
			Reviewer:            evidence.Reviewer{Type: evidence.ReviewerTool, Identity: toolName},
			RelatedFindingIDs:   []string{},
			DuplicateFindingIDs: []string{},
			VerificationRuns:    []evidence.VerificationRun{},
			Disposition:         "open",
			Timestamps:          evidence.FindingTimestamps{DetectedAt: "2026-09-17T12:00:00Z"},
			RawArtifact: evidence.ArtifactReference{
				URI:    fmt.Sprintf("json://%s/results.json", toolName),
				Format: "json",
				Index:  i,
			},
			RawIndex: i,
		}

		RedactFinding(&f)
		f.ID = fingerprint(f)
		f.Fingerprint = f.ID

		if !seen[f.ID] {
			seen[f.ID] = true
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// OSV-Scanner native JSON types
type osvOutput struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPackage struct {
	Package         osvPkgInfo `json:"package"`
	Vulnerabilities []osvVuln  `json:"vulnerabilities"`
}

type osvPkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVuln struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

func parseOSVScannerNative(toolName, toolVersion string, data []byte) ([]evidence.Finding, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("osv-scanner: malformed native JSON: %w", err)
	}
	if _, ok := raw["results"]; !ok {
		return nil, fmt.Errorf("osv-scanner: malformed native JSON: missing results array")
	}

	var out osvOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("osv-scanner: malformed native JSON: %w", err)
	}

	var findings []evidence.Finding
	seen := map[string]bool{}
	rawIdx := 0

	for _, res := range out.Results {
		srcPath := res.Source.Path
		if srcPath == "" {
			srcPath = "package-lock.json"
		}

		for _, pkg := range res.Packages {
			pkgDesc := fmt.Sprintf("%s@%s", pkg.Package.Name, pkg.Package.Version)
			for _, vuln := range pkg.Vulnerabilities {
				nativeSev := "MODERATE"
				if vuln.DatabaseSpecific != nil {
					if s, ok := vuln.DatabaseSpecific["severity"].(string); ok && s != "" {
						nativeSev = s
					}
				}

				normSev := evidence.SeverityMedium
				switch strings.ToUpper(nativeSev) {
				case "CRITICAL":
					normSev = evidence.SeverityCritical
				case "HIGH":
					normSev = evidence.SeverityHigh
				case "MODERATE", "MEDIUM":
					normSev = evidence.SeverityMedium
				case "LOW":
					normSev = evidence.SeverityLow
				}

				msg := vuln.Summary
				if msg == "" {
					msg = fmt.Sprintf("Vulnerability %s in %s", vuln.ID, pkgDesc)
				}

				loc := evidence.Location{
					URI: srcPath,
				}

				f := evidence.Finding{
					Tool:               toolName,
					ToolVersion:        toolVersion,
					RuleID:             vuln.ID,
					NativeSeverity:     nativeSev,
					NormalizedSeverity: normSev,
					Locations:          []evidence.Location{loc},
					Scope: evidence.FindingScope{
						Commit: "HEAD",
						Path:   srcPath,
					},
					Message: msg,
					Evidence: evidence.FindingEvidence{
						Details: fmt.Sprintf("%s affecting %s", vuln.ID, pkgDesc),
						Match:   pkgDesc,
					},
					Remediation: evidence.Remediation{
						Recommendation: fmt.Sprintf("Update %s to a non-vulnerable version", pkg.Package.Name),
					},
					Confidence: evidence.Confidence{
						Level:     evidence.ConfidenceHigh,
						Rationale: fmt.Sprintf("Direct package match in lockfile confirmed by OSV database entry for %s", pkgDesc),
					},
					ChallengeStatus:     evidence.ChallengeUnreviewed,
					Reviewer:            evidence.Reviewer{Type: evidence.ReviewerTool, Identity: toolName},
					RelatedFindingIDs:   vuln.Aliases,
					DuplicateFindingIDs: []string{},
					VerificationRuns:    []evidence.VerificationRun{},
					Disposition:         "open",
					Timestamps:          evidence.FindingTimestamps{DetectedAt: "2026-09-17T12:00:00Z"},
					RawArtifact: evidence.ArtifactReference{
						URI:    fmt.Sprintf("json://%s/results.json", toolName),
						Format: "json",
						Index:  rawIdx,
					},
					RawIndex: rawIdx,
				}
				rawIdx++

				RedactFinding(&f)
				f.ID = fingerprint(f)
				f.Fingerprint = f.ID

				if !seen[f.ID] {
					seen[f.ID] = true
					findings = append(findings, f)
				}
			}
		}
	}

	return findings, nil
}

// Trivy native JSON types
type trivyOutput struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	Severity         string `json:"Severity"`
	PrimaryURL       string `json:"PrimaryURL"`
}

func parseTrivyNative(toolName, toolVersion string, data []byte) ([]evidence.Finding, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("trivy: malformed native JSON: %w", err)
	}
	if _, ok := raw["Results"]; !ok {
		return nil, fmt.Errorf("trivy: malformed native JSON: missing Results array")
	}

	var out trivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("trivy: malformed native JSON: %w", err)
	}

	var findings []evidence.Finding
	seen := map[string]bool{}
	rawIdx := 0

	for _, res := range out.Results {
		for _, v := range res.Vulnerabilities {
			nativeSev := v.Severity
			if nativeSev == "" {
				nativeSev = "UNKNOWN"
			}

			normSev := evidence.SeverityUnknown
			switch strings.ToUpper(nativeSev) {
			case "CRITICAL":
				normSev = evidence.SeverityCritical
			case "HIGH":
				normSev = evidence.SeverityHigh
			case "MEDIUM":
				normSev = evidence.SeverityMedium
			case "LOW":
				normSev = evidence.SeverityLow
			}

			msg := v.Title
			if msg == "" {
				msg = v.Description
			}
			if msg == "" {
				msg = fmt.Sprintf("Vulnerability %s in %s", v.VulnerabilityID, v.PkgName)
			}

			loc := evidence.Location{
				URI: res.Target,
			}

			remedRec := fmt.Sprintf("Review vulnerability %s", v.VulnerabilityID)
			if v.FixedVersion != "" {
				remedRec = fmt.Sprintf("Upgrade %s to version %s or higher", v.PkgName, v.FixedVersion)
			}

			f := evidence.Finding{
				Tool:               toolName,
				ToolVersion:        toolVersion,
				RuleID:             v.VulnerabilityID,
				NativeSeverity:     nativeSev,
				NormalizedSeverity: normSev,
				Locations:          []evidence.Location{loc},
				Scope: evidence.FindingScope{
					Commit: "HEAD",
					Path:   res.Target,
				},
				Message: msg,
				Evidence: evidence.FindingEvidence{
					Details: v.Description,
					Match:   fmt.Sprintf("%s@%s", v.PkgName, v.InstalledVersion),
				},
				Remediation: evidence.Remediation{
					Recommendation:   remedRec,
					DocumentationURL: v.PrimaryURL,
				},
				Confidence: evidence.Confidence{
					Level:     evidence.ConfidenceHigh,
					Rationale: fmt.Sprintf("Trivy dependency scan identified %s in %s", v.VulnerabilityID, v.PkgName),
				},
				ChallengeStatus:     evidence.ChallengeUnreviewed,
				Reviewer:            evidence.Reviewer{Type: evidence.ReviewerTool, Identity: toolName},
				RelatedFindingIDs:   []string{},
				DuplicateFindingIDs: []string{},
				VerificationRuns:    []evidence.VerificationRun{},
				Disposition:         "open",
				Timestamps:          evidence.FindingTimestamps{DetectedAt: "2026-09-17T12:00:00Z"},
				RawArtifact: evidence.ArtifactReference{
					URI:    fmt.Sprintf("json://%s/results.json", toolName),
					Format: "json",
					Index:  rawIdx,
				},
				RawIndex: rawIdx,
			}
			rawIdx++

			RedactFinding(&f)
			f.ID = fingerprint(f)
			f.Fingerprint = f.ID

			if !seen[f.ID] {
				seen[f.ID] = true
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}
