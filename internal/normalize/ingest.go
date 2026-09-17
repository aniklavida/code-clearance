package normalize

import (
	"fmt"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// IngestSARIF validates the tool version, parses a SARIF 2.1.0 document,
// normalizes findings with tool-appropriate severity mapping, and redacts secrets.
func IngestSARIF(toolName, toolVersion string, data []byte) ([]evidence.Finding, error) {
	if err := ValidateToolVersion(toolName, toolVersion); err != nil {
		return nil, err
	}

	log, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: malformed sarif: %w", toolName, err)
	}

	var sevRule SeverityRule
	switch strings.ToLower(toolName) {
	case "gitleaks":
		sevRule = GitleaksSeverity
	case "osv-scanner":
		sevRule = OSVScannerSeverity
	case "semgrep", "semgrep-ce":
		sevRule = SemgrepSeverity
	case "trivy":
		sevRule = TrivySeverity
	default:
		sevRule = func(_ string, res Result, _ map[string]Rule) evidence.Severity {
			switch strings.ToLower(res.Level) {
			case "error":
				return evidence.SeverityHigh
			case "warning":
				return evidence.SeverityMedium
			case "note":
				return evidence.SeverityLow
			default:
				return evidence.SeverityUnknown
			}
		}
	}

	findings := Normalize(toolName, toolVersion, log, sevRule)
	return findings, nil
}

// Ingest ingests either SARIF 2.1.0 or native JSON output based on declared format
// or payload auto-detection, failing loudly on malformed or unsupported inputs.
func Ingest(toolName, toolVersion, format string, data []byte) ([]evidence.Finding, error) {
	if err := ValidateToolVersion(toolName, toolVersion); err != nil {
		return nil, err
	}

	fmtLower := strings.ToLower(strings.TrimSpace(format))
	switch fmtLower {
	case "sarif":
		return IngestSARIF(toolName, toolVersion, data)
	case "json", "native":
		return IngestNativeJSON(toolName, toolVersion, data)
	case "", "auto":
		str := string(data)
		if strings.Contains(str, `"runs"`) && (strings.Contains(str, `"version"`) || strings.Contains(str, `"$schema"`)) {
			return IngestSARIF(toolName, toolVersion, data)
		}
		return IngestNativeJSON(toolName, toolVersion, data)
	default:
		return nil, fmt.Errorf("tool %s: unsupported format %q", toolName, format)
	}
}
