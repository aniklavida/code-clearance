package normalize

import (
	"fmt"
	"strconv"
	"strings"
)

// ValidateToolVersion checks whether toolVersion is supported for toolName.
// It fails loudly with an error naming both the tool and the version when unsupported.
func ValidateToolVersion(toolName, toolVersion string) error {
	trimmedVer := strings.TrimSpace(toolVersion)
	if trimmedVer == "" {
		return fmt.Errorf("tool %s: missing tool version", toolName)
	}

	normVer := strings.TrimPrefix(trimmedVer, "v")
	parts := strings.Split(normVer, ".")
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("tool %s: invalid version format %q", toolName, toolVersion)
	}

	switch strings.ToLower(toolName) {
	case "gitleaks":
		if major != 8 {
			return fmt.Errorf("tool gitleaks: unsupported version %q, supported is v8.x", toolVersion)
		}
		return nil

	case "osv-scanner":
		if major < 1 || major > 2 {
			return fmt.Errorf("tool osv-scanner: unsupported version %q, supported is v1.x or v2.x", toolVersion)
		}
		return nil

	case "semgrep", "semgrep-ce":
		if major != 1 {
			return fmt.Errorf("tool semgrep: unsupported version %q, supported is v1.x", toolVersion)
		}
		return nil

	case "trivy":
		if major != 0 {
			return fmt.Errorf("tool trivy: unsupported version %q, supported is v0.x", toolVersion)
		}
		return nil

	default:
		return fmt.Errorf("tool %s: unsupported tool", toolName)
	}
}
