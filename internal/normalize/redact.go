package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

var (
	slackTokenPattern   = regexp.MustCompile(`\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b`)
	stripeKeyPattern    = regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b`)
	githubPatPattern    = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,}\b|\bgithub_pat_[0-9a-zA-Z_]{22,}\b`)
	awsKeyPattern       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	privateKeyPattern   = regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----`)
	genericTokenPattern = regexp.MustCompile(`(?i)\b(password|passwd|secret|api_key|apikey|access_key|auth_token|client_secret|bearer)\s*[:=]\s*["']?([^\s"']{8,})["']?`)
)

// RedactSecrets scans a string and replaces any detected secrets or credentials
// with "[REDACTED]".
func RedactSecrets(text string) string {
	if text == "" {
		return ""
	}

	res := slackTokenPattern.ReplaceAllString(text, "[REDACTED]")
	res = stripeKeyPattern.ReplaceAllString(res, "[REDACTED]")
	res = githubPatPattern.ReplaceAllString(res, "[REDACTED]")
	res = awsKeyPattern.ReplaceAllString(res, "[REDACTED]")
	res = privateKeyPattern.ReplaceAllString(res, "[REDACTED]")

	// For key-value patterns, preserve the key name and redact the secret value
	res = genericTokenPattern.ReplaceAllStringFunc(res, func(match string) string {
		sub := genericTokenPattern.FindStringSubmatch(match)
		if len(sub) == 3 {
			key := sub[1]
			return key + " = \"[REDACTED]\""
		}
		return match
	})

	return res
}

// RedactFinding scrubs secrets in-place across all textual evidence fields
// before the finding crosses the normalization boundary.
func RedactFinding(f *evidence.Finding) {
	if f == nil {
		return
	}

	f.Message = RedactSecrets(f.Message)
	f.Evidence.Details = RedactSecrets(f.Evidence.Details)
	f.Evidence.Snippet = RedactSecrets(f.Evidence.Snippet)
	f.Evidence.Context = RedactSecrets(f.Evidence.Context)

	// If Gitleaks or secret scanner identified a match, redact it completely
	if f.Tool == "gitleaks" || f.RuleID == "slack-bot-token" || f.RuleID == "stripe-access-token" {
		if f.Evidence.Match != "" {
			redacted := RedactSecrets(f.Evidence.Match)
			if redacted == f.Evidence.Match && len(f.Evidence.Match) > 6 {
				f.Evidence.Match = "[REDACTED]"
			} else {
				f.Evidence.Match = redacted
			}
		}
	} else if f.Evidence.Match != "" {
		f.Evidence.Match = RedactSecrets(f.Evidence.Match)
	}

	for i := range f.Locations {
		orig := f.Locations[i].Snippet
		if orig != "" {
			redacted := RedactSecrets(orig)
			f.Locations[i].Snippet = redacted
			if f.SnippetHash == "" || orig != redacted {
				h := sha256.Sum256([]byte(redacted))
				f.Locations[i].SnippetHash = hex.EncodeToString(h[:])
				if i == 0 {
					f.SnippetHash = f.Locations[i].SnippetHash
				}
			}
		}
	}

	if len(f.Locations) > 0 && f.Locations[0].Snippet != "" {
		f.Evidence.Snippet = f.Locations[0].Snippet
	}
}
