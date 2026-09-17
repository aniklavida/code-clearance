// Package correlate implements deterministic finding fingerprinting, single-adapter
// deduplication, and cross-tool correlation.
package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Fingerprint computes a deterministic, line-shift stable fingerprint for a finding.
// The fingerprint is invariant across tool executions and small unrelated edits
// (such as inserting or deleting lines elsewhere in the file).
func Fingerprint(f evidence.Finding) string {
	h := sha256.New()
	primaryPath := f.Scope.Path
	if len(f.Locations) > 0 && f.Locations[0].URI != "" {
		primaryPath = f.Locations[0].URI
	}

	// Content anchor: snippet hash, match text, or message
	contentAnchor := f.SnippetHash
	if contentAnchor == "" && len(f.Locations) > 0 {
		contentAnchor = f.Locations[0].SnippetHash
		if contentAnchor == "" && f.Locations[0].Snippet != "" {
			snipHash := sha256.Sum256([]byte(strings.TrimSpace(f.Locations[0].Snippet)))
			contentAnchor = hex.EncodeToString(snipHash[:])
		}
	}
	if contentAnchor == "" && f.Evidence.Snippet != "" {
		snipHash := sha256.Sum256([]byte(strings.TrimSpace(f.Evidence.Snippet)))
		contentAnchor = hex.EncodeToString(snipHash[:])
	}
	if contentAnchor == "" && f.Evidence.Match != "" {
		contentAnchor = strings.TrimSpace(f.Evidence.Match)
	}
	if contentAnchor == "" {
		contentAnchor = strings.TrimSpace(f.Message)
	}

	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00", f.Tool, f.RuleID, primaryPath, contentAnchor)
	sum := h.Sum(nil)
	return strings.ToLower(hex.EncodeToString(sum))[:16]
}
