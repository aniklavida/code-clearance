package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

type Baseline struct {
	Version      string   `json:"version"`
	CreatedAt    string   `json:"created_at"`
	Fingerprints []string `json:"fingerprints"`
}

func DefaultPath(targetDir string) string {
	return filepath.Join(targetDir, ".clearance", "baseline.json")
}

func Load(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Version != "v1" {
		return Baseline{}, fmt.Errorf("unsupported baseline version %q", b.Version)
	}
	b.Fingerprints = uniqueSorted(b.Fingerprints)
	return b, nil
}

func Save(path string, fingerprints []string, now time.Time) error {
	fingerprints = uniqueSorted(fingerprints)
	b := Baseline{
		Version:      "v1",
		CreatedAt:    now.UTC().Format(time.RFC3339),
		Fingerprints: fingerprints,
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create baseline directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit baseline: %w", err)
	}
	return nil
}

func FromReport(r evidence.Report) []string {
	values := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Fingerprint != "" {
			values = append(values, f.Fingerprint)
		}
	}
	return uniqueSorted(values)
}

func Digest(fingerprints []string) string {
	values := uniqueSorted(fingerprints)
	h := sha256.New()
	for _, f := range values {
		_, _ = h.Write([]byte(f))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
