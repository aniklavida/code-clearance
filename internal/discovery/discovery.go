// Package discovery inspects the repository to detect language stacks,
// package manifests, lockfiles, and probe which scanner adapters are available.
package discovery

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aniklavida/code-clearance/internal/adapters"
)

// StackInfo describes the detected language stacks and manifest files
// in the target directory.
type StackInfo struct {
	Languages []string `json:"languages"`
	Manifests []string `json:"manifests"`
	Lockfiles []string `json:"lockfiles"`
	HasGit    bool     `json:"has_git"`
}

// AdapterStatus captures the first-class availability probe for a single adapter.
type AdapterStatus struct {
	Name       string              `json:"name"`
	Capability adapters.Capability `json:"capability"`
	Available  bool                `json:"available"`
	Version    string              `json:"version"`
	Path       string              `json:"path,omitempty"`
	Reason     string              `json:"reason"`
	InputScope adapters.InputScope `json:"input_scope"`
}

// DetectStack inspects targetDir for language markers, package manifests,
// and lockfiles.
func DetectStack(targetDir string) StackInfo {
	info := StackInfo{
		Languages: []string{},
		Manifests: []string{},
		Lockfiles: []string{},
	}

	langSet := make(map[string]bool)
	manifestSet := make(map[string]bool)
	lockfileSet := make(map[string]bool)

	// Check for git
	gitDir := filepath.Join(targetDir, ".git")
	if fi, err := os.Stat(gitDir); err == nil && (fi.IsDir() || !fi.IsDir()) {
		info.HasGit = true
	}

	// Walk top 2 levels to detect manifests and languages
	_ = filepath.Walk(targetDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(targetDir, path)
		if err != nil {
			return nil
		}
		if rel == "." {
			return nil
		}

		// Don't descend into VCS or large dependency trees
		if fi.IsDir() {
			base := fi.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".clearance" {
				return filepath.SkipDir
			}
			// Limit depth to 2 levels
			if strings.Count(rel, string(filepath.Separator)) >= 2 {
				return filepath.SkipDir
			}
			return nil
		}

		base := fi.Name()

		// Go
		if base == "go.mod" {
			manifestSet[rel] = true
			langSet["go"] = true
		}
		if base == "go.sum" {
			lockfileSet[rel] = true
			langSet["go"] = true
		}
		if strings.HasSuffix(base, ".go") {
			langSet["go"] = true
		}

		// JavaScript / TypeScript / Node
		if base == "package.json" {
			manifestSet[rel] = true
			langSet["javascript"] = true
		}
		if base == "package-lock.json" || base == "yarn.lock" || base == "pnpm-lock.yaml" {
			lockfileSet[rel] = true
			langSet["javascript"] = true
		}
		if strings.HasSuffix(base, ".ts") || strings.HasSuffix(base, ".tsx") || base == "tsconfig.json" {
			langSet["typescript"] = true
		}
		if strings.HasSuffix(base, ".js") || strings.HasSuffix(base, ".jsx") {
			langSet["javascript"] = true
		}

		// Python
		if base == "requirements.txt" || base == "pyproject.toml" || base == "Pipfile" || base == "setup.py" {
			manifestSet[rel] = true
			langSet["python"] = true
		}
		if base == "poetry.lock" || base == "Pipfile.lock" {
			lockfileSet[rel] = true
			langSet["python"] = true
		}
		if strings.HasSuffix(base, ".py") {
			langSet["python"] = true
		}

		// Rust
		if base == "Cargo.toml" {
			manifestSet[rel] = true
			langSet["rust"] = true
		}
		if base == "Cargo.lock" {
			lockfileSet[rel] = true
			langSet["rust"] = true
		}

		// Container / Docker
		if base == "Dockerfile" || base == "Containerfile" || base == "docker-compose.yml" || base == "compose.yaml" {
			manifestSet[rel] = true
			langSet["container"] = true
		}

		return nil
	})

	for l := range langSet {
		info.Languages = append(info.Languages, l)
	}
	sort.Strings(info.Languages)

	for m := range manifestSet {
		info.Manifests = append(info.Manifests, m)
	}
	sort.Strings(info.Manifests)

	for lf := range lockfileSet {
		info.Lockfiles = append(info.Lockfiles, lf)
	}
	sort.Strings(info.Lockfiles)

	return info
}

// DiscoverAdapters inspects a set of adapters, probing each for its availability,
// version, and executable path. Every adapter yields a first-class result;
// unavailable adapters are recorded with an explicit reason rather than skipped.
func DiscoverAdapters(ctx context.Context, list []adapters.Adapter) []AdapterStatus {
	results := make([]AdapterStatus, 0, len(list))

	for _, a := range list {
		avail := a.Availability(ctx)
		status := AdapterStatus{
			Name:       a.Name(),
			Capability: a.Capability(),
			Available:  avail.Available,
			Version:    a.Version(),
			Path:       avail.Path,
			Reason:     avail.Reason,
			InputScope: a.InputScope(),
		}
		results = append(results, status)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	return results
}
