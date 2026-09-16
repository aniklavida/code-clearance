package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

const gitTimeout = 5 * time.Second

// DetectTarget resolves git repository identity, HEAD commit SHA, and
// computes a deterministic dirty-tree fingerprint for targetDir.
//
// If targetDir is not inside a git repository or git is unavailable,
// it explicitly sets the commit, repository, and fingerprint to
// evidence.NotAGitRepository ("not-a-git-repository").
func DetectTarget(ctx context.Context, targetDir string) evidence.TargetBinding {
	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	// 1. Check if targetDir is inside a git working tree.
	checkRes := Run(ctx, Spec{
		Name:    "git-inside-work-tree",
		Command: "git",
		Args:    []string{"rev-parse", "--is-inside-work-tree"},
		Dir:     absDir,
		Timeout: gitTimeout,
	})
	if checkRes.Err != nil || checkRes.ExitCode != 0 || strings.TrimSpace(string(checkRes.Stdout)) != "true" {
		return evidence.TargetBinding{
			Repository:  evidence.NotAGitRepository,
			Commit:      evidence.NotAGitRepository,
			Dirty:       false,
			Fingerprint: evidence.NotAGitRepository,
		}
	}

	// 2. Discover git root to ensure all paths and diffs are relative to repo root.
	topRes := Run(ctx, Spec{
		Name:    "git-toplevel",
		Command: "git",
		Args:    []string{"rev-parse", "--show-toplevel"},
		Dir:     absDir,
		Timeout: gitTimeout,
	})
	if topRes.ExitCode != 0 {
		return evidence.TargetBinding{
			Repository:  evidence.NotAGitRepository,
			Commit:      evidence.NotAGitRepository,
			Dirty:       false,
			Fingerprint: evidence.NotAGitRepository,
		}
	}
	topLevel := strings.TrimSpace(string(topRes.Stdout))

	// 3. Repository identity: remote.origin.url if configured, else directory basename.
	var repoID string
	remoteRes := Run(ctx, Spec{
		Name:    "git-remote-url",
		Command: "git",
		Args:    []string{"config", "--get", "remote.origin.url"},
		Dir:     topLevel,
		Timeout: gitTimeout,
	})
	if remoteRes.ExitCode == 0 {
		repoID = strings.TrimSpace(string(remoteRes.Stdout))
	}
	if repoID == "" {
		repoID = filepath.Base(topLevel)
	}

	// 4. Commit SHA of HEAD.
	commitRes := Run(ctx, Spec{
		Name:    "git-head-commit",
		Command: "git",
		Args:    []string{"rev-parse", "HEAD"},
		Dir:     topLevel,
		Timeout: gitTimeout,
	})
	hasHead := commitRes.ExitCode == 0
	commitSHA := strings.TrimSpace(string(commitRes.Stdout))
	if !hasHead {
		commitSHA = "unborn-head"
	}

	// 5. Check working-tree status with porcelain=v1.
	statusRes := Run(ctx, Spec{
		Name:    "git-status",
		Command: "git",
		Args:    []string{"status", "--porcelain=v1", "-uall"},
		Dir:     topLevel,
		Timeout: gitTimeout,
	})
	if statusRes.ExitCode != 0 {
		return evidence.TargetBinding{
			Repository:  repoID,
			Commit:      commitSHA,
			Dirty:       false,
			Fingerprint: evidence.CleanTreeFingerprint,
		}
	}

	rawStatus := strings.ReplaceAll(string(statusRes.Stdout), "\r\n", "\n")
	var statusLines []string
	for _, l := range strings.Split(rawStatus, "\n") {
		if strings.TrimSpace(l) != "" {
			statusLines = append(statusLines, l)
		}
	}

	if len(statusLines) == 0 {
		return evidence.TargetBinding{
			Repository:  repoID,
			Commit:      commitSHA,
			Dirty:       false,
			Fingerprint: evidence.CleanTreeFingerprint,
		}
	}

	// Working tree is dirty. Compute deterministic SHA-256 fingerprint.
	// Input components:
	// - sorted porcelain status lines
	// - git diff HEAD (for tracked modified and staged changes)
	// - contents of untracked files in sorted relative path order
	sort.Strings(statusLines)

	h := sha256.New()
	for _, line := range statusLines {
		h.Write([]byte(line))
		h.Write([]byte("\n"))
	}

	if hasHead {
		diffRes := Run(ctx, Spec{
			Name:    "git-diff-head",
			Command: "git",
			Args:    []string{"diff", "HEAD"},
			Dir:     topLevel,
			Timeout: gitTimeout,
		})
		if diffRes.ExitCode == 0 {
			normalizedDiff := strings.ReplaceAll(string(diffRes.Stdout), "\r\n", "\n")
			h.Write([]byte("--- git diff HEAD ---\n"))
			h.Write([]byte(normalizedDiff))
		}
	}

	// Process untracked files deterministically.
	var untrackedRelPaths []string
	for _, line := range statusLines {
		if strings.HasPrefix(line, "?? ") {
			rel := strings.TrimSpace(line[3:])
			// Strip optional quotes git adds for paths with special characters
			rel = strings.Trim(rel, "\"")
			untrackedRelPaths = append(untrackedRelPaths, rel)
		}
	}
	sort.Strings(untrackedRelPaths)

	for _, rel := range untrackedRelPaths {
		fullPath := filepath.Join(topLevel, rel)
		data, err := os.ReadFile(fullPath)
		if err == nil {
			h.Write([]byte("untracked:" + rel + "\n"))
			h.Write(data)
			h.Write([]byte("\n"))
		}
	}

	fp := hex.EncodeToString(h.Sum(nil))

	return evidence.TargetBinding{
		Repository:  repoID,
		Commit:      commitSHA,
		Dirty:       true,
		Fingerprint: fp,
	}
}
