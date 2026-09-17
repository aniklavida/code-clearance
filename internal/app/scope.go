package app

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// ScopePlan represents the concrete files and checks resolved for a clearance run.
type ScopePlan struct {
	Scope        string
	Target       evidence.TargetBinding
	FilesChecked []string
	Adapters     []string
	Commands     []policy.CommandRule
	BaseCommit   string
}

// ScopeOptions configures how a scope plan is resolved.
type ScopeOptions struct {
	Scope      string // "quick", "full", or "release"
	BaseCommit string // optional base commit for quick diffs
}

// PlanScope resolves a scan request into an exact set of files and checks,
// binding the result to repository identity, commit SHA, and dirty-tree fingerprint.
func PlanScope(ctx context.Context, targetDir string, opts ScopeOptions, cfg policy.Config) (*ScopePlan, error) {
	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	scope := strings.ToLower(strings.TrimSpace(opts.Scope))
	if scope == "" {
		scope = "quick"
	}

	target := DetectTarget(ctx, absDir)

	var filesChecked []string
	isGit := target.Commit != evidence.NotAGitRepository

	if scope == "full" || scope == "release" {
		filesChecked = resolveFullFiles(ctx, absDir, isGit)
	} else {
		// Quick scope
		filesChecked = resolveQuickFiles(ctx, absDir, isGit, target.Dirty, opts.BaseCommit)
	}

	// Resolve adapters and commands according to scope rules in policy config
	var scopeAdapters []string
	var scopeCommands []policy.CommandRule

	var rule policy.ScopeRule
	switch scope {
	case "full":
		rule = cfg.Scopes.Full
	case "release":
		rule = cfg.Scopes.Release
	default:
		rule = cfg.Scopes.Quick
	}

	if len(rule.Adapters) > 0 {
		scopeAdapters = append(scopeAdapters, rule.Adapters...)
	} else {
		// Fall back to config required and optional adapters
		scopeAdapters = append(scopeAdapters, cfg.Adapters.Required...)
		scopeAdapters = append(scopeAdapters, cfg.Adapters.Optional...)
	}
	sort.Strings(scopeAdapters)
	scopeAdapters = dedupeStrings(scopeAdapters)

	// Map command names from scope rule to CommandRule definitions
	cmdMap := make(map[string]policy.CommandRule)
	for _, c := range cfg.Commands.Required {
		cmdMap[c.Name] = c
	}
	for _, c := range cfg.Commands.Optional {
		cmdMap[c.Name] = c
	}

	for _, cmdName := range rule.Commands {
		if ruleDef, ok := cmdMap[cmdName]; ok {
			scopeCommands = append(scopeCommands, ruleDef)
		}
	}

	return &ScopePlan{
		Scope:        scope,
		Target:       target,
		FilesChecked: filesChecked,
		Adapters:     scopeAdapters,
		Commands:     scopeCommands,
		BaseCommit:   opts.BaseCommit,
	}, nil
}

func resolveQuickFiles(ctx context.Context, targetDir string, isGit bool, isDirty bool, baseCommit string) []string {
	if !isGit {
		return walkDirectoryFiles(targetDir)
	}

	topRes := Run(ctx, Spec{
		Name:    "git-toplevel",
		Command: "git",
		Args:    []string{"rev-parse", "--show-toplevel"},
		Dir:     targetDir,
		Timeout: gitTimeout,
	})
	topLevel := strings.TrimSpace(string(topRes.Stdout))
	if topLevel == "" {
		topLevel = targetDir
	}

	fileSet := make(map[string]bool)

	if isDirty {
		// Dirty tree: query git status --porcelain=v1 -uall
		statusRes := Run(ctx, Spec{
			Name:    "git-status-quick",
			Command: "git",
			Args:    []string{"status", "--porcelain=v1", "-uall"},
			Dir:     topLevel,
			Timeout: gitTimeout,
		})
		if statusRes.ExitCode == 0 {
			lines := strings.Split(strings.ReplaceAll(string(statusRes.Stdout), "\r\n", "\n"), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if len(l) < 3 {
					continue
				}
				pathPart := strings.TrimSpace(l[2:])
				// In renames (R  old -> new), pick new
				if idx := strings.Index(pathPart, " -> "); idx != -1 {
					pathPart = pathPart[idx+4:]
				}
				pathPart = strings.Trim(pathPart, "\"")
				if pathPart != "" {
					fileSet[pathPart] = true
				}
			}
		}
	} else if baseCommit != "" {
		// Clean tree with explicit base commit diff
		diffRes := Run(ctx, Spec{
			Name:    "git-diff-base",
			Command: "git",
			Args:    []string{"diff", "--name-only", baseCommit},
			Dir:     topLevel,
			Timeout: gitTimeout,
		})
		if diffRes.ExitCode == 0 {
			lines := strings.Split(strings.ReplaceAll(string(diffRes.Stdout), "\r\n", "\n"), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" {
					fileSet[l] = true
				}
			}
		}
	} else {
		// Clean tree without explicit base: diff HEAD~1 if present
		parentRes := Run(ctx, Spec{
			Name:    "git-rev-parse-head-parent",
			Command: "git",
			Args:    []string{"rev-parse", "--verify", "HEAD~1"},
			Dir:     topLevel,
			Timeout: gitTimeout,
		})
		if parentRes.ExitCode == 0 {
			diffRes := Run(ctx, Spec{
				Name:    "git-diff-head-parent",
				Command: "git",
				Args:    []string{"diff", "--name-only", "HEAD~1", "HEAD"},
				Dir:     topLevel,
				Timeout: gitTimeout,
			})
			if diffRes.ExitCode == 0 {
				lines := strings.Split(strings.ReplaceAll(string(diffRes.Stdout), "\r\n", "\n"), "\n")
				for _, l := range lines {
					l = strings.TrimSpace(l)
					if l != "" {
						fileSet[l] = true
					}
				}
			}
		} else {
			// Initial commit with no parent
			lsRes := Run(ctx, Spec{
				Name:    "git-ls-tree-head",
				Command: "git",
				Args:    []string{"ls-tree", "-r", "--name-only", "HEAD"},
				Dir:     topLevel,
				Timeout: gitTimeout,
			})
			if lsRes.ExitCode == 0 {
				lines := strings.Split(strings.ReplaceAll(string(lsRes.Stdout), "\r\n", "\n"), "\n")
				for _, l := range lines {
					l = strings.TrimSpace(l)
					if l != "" {
						fileSet[l] = true
					}
				}
			}
		}
	}

	var files []string
	for f := range fileSet {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

func resolveFullFiles(ctx context.Context, targetDir string, isGit bool) []string {
	if !isGit {
		return walkDirectoryFiles(targetDir)
	}

	topRes := Run(ctx, Spec{
		Name:    "git-toplevel",
		Command: "git",
		Args:    []string{"rev-parse", "--show-toplevel"},
		Dir:     targetDir,
		Timeout: gitTimeout,
	})
	topLevel := strings.TrimSpace(string(topRes.Stdout))
	if topLevel == "" {
		topLevel = targetDir
	}

	fileSet := make(map[string]bool)

	// Tracked files
	lsRes := Run(ctx, Spec{
		Name:    "git-ls-files",
		Command: "git",
		Args:    []string{"ls-files"},
		Dir:     topLevel,
		Timeout: gitTimeout,
	})
	if lsRes.ExitCode == 0 {
		for _, l := range strings.Split(strings.ReplaceAll(string(lsRes.Stdout), "\r\n", "\n"), "\n") {
			l = strings.TrimSpace(l)
			if l != "" {
				fileSet[l] = true
			}
		}
	}

	// Untracked (not ignored) files
	othersRes := Run(ctx, Spec{
		Name:    "git-ls-others",
		Command: "git",
		Args:    []string{"ls-files", "--others", "--exclude-standard"},
		Dir:     topLevel,
		Timeout: gitTimeout,
	})
	if othersRes.ExitCode == 0 {
		for _, l := range strings.Split(strings.ReplaceAll(string(othersRes.Stdout), "\r\n", "\n"), "\n") {
			l = strings.TrimSpace(l)
			if l != "" {
				fileSet[l] = true
			}
		}
	}

	var files []string
	for f := range fileSet {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

func walkDirectoryFiles(dir string) []string {
	var files []string
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() {
			name := fi.Name()
			if name == ".git" || name == ".clearance" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err == nil && rel != "." {
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(files)
	return files
}

func dedupeStrings(in []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
