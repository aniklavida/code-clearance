package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
)

// ParseCommand parses and strictly validates a repository-defined command string
// from clearance.yaml.
//
// Invariants enforced:
//  1. Untrusted commands NEVER become shell execution. No sh -c, no shell interpolation.
//  2. Newline injection is rejected.
//  3. Executable names with a leading '-' (flag injection) are rejected.
//  4. Executable paths traversing outside the repository are rejected.
//  5. Hostile argument values (; rm -rf /, $(whoami), backticks) are preserved as inert
//     argv elements without evaluation.
func ParseCommand(rawCommand string, repoDir string) (string, []string, error) {
	trimmed := strings.TrimSpace(rawCommand)
	if trimmed == "" {
		return "", nil, errors.New("empty command")
	}

	// 1. Reject newline injection
	if strings.ContainsAny(rawCommand, "\r\n") {
		return "", nil, errors.New("command contains newline injection")
	}

	// 2. Parse command string into tokens without shell expansion
	tokens, err := tokenizeArguments(rawCommand)
	if err != nil {
		return "", nil, fmt.Errorf("parse arguments: %w", err)
	}
	if len(tokens) == 0 {
		return "", nil, errors.New("no command tokens")
	}

	cmdName := tokens[0]

	// 3. Reject leading '-' that could be read as a flag
	if strings.HasPrefix(cmdName, "-") {
		return "", nil, errors.New("command name cannot start with '-' (flag injection rejected)")
	}

	// 4. Reject shell invocation flags (no sh -c)
	baseName := strings.ToLower(filepath.Base(cmdName))
	if isShellBinary(baseName) {
		for _, arg := range tokens[1:] {
			lower := strings.ToLower(arg)
			if lower == "-c" || lower == "/c" || lower == "-command" {
				return "", nil, errors.New("arbitrary shell execution forbidden (no sh -c)")
			}
		}
	}

	// 5. Check path traversal
	if strings.ContainsAny(cmdName, "/\\") {
		absRepo, err := filepath.Abs(repoDir)
		if err != nil {
			absRepo = repoDir
		}
		var fullPath string
		if filepath.IsAbs(cmdName) {
			fullPath = filepath.Clean(cmdName)
		} else {
			fullPath = filepath.Clean(filepath.Join(absRepo, cmdName))
		}

		rel, err := filepath.Rel(absRepo, fullPath)
		if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
			return "", nil, errors.New("command path traverses outside repository")
		}
	}

	// 6. Reject metacharacters in the executable name itself
	if strings.ContainsAny(cmdName, ";|&><$#`") {
		return "", nil, errors.New("invalid executable name")
	}

	return cmdName, tokens[1:], nil
}

func isShellBinary(base string) bool {
	switch strings.TrimSuffix(base, ".exe") {
	case "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}

// tokenizeArguments splits a command line string into argv elements without
// shell interpolation. Single and double quotes are supported for grouping
// arguments, but variable expansions ($VAR, $(cmd), `cmd`) remain inert literals.
func tokenizeArguments(s string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inQuotes := false
	quoteChar := rune(0)

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if inQuotes {
			if r == quoteChar {
				inQuotes = false
				quoteChar = 0
			} else {
				current.WriteRune(r)
			}
		} else {
			if r == '\'' || r == '"' {
				inQuotes = true
				quoteChar = r
			} else if unicode.IsSpace(r) {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
		}
	}

	if inQuotes {
		return nil, errors.New("unclosed quote in command")
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}

// RunRepositoryCommand executes one repository-defined command safely.
func RunRepositoryCommand(ctx context.Context, cmdRule policy.CommandRule, repoDir string) (evidence.RunOutcome, []byte, error) {
	toolName := "command:" + cmdRule.Name
	cmd, args, err := ParseCommand(cmdRule.Run, repoDir)
	if err != nil {
		outcome := evidence.RunOutcome{
			Tool:        toolName,
			ToolVersion: "repository-rule",
			Command:     cmdRule.Run,
			ExitCode:    -1,
			Status:      evidence.StatusCrashed,
			StderrTail:  err.Error(),
		}
		return outcome, nil, err
	}

	timeout := time.Duration(cmdRule.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	res := Run(ctx, Spec{
		Name:    toolName,
		Command: cmd,
		Args:    args,
		Dir:     repoDir,
		Timeout: timeout,
	})

	outcome := evidence.RunOutcome{
		Tool:        toolName,
		ToolVersion: "repository-rule",
		Command:     cmdRule.Run,
		ExitCode:    res.ExitCode,
		Duration:    res.Duration.String(),
		StderrTail:  tailBytes(res.Stderr, 10),
		Findings:    []evidence.Finding{},
	}

	switch {
	case res.TimedOut:
		outcome.Status = evidence.StatusTimedOut
	case res.Killed:
		outcome.Status = evidence.StatusUnavailable
	case res.Err != nil || (res.ExitCode != 0):
		outcome.Status = evidence.StatusCrashed
	default:
		outcome.Status = evidence.StatusOK
	}

	return outcome, res.Stdout, nil
}

func tailBytes(b []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
