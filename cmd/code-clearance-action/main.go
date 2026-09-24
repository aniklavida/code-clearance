// Command code-clearance-action is the GitHub Actions transport for Code
// Clearance. It is a thin entry point: it parses action inputs, calls the
// shared internal/action.Run (which itself calls the same internal/app core the
// CLI and MCP server use), emits changed-line annotations and SARIF, and sets a
// policy-derived exit code.
//
// It is deliberately Docker-less and uploads no source code: it reads only the
// checkout it is handed and writes only to the output paths it is given.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aniklavida/code-clearance/internal/action"
	_ "github.com/aniklavida/code-clearance/internal/adapters"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/schema"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("code-clearance-action", flag.ContinueOnError)
	fs.SetOutput(stderr)

	target := fs.String("target", ".", "path to the checkout to analyse")
	scope := fs.String("scope", "quick", "scan scope: quick, full or release")
	configPath := fs.String("config", "", "explicit clearance config path (default: discover in target)")
	diffPath := fs.String("diff", "", "path to a unified diff file to scope annotations to")
	baseRef := fs.String("base-ref", "", "git base ref/sha to diff against when no diff file is given")
	headRef := fs.String("head-ref", "HEAD", "git head ref/sha for the base diff")
	changedOnly := fs.Bool("changed-only", true, "annotate only findings on changed lines")
	sarifOut := fs.String("sarif-out", "code-clearance.sarif", "path to write the SARIF report")
	jsonOut := fs.String("json-out", "", "optional path to write the JSON clearance report")
	summaryOut := fs.String("summary-out", "", "optional path to write the markdown summary (defaults to $GITHUB_STEP_SUMMARY)")
	failOn := fs.String("fail-on", "blocked", "when to fail the step: blocked, any or never")
	allowNetwork := fs.Bool("allow-network", false, "permit network access (default false)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := action.Options{
		TargetDir:    *target,
		Scope:        *scope,
		DiffPath:     *diffPath,
		BaseRef:      *baseRef,
		HeadRef:      *headRef,
		ChangedOnly:  *changedOnly,
		AllowNetwork: *allowNetwork,
	}
	if *configPath != "" {
		loaded, err := loadConfigFile(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "code-clearance-action: %v\n", err)
			return 1
		}
		opts.Config = loaded
	}

	result, err := action.Run(ctx, nil, opts)
	if err != nil {
		fmt.Fprintf(stderr, "code-clearance-action: %v\n", err)
		return 1
	}

	// Annotations first, so they appear on the changed lines even if a later
	// write fails.
	for _, a := range result.Annotations {
		fmt.Fprintln(stdout, a.GitHubCommand())
	}

	if *sarifOut != "" {
		if err := os.WriteFile(*sarifOut, result.SARIF, 0o644); err != nil {
			fmt.Fprintf(stderr, "code-clearance-action: write SARIF: %v\n", err)
			return 1
		}
	}

	if *jsonOut != "" {
		data, err := json.MarshalIndent(result.Report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "code-clearance-action: marshal report: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*jsonOut, data, 0o644); err != nil {
			fmt.Fprintf(stderr, "code-clearance-action: write report: %v\n", err)
			return 1
		}
	}

	writeSummary(*summaryOut, result.Summary)
	writeOutputs(result, *sarifOut, *jsonOut)

	if shouldFail(result.Report.Outcome, *failOn) {
		fmt.Fprintf(stderr, "code-clearance-action: outcome %q (reason: %s)\n", result.Report.Outcome, result.Report.Reason)
		return 1
	}
	return 0
}

// loadConfigFile validates and loads an explicit config path through the same
// schema and policy loader the CLI uses, so an explicit config and a discovered
// one cannot diverge.
func loadConfigFile(path string) (*policy.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := schema.ValidateClearance(data); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	cfg, err := policy.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	return &cfg, nil
}

// writeSummary writes the markdown summary to path, or appends it to
// $GITHUB_STEP_SUMMARY when no path was provided.
func writeSummary(path, summary string) {
	if summary == "" {
		return
	}
	if path == "" {
		path = os.Getenv("GITHUB_STEP_SUMMARY")
	}
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, summary)
}

// writeOutputs publishes step outputs for the composite action when running
// under GitHub Actions.
func writeOutputs(result action.Result, sarifOut, jsonOut string) {
	outPath := os.Getenv("GITHUB_OUTPUT")
	if outPath == "" {
		return
	}
	f, err := os.OpenFile(outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()

	writeOutput(f, "outcome", string(result.Report.Outcome))
	writeOutput(f, "reason", result.Report.Reason)
	writeOutput(f, "sarif-file", sarifOut)
	writeOutput(f, "json-file", jsonOut)
	writeOutput(f, "annotations", fmt.Sprintf("%d", len(result.Annotations)))
}

func writeOutput(f *os.File, key, value string) {
	if strings.ContainsAny(value, "\n\r") {
		fmt.Fprintf(f, "%s<<EOF\n%s\nEOF\n", key, value)
		return
	}
	fmt.Fprintf(f, "%s=%s\n", key, value)
}

// shouldFail maps the policy verdict to a step exit code. An incomplete result
// always fails unless fail-on=never: a green badge earned by a missing tool is
// exactly the failure this product exists to prevent.
func shouldFail(outcome evidence.ClearanceOutcome, failOn string) bool {
	switch outcome {
	case evidence.OutcomeBlocked:
		return failOn != "never"
	case evidence.OutcomeIncomplete:
		return failOn != "never"
	case evidence.OutcomeClearedWithResidualRisk:
		return failOn == "any"
	default:
		return false
	}
}
