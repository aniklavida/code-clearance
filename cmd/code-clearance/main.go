package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/aniklavida/code-clearance/internal/adapters"
	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/mcpserver"
	"github.com/aniklavida/code-clearance/internal/report"
)

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "record-review":
		os.Exit(runRecordReview(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "findings":
		os.Exit(runFindings(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "serve":
		os.Exit(runServe(ctx, os.Args[2:], os.Stderr))
	case "version", "--version", "-v":
		reportVersion(os.Stdout)
		os.Exit(0)
	case "-h", "--help", "help":
		printUsage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `Code Clearance — local-first assurance layer

Usage:
  code-clearance <command> [flags] [dir]

Commands:
  scan            Run clearance scanners and report evidence
  record-review   Record a review decision for a finding
  findings        Get current findings and review states
  serve           Serve clearance MCP tools over stdio
  version Print the version, and whether this build is signed
`)
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output report as JSON")
	scopeFlag := fs.String("scope", "quick", "scan scope: quick (changed files), full (all files), release")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := "."
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	report, err := app.ScanWithOptions(ctx, targetDir, app.ScanOptions{Scope: *scopeFlag})
	if err != nil {
		fmt.Fprintf(stderr, "scan error: %v\n", err)
		return 1
	}

	if *jsonOut {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "json marshal error: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(data))
	} else {
		printHumanReport(report, stdout)
	}

	// Exit non-zero if any findings were detected or checks failed
	for _, run := range report.Runs {
		if run.Status == evidence.StatusFindings || run.Status == evidence.StatusCrashed || run.Status == evidence.StatusTimedOut {
			return 1
		}
	}
	return 0
}

func printHumanReport(r evidence.Report, w io.Writer) {
	if err := report.WriteTerminal(r, w); err != nil {
		fmt.Fprintf(w, "report error: %v\n", err)
	}
}

func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	if err := mcpserver.ServeStdio(ctx); err != nil {
		fmt.Fprintf(stderr, "mcp server error: %v\n", err)
		return 1
	}
	return 0
}

func runRecordReview(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("record-review", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "target directory")
	fp := fs.String("fingerprint", "", "finding fingerprint")
	status := fs.String("status", "", "challenge status (e.g. rejected, accepted-risk)")
	reason := fs.String("reason", "", "rationale for the review")
	reviewerType := fs.String("reviewer-type", "human", "type of reviewer (human, agent, tool)")
	identity := fs.String("identity", "", "reviewer identity")
	expires := fs.String("expires-at", "", "optional expiry for accepted-risk")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *fp == "" || *status == "" {
		fmt.Fprintf(stderr, "error: fingerprint and status are required\n")
		return 2
	}

	err := app.RecordReview(ctx, app.RecordReviewArgs{
		TargetDir:        *dir,
		Fingerprint:      *fp,
		ChallengeStatus:  *status,
		Reason:           *reason,
		ReviewerType:     *reviewerType,
		ReviewerIdentity: *identity,
		ExpiresAt:        *expires,
	})
	if err != nil {
		fmt.Fprintf(stderr, "failed to record review: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "Review recorded successfully")
	return 0
}

func runFindings(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "target directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	findings, err := app.GetFindings(ctx, app.GetFindingsArgs{TargetDir: *dir})
	if err != nil {
		fmt.Fprintf(stderr, "failed to get findings: %v\n", err)
		return 1
	}

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "json marshal error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(data))
	return 0
}
