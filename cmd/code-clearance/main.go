package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/schema"
	"github.com/aniklavida/code-clearance/internal/store"
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
	case "run", "clearance_run":
		os.Exit(runClearanceRun(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "report", "clearance_report":
		os.Exit(runClearanceReport(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "scan":
		os.Exit(runScan(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "record-review":
		os.Exit(runRecordReview(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "verify", "clearance_verify":
		os.Exit(runVerify(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "fix-context", "get-fix-context", "clearance_get_fix_context":
		os.Exit(runFixContext(ctx, os.Args[2:], os.Stdout, os.Stderr))
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
  run             Run the full clearance pipeline using a profile
  report          Re-render the most recently persisted run's report
  scan            Run clearance scanners and report evidence
  record-review   Record a review decision for a finding
  verify          Rerun minimum affected checks to verify remediation
  fix-context     Get evidence and constraints to prepare a fix
  findings        Get current findings and review states
  serve           Serve clearance MCP tools over stdio
  version         Print the version, and whether this build is signed
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

	if *status == string(evidence.ChallengeFixed) {
		fmt.Fprintf(stderr, "error: a finding cannot be marked fixed directly: findings become fixed only through new recorded evidence from a verification run\n")
		return 1
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

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output report as JSON")
	dir := fs.String("dir", ".", "target directory")
	findingID := fs.String("finding-id", "", "finding ID to verify")
	fp := fs.String("fingerprint", "", "finding fingerprint to verify")
	patchPath := fs.String("patch", "", "optional path to patch file")
	patchDiff := fs.String("diff", "", "optional patch diff")
	patchCommit := fs.String("commit", "", "optional patch commit")
	approved := fs.Bool("approved", false, "confirm host approval for material patch")
	timeoutSec := fs.Int("timeout", 0, "timeout in seconds")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := *dir
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	if *findingID == "" && *fp == "" {
		fmt.Fprintf(stderr, "error: finding-id or fingerprint is required\n")
		return 2
	}

	rep, err := app.Verify(ctx, app.VerifyArgs{
		TargetDir:      targetDir,
		FindingID:      *findingID,
		Fingerprint:    *fp,
		PatchPath:      *patchPath,
		PatchDiff:      *patchDiff,
		PatchCommit:    *patchCommit,
		Approved:       *approved,
		TimeoutSeconds: *timeoutSec,
	})
	if err != nil {
		fmt.Fprintf(stderr, "verification error: %v\n", err)
		return 1
	}

	if *jsonOut {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "json marshal error: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(data))
	} else {
		printHumanReport(rep, stdout)
	}

	if rep.Outcome != evidence.OutcomeCleared && rep.Outcome != evidence.OutcomeClearedWithResidualRisk {
		return 1
	}
	return 0
}

func runFixContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fix-context", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output fix context as JSON")
	dir := fs.String("dir", ".", "target directory")
	findingID := fs.String("finding-id", "", "finding ID to retrieve fix context for")
	fp := fs.String("fingerprint", "", "finding fingerprint to retrieve fix context for")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := *dir
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	if *findingID == "" && *fp == "" {
		fmt.Fprintf(stderr, "error: finding-id or fingerprint is required\n")
		return 2
	}

	fixCtx, err := app.GetFixContext(ctx, app.FixContextArgs{
		TargetDir:   targetDir,
		FindingID:   *findingID,
		Fingerprint: *fp,
	})
	if err != nil {
		fmt.Fprintf(stderr, "fix context error: %v\n", err)
		return 1
	}

	if *jsonOut {
		data, err := json.MarshalIndent(fixCtx, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "json marshal error: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(data))
	} else {
		data, _ := json.MarshalIndent(fixCtx, "", "  ")
		fmt.Fprintln(stdout, string(data))
	}
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

func runClearanceRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output report as JSON")
	profile := fs.String("profile", "quick", "scan profile: quick (default), full, release")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := "."
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	opts := app.ScanOptions{Scope: *profile}
	cfgPath := filepath.Join(targetDir, "clearance.json")
	if data, err := os.ReadFile(cfgPath); err == nil {
		if valErr := schema.ValidateClearance(data); valErr != nil {
			fmt.Fprintf(stderr, "invalid clearance.json: %v\n", valErr)
			return 1
		}
		if cfg, cfgErr := policy.Load(cfgPath); cfgErr == nil {
			opts.Config = &cfg
		}
	}

	report, err := app.ScanWithOptions(ctx, targetDir, opts)
	if err != nil {
		fmt.Fprintf(stderr, "scan error: %v\n", err)
		return 1
	}

	// Persist the report
	st, err := store.New(filepath.Join(targetDir, ".clearance"))
	if err == nil {
		session, err := st.CreateRun("")
		if err == nil {
			data, _ := json.MarshalIndent(report, "", "  ")
			session.SaveArtifact("clearance_report", "json", data)
		}
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

	for _, run := range report.Runs {
		if run.Status == evidence.StatusFindings || run.Status == evidence.StatusCrashed || run.Status == evidence.StatusTimedOut {
			return 1
		}
	}
	if report.Outcome != evidence.OutcomeCleared && report.Outcome != evidence.OutcomeClearedWithResidualRisk {
		return 1
	}
	return 0
}

func runClearanceReport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output report as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := "."
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	st, err := store.New(filepath.Join(targetDir, ".clearance"))
	if err != nil {
		fmt.Fprintf(stderr, "store error: %v\n", err)
		return 1
	}

	runsDir := filepath.Join(st.RootDir(), "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil || len(entries) == 0 {
		fmt.Fprintf(stderr, "no previous runs found\n")
		return 1
	}

	var latest string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "run-") {
			if e.Name() > latest {
				latest = e.Name()
			}
		}
	}
	if latest == "" {
		fmt.Fprintf(stderr, "no previous runs found\n")
		return 1
	}

	reportPath := filepath.Join(runsDir, latest, "artifacts", "clearance_report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Fprintf(stderr, "could not read report from latest run: %v\n", err)
		return 1
	}

	if *jsonOut {
		fmt.Fprintln(stdout, string(data))
		return 0
	}

	var rep evidence.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		fmt.Fprintf(stderr, "could not parse report JSON: %v\n", err)
		return 1
	}

	printHumanReport(rep, stdout)
	return 0
}
