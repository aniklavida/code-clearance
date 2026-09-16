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
	case "serve":
		os.Exit(runServe(ctx, os.Args[2:], os.Stderr))
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
  scan    Run clearance scanners and report evidence
  serve   Serve clearance MCP tools over stdio
`)
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output report as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := "."
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	report, err := app.Scan(ctx, targetDir)
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

func printHumanReport(report evidence.Report, w io.Writer) {
	fmt.Fprintf(w, "Repository:  %s\n", report.Target.Repository)
	fmt.Fprintf(w, "Commit:      %s\n", report.Target.Commit)
	fmt.Fprintf(w, "Dirty:       %v\n", report.Target.Dirty)
	fmt.Fprintf(w, "Fingerprint: %s\n", report.Target.Fingerprint)
	fmt.Fprintln(w)

	totalFindings := 0
	for _, run := range report.Runs {
		fmt.Fprintf(w, "[%s] %s (exit %d, %s)\n", run.Status, run.Tool, run.ExitCode, run.Duration)
		if len(run.Findings) > 0 {
			totalFindings += len(run.Findings)
			for _, f := range run.Findings {
				locStr := ""
				if len(f.Locations) > 0 {
					locStr = f.Locations[0].URI
					if f.Locations[0].StartLine != nil {
						locStr = fmt.Sprintf("%s:%d", locStr, *f.Locations[0].StartLine)
					}
				}
				fmt.Fprintf(w, "  - [%s] %s: %s (%s)\n", f.NormalizedSeverity, f.RuleID, f.Message, locStr)
			}
		}
	}

	fmt.Fprintln(w)
	if totalFindings == 0 {
		fmt.Fprintln(w, "Clearance: no findings reported.")
	} else {
		fmt.Fprintf(w, "Clearance: %d finding(s) reported.\n", totalFindings)
	}
}

func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	if err := mcpserver.ServeStdio(ctx); err != nil {
		fmt.Fprintf(stderr, "mcp server error: %v\n", err)
		return 1
	}
	return 0
}
