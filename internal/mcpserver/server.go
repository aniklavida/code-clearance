// Package mcpserver implements one MCP tool over the official Go SDK,
// backed by the runner+sarifing+adapters pipeline validated elsewhere in
// this surface. It exists to prove the "official MCP flow" leg of the
// a real client, over real stdio, calling a real tool
// that runs real external processes and returns real normalized findings.
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"encoding/json"
	"fmt"
	_ "github.com/aniklavida/code-clearance/internal/adapters"
	"github.com/aniklavida/code-clearance/internal/app"
	"os"
	"path/filepath"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/schema"
	"github.com/aniklavida/code-clearance/internal/store"
)

// ScanArgs is the input schema for the run_clearance_scan tool. The SDK's
// generic mcp.AddTool derives the JSON schema from these struct tags.
type ScanArgs struct {
	TargetDir string `json:"target_dir" jsonschema:"absolute path to the directory to scan"`
	Scope     string `json:"scope,omitempty" jsonschema:"optional scan scope: quick (default), full, or release"`
}

// ScanOutput is the structured tool output: a complete evidence report
// bound to repository identity, commit SHA, and dirty-tree fingerprint.
type ScanOutput = evidence.Report

// NewServer builds the MCP server with a single tool,
// run_clearance_scan, that executes the shared clearance scan core
// against the given directory and returns normalized evidence.
func NewServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "code-clearance",
		Version: "0.0.0-dev",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_clearance_scan",
		Description: "Run the clearance scanners against a " +
			"target directory and return normalized, evidence-backed findings bound to commit and tree state.",
	}, RunClearanceScan)

	mcp.AddTool(server, &mcp.Tool{
		Name: "clearance_scan",
		Description: "Run the clearance scanners against a " +
			"target directory and return normalized, evidence-backed findings bound to commit and tree state.",
	}, RunClearanceScan)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "clearance_get_fix_context",
		Description: "Get the evidence and constraints an agent needs to prepare a patch for one finding, and nothing beyond that.",
	}, GetFixContext)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "clearance_verify",
		Description: "Rerun the minimum affected checks and tests after a change to verify remediation of a finding.",
	}, ClearanceVerify)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "clearance_record_review",
		Description: "Record a review decision for a specific finding by fingerprint.",
	}, RecordReview)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "clearance_get_findings",
		Description: "Get the list of current findings with their evidence and review states.",
	}, GetFindings)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "clearance_run",
		Description: "Run the full clearance pipeline (scan+evaluate) using the named profile and clearance.json config.",
	}, ClearanceRun)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "clearance_report",
		Description: "Re-render the most recently persisted run's report.",
	}, ClearanceReport)

	return server
}

// RunClearanceScan is the tool handler delegating execution to the shared core.
func RunClearanceScan(ctx context.Context, req *mcp.CallToolRequest, args ScanArgs) (*mcp.CallToolResult, ScanOutput, error) {
	scope := args.Scope
	if scope == "" {
		scope = "quick"
	}
	report, err := app.ScanWithOptions(ctx, args.TargetDir, app.ScanOptions{Scope: scope})
	if err != nil {
		return nil, report, err
	}
	return nil, report, nil
}

func RecordReview(ctx context.Context, req *mcp.CallToolRequest, args app.RecordReviewArgs) (*mcp.CallToolResult, string, error) {
	if args.ChallengeStatus == string(evidence.ChallengeFixed) {
		return nil, "", fmt.Errorf("a finding cannot be marked fixed directly: findings become fixed only through new recorded evidence from a verification run (clearance_verify)")
	}
	// The MCP tool surface is only ever invoked by an agent, never directly by a human.
	// Force the reviewer type to agent so that agents cannot bypass human_required_classes
	// by claiming to be a human reviewer.
	args.ReviewerType = string(evidence.ReviewerAgent)
	err := app.RecordReview(ctx, args)
	if err != nil {
		return nil, "", err
	}
	return nil, "Review recorded successfully", nil
}

func GetFixContext(ctx context.Context, req *mcp.CallToolRequest, args app.FixContextArgs) (*mcp.CallToolResult, *app.FixContext, error) {
	fixCtx, err := app.GetFixContext(ctx, args)
	if err != nil {
		return nil, nil, err
	}
	return nil, fixCtx, nil
}

func ClearanceVerify(ctx context.Context, req *mcp.CallToolRequest, args app.VerifyArgs) (*mcp.CallToolResult, evidence.Report, error) {
	rep, err := app.Verify(ctx, args)
	if err != nil {
		return nil, evidence.Report{}, err
	}
	return nil, rep, nil
}

func GetFindings(ctx context.Context, req *mcp.CallToolRequest, args app.GetFindingsArgs) (*mcp.CallToolResult, []evidence.Finding, error) {
	findings, err := app.GetFindings(ctx, args)
	if err != nil {
		return nil, nil, err
	}
	return nil, findings, nil
}

// ServeStdio runs the MCP server over standard I/O until the context is cancelled
// or the client disconnects.
func ServeStdio(ctx context.Context) error {
	server := NewServer()
	return server.Run(ctx, &mcp.StdioTransport{})
}

type ClearanceRunArgs struct {
	TargetDir string `json:"target_dir" jsonschema:"absolute path to the directory to scan"`
	Profile   string `json:"profile,omitempty" jsonschema:"optional profile to run (quick, full, release)"`
}

func ClearanceRun(ctx context.Context, req *mcp.CallToolRequest, args ClearanceRunArgs) (*mcp.CallToolResult, evidence.Report, error) {
	scope := args.Profile
	if scope == "" {
		scope = "quick"
	}

	opts := app.ScanOptions{Scope: scope}

	cfgPath := policy.FindConfigFile(args.TargetDir)
	if cfgPath != "" {
		if data, err := os.ReadFile(cfgPath); err == nil {
			if valErr := schema.ValidateClearance(data); valErr != nil {
				return nil, evidence.Report{}, valErr
			}
			if cfg, cfgErr := policy.Load(cfgPath); cfgErr == nil {
				opts.Config = &cfg
			}
		}
	}

	report, err := app.ScanWithOptions(ctx, args.TargetDir, opts)
	if err != nil {
		return nil, evidence.Report{}, err
	}

	st, err := store.New(filepath.Join(args.TargetDir, ".clearance"))
	if err == nil {
		session, err := st.CreateRun("")
		if err == nil {
			data, _ := json.Marshal(report)
			session.SaveArtifact("clearance_report", "json", data)
			// Write a stable pointer to this run so ClearanceReport finds it exactly
			os.WriteFile(filepath.Join(st.RootDir(), "latest-run.json"), []byte(session.RunID()), 0644)
		}
	}

	return nil, report, nil
}

type ClearanceReportArgs struct {
	TargetDir string `json:"target_dir" jsonschema:"absolute path to the project directory"`
}

func ClearanceReport(ctx context.Context, req *mcp.CallToolRequest, args ClearanceReportArgs) (*mcp.CallToolResult, evidence.Report, error) {
	st, err := store.New(filepath.Join(args.TargetDir, ".clearance"))
	if err != nil {
		return nil, evidence.Report{}, err
	}

	pointerPath := filepath.Join(st.RootDir(), "latest-run.json")
	latestBytes, err := os.ReadFile(pointerPath)
	if err != nil {
		return nil, evidence.Report{}, os.ErrNotExist
	}
	latest := string(latestBytes)

	runsDir := filepath.Join(st.RootDir(), "runs")
	reportPath := filepath.Join(runsDir, latest, "artifacts", "clearance_report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, evidence.Report{}, err
	}

	var rep evidence.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, evidence.Report{}, err
	}

	return nil, rep, nil
}
