// Package mcpserver implements one MCP tool over the official Go SDK,
// backed by the runner+sarifing+adapters pipeline validated elsewhere in
// this surface. It exists to prove the "official MCP flow" leg of the
// a real client, over real stdio, calling a real tool
// that runs real external processes and returns real normalized findings.
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	_ "github.com/aniklavida/code-clearance/internal/adapters"
	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
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
		Name:        "clearance_record_review",
		Description: "Record a review decision for a specific finding by fingerprint.",
	}, RecordReview)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "clearance_get_findings",
		Description: "Get the list of current findings with their evidence and review states.",
	}, GetFindings)

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
	err := app.RecordReview(ctx, args)
	if err != nil {
		return nil, "", err
	}
	return nil, "Review recorded successfully", nil
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
