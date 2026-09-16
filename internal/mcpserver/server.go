// Package mcpserver implements one MCP tool over the official Go SDK,
// backed by the runner+sarifing+adapters pipeline validated elsewhere in
// this surface. It exists to prove the "official MCP flow" leg of the
// a real client, over real stdio, calling a real tool
// that runs real external processes and returns real normalized findings.
package mcpserver

import (
	"context"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aniklavida/code-clearance/internal/adapters"
	"github.com/aniklavida/code-clearance/internal/evidence"
)

// ScanArgs is the input schema for the run_clearance_scan tool. The SDK's
// generic mcp.AddTool derives the JSON schema from these struct tags.
type ScanArgs struct {
	TargetDir string `json:"target_dir" jsonschema:"absolute path to the directory to scan"`
}

// ScanOutput is the structured tool output: one outcome per adapter run,
// each carrying its own normalized findings. It mirrors what a real
// clearance_run MCP tool would return, minus policy evaluation.
type ScanOutput struct {
	Runs []evidence.RunOutcome `json:"runs"`
}

// NewServer builds the MCP server with a single tool,
// run_clearance_scan, that runs the gitleaks and osv-scanner adapters
// against the given directory and returns normalized evidence.
func NewServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "code-clearance",
		Version: "0.0.0-dev",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_clearance_scan",
		Description: "Run the gitleaks and osv-scanner adapters against a " +
			"target directory and return normalized, evidence-backed findings.",
	}, runClearanceScan)

	return server
}

func runClearanceScan(ctx context.Context, req *mcp.CallToolRequest, args ScanArgs) (*mcp.CallToolResult, ScanOutput, error) {
	out := ScanOutput{}

	out.Runs = append(out.Runs, adapters.Gitleaks(ctx, args.TargetDir))

	lockfile := filepath.Join(args.TargetDir, "package-lock.json")
	out.Runs = append(out.Runs, adapters.OSVScanner(ctx, lockfile))

	// Returning (result, output, err) with result==nil lets AddTool
	// build the CallToolResult content automatically from the
	// structured output (see the SDK's generic tool handler behavior).
	return nil, out, nil
}
