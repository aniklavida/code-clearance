package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aniklavida/code-clearance/internal/mcpserver"
)

func runMCP(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printMCPUsage(stderr)
		return 2
	}

	switch args[0] {
	case "register":
		return runMCPRegister(ctx, args[1:], stdout, stderr)
	case "verify":
		return runMCPVerify(ctx, args[1:], stdout, stderr)
	case "unregister":
		return runMCPUnregister(ctx, args[1:], stdout, stderr)
	case "status":
		return runMCPStatus(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printMCPUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown mcp subcommand: %q\n\n", args[0])
		printMCPUsage(stderr)
		return 2
	}
}

func printMCPUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage:
  code-clearance mcp <subcommand> [flags]

Subcommands:
  register    Register Code Clearance MCP server in a host configuration file
  verify      Verify MCP server registration by executing protocol handshake over stdio
  unregister  Remove Code Clearance MCP server registration from a host config
  status      Show current MCP server registration status

Hosts supported for configuration snippets:
  local            Workspace-local .mcp.json (default, tested)
  claude-desktop   Claude Desktop app config (documented)
  cursor           Cursor IDE config (documented)
  windsurf         Windsurf IDE config (documented)

Notice: MCP servers are passive. Registering the server does not make Code Clearance
run itself; automatic use comes from the host's own instructions, hooks, or CI calling
it after meaningful changes.
`)
}

func runMCPRegister(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp register", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "local", "target MCP host: local, claude-desktop, cursor, windsurf")
	customPath := fs.String("config", "", "custom path to host configuration JSON file")
	cmdBin := fs.String("command", "", "command to invoke code-clearance (default: executable path or 'code-clearance')")
	cmdArgs := fs.String("args", "serve", "space-separated arguments for MCP server command")
	approve := fs.Bool("approve", false, "approve writing configuration to host file")
	fs.BoolVar(approve, "y", false, "alias for --approve")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := "."
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	configPath, err := mcpserver.GetHostConfigPath(*host, *customPath, targetDir)
	if err != nil {
		fmt.Fprintf(stderr, "mcp register error: %v\n", err)
		return 1
	}

	resolvedBin := *cmdBin
	if resolvedBin == "" {
		if exe, err := os.Executable(); err == nil {
			resolvedBin = exe
		} else {
			resolvedBin = "code-clearance"
		}
	}

	argSlice := strings.Fields(*cmdArgs)
	reg := mcpserver.ServerRegistration{
		Command: resolvedBin,
		Args:    argSlice,
	}

	snippet := mcpserver.GenerateRegistrationSnippet(resolvedBin, argSlice)

	if !*approve {
		fmt.Fprintf(stdout, "Proposed MCP registration for host %q (%s):\n", *host, configPath)
		fmt.Fprintf(stdout, "----------------------------------------\n")
		fmt.Fprintf(stdout, "%s\n", snippet)
		fmt.Fprintf(stdout, "----------------------------------------\n\n")
		fmt.Fprintf(stdout, "Notice: MCP servers are passive. Registering the server does not make Code Clearance\n")
		fmt.Fprintf(stdout, "run itself; automatic use comes from the host's own instructions, hooks, or CI calling\n")
		fmt.Fprintf(stdout, "it after meaningful changes.\n\n")
		fmt.Fprintf(stdout, "Approval required: rerun with --approve to write this configuration:\n")
		if *customPath != "" {
			fmt.Fprintf(stdout, "  code-clearance mcp register --config %q --approve\n", *customPath)
		} else {
			fmt.Fprintf(stdout, "  code-clearance mcp register --host %s --approve\n", *host)
		}
		return 0
	}

	if err := mcpserver.RegisterServer(configPath, reg); err != nil {
		fmt.Fprintf(stderr, "failed to write host configuration %s: %v\n", configPath, err)
		return 1
	}

	fmt.Fprintf(stdout, "Successfully registered code-clearance in %s.\n\n", configPath)
	fmt.Fprintf(stdout, "Notice: MCP servers are passive. Registering the server does not make Code Clearance\n")
	fmt.Fprintf(stdout, "run itself; automatic use comes from the host's own instructions, hooks, or CI calling\n")
	fmt.Fprintf(stdout, "it after meaningful changes.\n\n")
	fmt.Fprintf(stdout, "Run 'code-clearance mcp verify --config %q' to verify the registration.\n", configPath)
	return 0
}

func runMCPVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	customPath := fs.String("config", "", "path to host configuration JSON file (default: .mcp.json)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	configPath := *customPath
	if configPath == "" {
		if fs.NArg() > 0 {
			configPath = fs.Arg(0)
		} else {
			configPath = ".mcp.json"
		}
	}

	tools, err := mcpserver.VerifyRegistration(ctx, configPath)
	if err != nil {
		fmt.Fprintf(stderr, "MCP registration verification failed: unreachable MCP registration at %s: %v\n", configPath, err)
		fmt.Fprintf(stderr, "Remedy: update host configuration with valid path to code-clearance binary, then rerun\n")
		return 1
	}

	fmt.Fprintf(stdout, "MCP server registration verified: server at %s responded to protocol handshake.\n", configPath)
	fmt.Fprintf(stdout, "Registered tools (%d): %s\n", len(tools), strings.Join(tools, ", "))
	return 0
}

func runMCPUnregister(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp unregister", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "local", "target MCP host: local, claude-desktop, cursor, windsurf")
	customPath := fs.String("config", "", "path to host configuration JSON file")
	approve := fs.Bool("approve", false, "approve removing registration from host config")
	fs.BoolVar(approve, "y", false, "alias for --approve")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetDir := "."
	if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}

	configPath, err := mcpserver.GetHostConfigPath(*host, *customPath, targetDir)
	if err != nil {
		fmt.Fprintf(stderr, "mcp unregister error: %v\n", err)
		return 1
	}

	if !*approve {
		fmt.Fprintf(stdout, "Approval required: this will edit %s to remove the code-clearance server registration.\n", configPath)
		fmt.Fprintf(stdout, "Rerun with --approve to confirm:\n")
		fmt.Fprintf(stdout, "  code-clearance mcp unregister --config %q --approve\n", configPath)
		return 0
	}

	if err := mcpserver.UnregisterServer(configPath); err != nil {
		fmt.Fprintf(stderr, "failed to unregister server from %s: %v\n", configPath, err)
		return 1
	}

	fmt.Fprintf(stdout, "Successfully removed code-clearance registration from %s.\n", configPath)
	return 0
}

func runMCPStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	customPath := fs.String("config", ".mcp.json", "path to host configuration JSON file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	configPath := *customPath
	if _, err := os.Stat(configPath); err != nil {
		fmt.Fprintf(stdout, "No registration config found at %s.\n", configPath)
		fmt.Fprintf(stdout, "Run 'code-clearance mcp register --approve' to register Code Clearance.\n")
		return 0
	}

	tools, err := mcpserver.VerifyRegistration(ctx, configPath)
	if err != nil {
		fmt.Fprintf(stdout, "MCP registration found at %s, but verification failed: %v\n", configPath, err)
		return 1
	}

	fmt.Fprintf(stdout, "MCP server registered and verified at %s (%d tools active).\n", configPath, len(tools))
	return 0
}
