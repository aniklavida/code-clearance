package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ServerRegistration defines the command, arguments, and environment for an MCP server.
type ServerRegistration struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// HostConfigFile models standard MCP host configuration files (Claude Desktop, Cursor, etc.).
type HostConfigFile struct {
	MCPServers map[string]ServerRegistration `json:"mcpServers"`
}

// GetHostConfigPath resolves the configuration file path for a named MCP host or custom path.
func GetHostConfigPath(host string, customPath string, targetDir string) (string, error) {
	if customPath != "" {
		return customPath, nil
	}

	switch strings.ToLower(host) {
	case "local", "":
		if targetDir == "" {
			targetDir = "."
		}
		return filepath.Join(targetDir, ".mcp.json"), nil

	case "claude-desktop":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home directory: %w", err)
		}
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		case "windows":
			appData := os.Getenv("APPDATA")
			if appData == "" {
				appData = filepath.Join(home, "AppData", "Roaming")
			}
			return filepath.Join(appData, "Claude", "claude_desktop_config.json"), nil
		default: // linux, freebsd, etc.
			return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
		}

	case "cursor":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home directory: %w", err)
		}
		return filepath.Join(home, ".cursor", "mcp.json"), nil

	case "windsurf":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home directory: %w", err)
		}
		return filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), nil

	default:
		return "", fmt.Errorf("unsupported host %q; supported host names: local, claude-desktop, cursor, windsurf (or provide custom path via --config)", host)
	}
}

// GenerateRegistrationSnippet returns a formatted JSON snippet for copy-paste registration.
func GenerateRegistrationSnippet(command string, args []string) string {
	cfg := HostConfigFile{
		MCPServers: map[string]ServerRegistration{
			"code-clearance": {
				Command: command,
				Args:    args,
			},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return string(data)
}

// RegisterServer writes or updates the code-clearance registration in the given host config path.
func RegisterServer(configPath string, reg ServerRegistration) error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory for host config %q: %w", configPath, err)
	}

	hostCfg := HostConfigFile{
		MCPServers: make(map[string]ServerRegistration),
	}

	if data, err := os.ReadFile(configPath); err == nil {
		_ = json.Unmarshal(data, &hostCfg)
		if hostCfg.MCPServers == nil {
			hostCfg.MCPServers = make(map[string]ServerRegistration)
		}
	}

	hostCfg.MCPServers["code-clearance"] = reg

	data, err := json.MarshalIndent(hostCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode host configuration JSON: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("write host config %q: %w", configPath, err)
	}
	return nil
}

// UnregisterServer removes the code-clearance registration from the given host config path.
func UnregisterServer(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read host config %q: %w", configPath, err)
	}

	var hostCfg HostConfigFile
	if err := json.Unmarshal(data, &hostCfg); err != nil {
		return fmt.Errorf("parse host config %q: %w", configPath, err)
	}

	if hostCfg.MCPServers != nil {
		delete(hostCfg.MCPServers, "code-clearance")
	}

	outData, err := json.MarshalIndent(hostCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode host configuration JSON: %w", err)
	}

	if err := os.WriteFile(configPath, outData, 0644); err != nil {
		return fmt.Errorf("write host config %q: %w", configPath, err)
	}
	return nil
}

// VerifyRegistration connects to the registered server command over stdio using the MCP protocol,
// executes a tools/list call, and verifies that the clearance tools respond.
func VerifyRegistration(ctx context.Context, configPath string) ([]string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read host config %q: %w; ensure the config file exists or run 'code-clearance mcp register --approve', then rerun", configPath, err)
	}

	var hostCfg HostConfigFile
	if err := json.Unmarshal(data, &hostCfg); err != nil {
		return nil, fmt.Errorf("parse host config %q: %w; fix JSON syntax in host configuration, then rerun", configPath, err)
	}

	serverCfg, ok := hostCfg.MCPServers["code-clearance"]
	if !ok {
		return nil, fmt.Errorf("no 'code-clearance' server found in %s; register it with 'code-clearance mcp register --approve', then rerun", configPath)
	}

	if serverCfg.Command == "" {
		return nil, fmt.Errorf("server 'code-clearance' in %s has empty command; update host configuration with valid command path, then rerun", configPath)
	}

	cmd := exec.CommandContext(ctx, serverCfg.Command, serverCfg.Args...)
	if len(serverCfg.Env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range serverCfg.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	transport := &mcp.CommandTransport{
		Command: cmd,
	}

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "code-clearance-verifier",
		Version: "1.0.0",
	}, nil)

	connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	session, err := client.Connect(connCtx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to MCP server (%s %s): %w; update host configuration with valid path to code-clearance binary, then rerun",
			serverCfg.Command, strings.Join(serverCfg.Args, " "), err)
	}
	defer session.Close()

	toolsResult, err := session.ListTools(connCtx, nil)
	if err != nil {
		return nil, fmt.Errorf("call tools/list on MCP server: %w; verify server command invokes 'code-clearance serve', then rerun", err)
	}

	var toolNames []string
	for _, t := range toolsResult.Tools {
		toolNames = append(toolNames, t.Name)
	}

	hasClearanceTool := false
	for _, name := range toolNames {
		if name == "run_clearance_scan" || name == "clearance_scan" {
			hasClearanceTool = true
			break
		}
	}
	if !hasClearanceTool {
		return toolNames, fmt.Errorf("server responded but clearance tools (run_clearance_scan) not found; verify server command invokes 'code-clearance serve', then rerun")
	}

	return toolNames, nil
}
