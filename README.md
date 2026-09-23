# Code Clearance

Evidence-based clearance for AI-generated code.

> **Pre-implementation:** Code Clearance has a version 1.0 product specification, a locked technical foundation (Go, the official MCP Go SDK, and a lightweight core with external scanner adapters) and a repository foundation, but no working release yet. Capabilities below are planned unless explicitly marked implemented.

Code Clearance will be a local-first assurance engine that coding agents, developers and CI workflows can invoke after meaningful code changes, on Linux, macOS and Windows. It will coordinate trusted scanners and repository checks, normalize and challenge findings, verify fixes by rerunning evidence, and produce a commit-bound report showing what passed, failed, remained unknown or was accepted as risk.

The intended workflow is:

```text
scan → normalize → correlate → challenge → fix → rescan/test → clearance report
```

Code Clearance will not promise zero bugs. A result must disclose its scope, tool versions, unavailable checks, coverage and residual risk.

## Planned interfaces

- One cross-platform `code-clearance` CLI core, for Linux, macOS and Windows
- Local MCP server for compatible coding-agent hosts
- GitHub Action and pull-request annotations
- Terminal, JSON, SARIF-compatible and local HTML reports

## Documents

- [Product specification](docs/SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Build-to-release roadmap](docs/ROADMAP.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)

## Current status

The product specification, the contribution foundation, and the first working slice of the engine are here. **No release has been published**, and most capabilities listed above remain planned.

What runs today: a bounded process runner with cancellation and captured exit state, SARIF 2.1.0 normalization, adapters for `gitleaks` and `osv-scanner`, one MCP tool over the official Go SDK, and a single binary exposing the same core through `scan` and `serve`. Scan results are bound to the repository, the commit and a dirty-tree fingerprint.

## Installation (planned)

Nothing is published yet, so neither path below works today. They are recorded so the shape is not a surprise later.

**Tagged release binaries** will be the supported way to install, for Linux, macOS and Windows, with checksums and signing where the platform supports it. A tool whose subject is supply-chain assurance should ship artifacts you can verify.

**`go install github.com/aniklavida/code-clearance/cmd/code-clearance@latest`** will also work, for people who already have a Go toolchain and prefer it. It builds on your machine, so it produces nothing signed — `code-clearance version` says so rather than leaving you to guess.

Package managers such as Homebrew are not planned for the first release. They would not cover Windows, so they solve none of the platform problem.

External scanners are invoked as separate processes and are never vendored: you install `gitleaks` and `osv-scanner` yourself, and Code Clearance reports honestly when a required one is missing.

## Onboarding and quick start

### 1. Initialize configuration (`code-clearance init`)

`code-clearance init` inspects the repository stack (languages, package manifests, lockfiles) and scanner tools available on the host, then proposes a versioned `clearance.yaml` configuration.

To review the proposed configuration without writing it:

```bash
code-clearance init
```

Code Clearance never modifies or creates files without an explicit approval step. To approve and write the proposed configuration:

```bash
code-clearance init --approve
```

### 2. Verify health and environment (`code-clearance doctor`)

`code-clearance doctor` confirms:
- the core engine runs and store paths are accessible;
- each configured scanner adapter actually works (tested via a real minimal version probe, not just checking that the binary exists);
- each repository-defined command from `clearance.yaml` is permitted by the command allowlist and executes cleanly;
- registered MCP host connections respond over stdio.

```bash
code-clearance doctor
```

When a required scanner is missing or broken, `doctor` outputs an actionable diagnostic naming the specific remedy (e.g. `gitleaks not found on PATH; install it or move it to adapters.optional, then rerun`).

When missing scanners are detected, `doctor` displays the recommended install command for your platform. Machine-modifying actions require explicit approval:

```bash
code-clearance doctor --install-missing --approve
```

### 3. Register MCP server (`code-clearance mcp`)

> **MCP servers are passive.** Registering the server does not make Code Clearance run itself. Automatic use comes from the host's own instructions, hooks, or CI calling it after meaningful changes. The server does not watch or run on its own.

To preview copy-paste registration snippets:

```bash
code-clearance mcp register --host local
```

Supported host targets:
- `local`: Workspace-level `.mcp.json` (**tested and verified** in this environment via stdio protocol handshake).
- `claude-desktop`: Claude Desktop configuration (**documented** configuration format; interactive desktop GUI integration is unverified in this headless environment).
- `cursor`: Cursor IDE configuration (**documented** configuration format; desktop GUI integration is unverified in this headless environment).
- `windsurf`: Windsurf IDE configuration (**documented** configuration format; desktop GUI integration is unverified in this headless environment).

To approve writing the registration to the target host configuration:

```bash
code-clearance mcp register --host local --approve
```

### 4. Verify MCP registration

`code-clearance mcp verify` connects to the registered server over stdio, performs the MCP protocol initialization handshake, and lists registered tools to confirm the server responds:

```bash
code-clearance mcp verify --config .mcp.json
```

### 5. Run first scan

```bash
code-clearance scan --scope quick
```

## Updating Code Clearance

When updating an existing installation:

- **Go toolchain:**
  ```bash
  go install github.com/aniklavida/code-clearance/cmd/code-clearance@latest
  ```
- **Release binary:**
  Download the latest binary release for your platform, replace the existing executable, and run `code-clearance doctor` to verify the upgrade.

## Clean uninstall path

To completely remove Code Clearance and all associated registrations:

1. **Remove MCP registrations:**
   Run unregister with approval:
   ```bash
   code-clearance mcp unregister --host local --approve
   ```
   Or manually remove the `"code-clearance"` entry from your host's MCP configuration file (e.g., `.mcp.json` or desktop host config).

2. **Remove repository state:**
   Delete the local clearance cache and policy files from repositories:
   ```bash
   rm -rf .clearance clearance.yaml
   ```

3. **Remove executable binary:**
   - If installed via Go: `rm "$(go env GOPATH)/bin/code-clearance"`
   - If installed manually: remove the binary from your local bin directory (e.g., `/usr/local/bin/code-clearance`).

