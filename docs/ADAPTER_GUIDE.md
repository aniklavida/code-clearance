# Adapter guide

**Status: Implemented and tested** for the existing Gitleaks and OSV-Scanner adapters, including real-process and raw-artifact coverage. **Experimental** for Semgrep and Trivy because their parser fixtures exist but their binaries were unavailable in the recorded run.

This guide is for adding a scanner without copying its engine into Code Clearance and without changing the application core. Code Clearance invokes the scanner as a bounded external process, preserves its raw output, normalizes results and lets policy consume the same evidence through CLI, MCP and Action entry points.

## What a new adapter must provide

Implement `internal/adapters.Adapter` from `internal/adapters/contract.go`:

```go
type Adapter interface {
    Name() string
    Capability() Capability
    Availability(context.Context) Availability
    Version() string
    InputScope() InputScope
    Command(string) []string
    ExitSemantics() ExitSemantics
    Descriptor(context.Context, string) Descriptor
    Run(context.Context, string) evidence.RunOutcome
}
```

Use the existing capability values: `secrets`, `dependencies`, `sast`, `container` or `posture`. A new capability is possible, but it needs a report/design decision rather than an adapter-only assumption.

`Run` must always return one `evidence.RunOutcome`, including when the executable is missing. The outcome must state the actual status and preserve enough evidence to explain it:

- `not-installed` for a missing executable;
- `unavailable` for unsupported version, unreadable output or cancelled execution;
- `timed-out` for a bounded deadline;
- `crashed` for an unexpected exit or parse failure;
- `ok` for a completed clean run;
- `ok-findings` for a completed run with retained findings.

Never convert a missing, skipped, timed-out, crashed or unavailable check into `ok`.

## Choose the boundary first

### SARIF output

Prefer SARIF 2.1.0 when the scanner emits a standard document. Reuse `normalize.Parse` and `normalize.Normalize`, then provide a tool-specific severity rule. This keeps locations, messages, snippets, rule IDs, raw indices and evidence fields in the common model.

### Native JSON

Add a typed parser to `internal/normalize/native.go` when the scanner's native shape is stable. The parser must validate the top-level shape, preserve native severity and source details, redact normalized text, assign a deterministic fingerprint, and return a named error for malformed or unsupported input.

An adapter-local parser is possible for an experiment, but a supported scanner should use the shared normalizer so CLI, MCP, Action and policy see the same result.

## 1. Add the concrete adapter

Create a file under `internal/adapters`, following `adapters.go`:

1. define a small adapter struct containing the detected version and any test override;
2. add a constructor with the supported default version;
3. implement stable `Name`, `Capability`, `Version`, `InputScope` and `ExitSemantics` methods;
4. implement `Availability` with `exec.LookPath`; always return a reason and, when available, a path;
5. implement `Command(target)` as an explicit executable plus argument array, never a shell string;
6. add a compile-time assertion `var _ Adapter = (*YourAdapter)(nil)`;
7. implement `Descriptor` by returning the same metadata used by the individual methods;
8. implement `Run` with the sequence below.

Do not invent a version. `DetectToolVersion` and `normalize.ValidateToolVersion` currently have supported cases for the four built-in scanner families. A new tool needs a version case and tests before `doctor` can verify it.

## 2. Run the scanner safely

Use `app.Run` with:

- the executable as `Spec.Command`;
- arguments as `Spec.Args`;
- an explicit working directory where appropriate;
- a bounded timeout;
- the caller's context;
- captured stdout, stderr, exit state, duration and kill state.

Do not use `sh -c`, string interpolation or an unbounded command. Record the exact argv that ran. If the scanner needs a generated report path, derive the executed arguments from the declared command and record the final command including that path.

Classify the process before parsing output. On timeout, cancellation, start failure or unexpected exit, return a non-pass outcome and do not attempt to parse partial output. On a valid result, set `RawData` to the exact bytes returned by the scanner. The engine persists those bytes and rewrites the artifact URI.

## 3. Normalize findings

For each retained finding, populate the evidence model completely:

- tool and version;
- rule ID and native severity;
- normalized severity;
- locations and snippet hash;
- message and concrete evidence;
- remediation recommendation;
- confidence level and rationale;
- initial challenge state `unreviewed` and tool reviewer;
- related/duplicate arrays and verification arrays;
- disposition and timestamps;
- raw artifact reference and raw result index.

Use the existing redaction functions. Normalized messages, snippets, matches and context are scrubbed before they reach a report or MCP payload; raw bytes remain local. Never put a complete secret-bearing stdout in `StderrTail`.

## 4. Register it without changing the core engine

The default engine exposes a named registration function:

```go
app.RegisterNamedAdapter("your-scanner", func(ctx context.Context, target string) []evidence.RunOutcome {
    return []evidence.RunOutcome{NewYourAdapter().Run(ctx, target)}
})
```

Registering a repository or lockfile target is an adapter decision. The current engine passes the repository directory; an adapter that accepts a lockfile must select the relevant file itself, as the OSV-Scanner registration does. A future file-list/diff input contract is **Planned for v1.0**, not a prerequisite for the current adapter boundary.

The CLI, MCP server and Action already blank-import `internal/adapters`, so adding a named registration makes the adapter available through the shared default engine without adding transport-specific code.

## 5. Add it to discovery and onboarding

For first-class support, also update these adapter-package or command-package lists:

- `DefaultAdapters()` in `internal/adapters/adapters.go`, so `init` discovers it;
- `DefaultScanners()` if the complete default scanner suite should include it;
- `DetectToolVersion()` and its tests;
- `ProposeConfig()` in `cmd/code-clearance/init.go`, if `init` should propose it as required or optional;
- the install guide in `cmd/code-clearance/doctor.go` if a safe, reviewed command is available.

These are registration, discovery and onboarding lists; they are not a reason to add a second scan engine or a transport-specific policy path.

## 6. Add fixture and failure tests

At minimum, add:

1. a real or faithfully captured SARIF/native output fixture under `internal/normalize/testdata`;
2. parser tests for valid output, empty output, malformed output and an unsupported version;
3. assertions for native severity, normalized severity, locations, raw index and redacted text;
4. adapter contract tests for metadata, availability and exit semantics;
5. missing-executable, unexpected-exit, timeout and cancellation tests;
6. a real-process test when the binary is available;
7. an engine test proving raw bytes are stored and finding artifact references resolve to the stored artifact;
8. policy tests proving missing required evidence is `incomplete` and optional evidence remains disclosed;
9. onboarding tests proving `init` and `doctor` report a missing new adapter honestly.

The existing test locations are:

- `internal/normalize/normalization_test.go`;
- `internal/normalize/sarif_test.go`;
- `internal/adapters/contract_test.go`;
- `internal/adapters/adapters_test.go`;
- `internal/adapters/default_scanners_test.go`;
- `internal/discovery/discovery_test.go`;
- `cmd/code-clearance/onboarding_test.go`.

A real-process test is not optional merely because a CI runner lacks the binary. The test should skip with a clear reason when the binary is absent, and the required scanner subset used by the project must not silently skip. The recorded dogfood environment had Gitleaks and OSV-Scanner available, while Semgrep and Trivy were unavailable.

## 7. Verify the public contract

Run:

```bash
gofmt -l .
go vet ./...
go build ./...
go test ./...
go test -v ./internal/adapters
go test -v ./internal/normalize
go test -v ./internal/app
go test -v ./cmd/code-clearance
```

Then run the adapter against a disposable fixture and inspect terminal, JSON and raw artifact output. The report must identify the actual command and version, preserve raw evidence, show unavailable states rather than silently omitting them, and produce the same policy outcome through the CLI and MCP paths.

## Files a normal contribution does not need to change

A scanner adapter should not require edits to:

- `internal/app/scan.go`;
- `internal/app/runner.go`;
- `internal/app/scope.go`;
- `internal/policy/eval.go`;
- `internal/mcpserver/server.go`;
- `internal/action/action.go`;
- CLI or Action entry-point files.

Those files define the shared core and transport boundaries. Runtime plugin loading, per-file/diff scanner input, and a new report or policy contract are **Unsupported** until the core is deliberately extended and tested.

## Review checklist

- [ ] External scanner is invoked, not copied or embedded.
- [ ] Explicit executable, arguments, working directory, timeout and context are used.
- [ ] Exit semantics are declared and honored.
- [ ] Missing, crashed, timed-out and unavailable states are non-passing.
- [ ] Raw output is preserved locally.
- [ ] Normalized evidence is redacted and traceable.
- [ ] Version detection, parser fixtures and failure boundaries are tested.
- [ ] Registration, `init`, `doctor`, policy and engine behavior are covered.
- [ ] No claim exceeds the evidence recorded for the adapter.
