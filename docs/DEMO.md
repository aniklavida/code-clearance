# Code Clearance demo

This is the public demonstration of the one loop Code Clearance implements:

```text
scan → normalize → correlate → challenge → fix → rescan/test → report
```

It shows four things, **in this locked order**:

1. a **confirmed issue** that blocks clearance;
2. a **rejected false positive** whose reason is kept;
3. a **verified fix**, proven by a targeted rerun rather than an assertion;
4. **residual risk** that is declared, with an owner and an expiry.

The order is a product decision, not a suggestion: confirmation, then honest
rejection, then evidence of a fix, then the residual risk. Do not reorder it.

## Run it

Requirements: Go (matching `go.mod`) and [`gitleaks`](https://github.com/gitleaks/gitleaks) on `PATH`.
`python3` is used only to read JSON out of the CLI.

```bash
bash scripts/demo.sh
```

The script builds `code-clearance`, copies the checked-in Go fixture
`testdata/fixtures/go` into a temporary directory, adds a throwaway private key
in three places, and runs the real commands against that copy. The temporary
directory is removed on exit and nothing is uploaded or written back to this
repository.

## What each beat proves

### 1. A confirmed issue blocks clearance

A key is hardcoded on a runtime code path. `gitleaks` finds it; a human records
`--status confirmed`; `code-clearance scan --scope release` returns:

```text
Outcome: blocked
Reason:  ... blocking finding(s) detected: ...
```

Confirmation is a recorded disposition, not a deletion of evidence.

### 2. A rejected false positive stops blocking, with a reason kept

The same key also appears in a test fixture. That is a false positive for a
real deployment, so the reviewer records `--status rejected` with a reason.
The finding remains in the report with `status: rejected` and its rationale,
rather than being silently dropped.

### 3. A fix is verified by a targeted rerun, not asserted

The runtime key is removed and a unified diff is passed to
`code-clearance verify ... --approved`. The rerun executes only the affected
check (`gitleaks`), does not detect the finding, and writes the
finding → patch → verification-run lineage:

```text
status: fixed
patch: diff
verification: run-... (ok, cleared)
Outcome: cleared
```

There is no CLI or MCP path that lets a caller mark a finding fixed directly;
`record-review --status fixed` is refused. Only a successful rerun can do it.

### 4. Residual risk is declared, not hidden

A documented example credential in `docs/example-credentials.md` is accepted as
residual risk with a reason, an owner and an expiry. A final
`scan --scope release` returns:

```text
── Residual Risk ──
  [critical] documented example credential kept as a scanner fixture (tool: gitleaks)
Outcome: cleared-with-residual-risk
```

The report also lists the checks that did not run (for example `semgrep` and
`trivy`, when their binaries are absent) under `Uncovered`, so coverage is
visible rather than implied.

## Manual walkthrough

`scripts/demo.sh` is the source of truth; the steps it runs are:

```bash
bin="$(mktemp -d)/code-clearance"
go build -o "$bin" ./cmd/code-clearance

demo="$(mktemp -d)"
cp -R testdata/fixtures/go/. "$demo/"

# 1. Confirmed issue (after seeding the three key locations and clearance.json)
fp="$(... fingerprint from: "$bin" findings --dir "$demo")"
"$bin" record-review --dir "$demo" --fingerprint "$fp" \
  --status confirmed --reason "hardcoded private key on a runtime code path" \
  --reviewer-type human --identity demo-maintainer
"$bin" scan --scope release "$demo"

# 2. Rejected false positive
"$bin" record-review --dir "$demo" --fingerprint "$fp_test" \
  --status rejected --reason "test fixture, not a real credential" \
  --reviewer-type human --identity demo-maintainer
"$bin" scan --scope release "$demo"

# 3. Verified fix
"$bin" verify --dir "$demo" --fingerprint "$fp" --diff "$(cat fix.patch)" --approved

# 4. Residual risk (after adding the accepted_risks entry to clearance.json)
"$bin" scan --scope release "$demo"
```

`"$bin" findings --dir "$demo"` prints the current findings and review states
as JSON at any point.
