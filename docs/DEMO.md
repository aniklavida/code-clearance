# Code Clearance demo

**Status: Experimental.** The script runs the real review, fix and verification operations against a throwaway copy of the Go fixture, but the recorded run does not produce the four outcomes claimed by its banner. It also masks nonzero scan exits with `|| true`. Do not use it as acceptance evidence until its Release scans have verified Git provenance and the final report reaches `cleared-with-residual-risk`.

## What the recorded run actually did

Requirements are Go, Gitleaks on `PATH` and Python 3:

```bash
bash scripts/demo.sh
```

The script builds Code Clearance, copies `testdata/fixtures/go` to a temporary directory, seeds one throwaway private-key-shaped value in three locations and removes the temporary directory on exit.

On 2026-09-25 the script exited zero, but the observed reports were:

| Beat | Observed result |
|---|---|
| Confirmed production finding | `blocked`, but because the temporary copy had no Git provenance |
| Rejected test-fixture finding | Review state changed to `rejected`; overall result remained blocked for the same provenance reason |
| Applied fix and targeted verification | The original finding became `fixed` with patch and verification lineage; targeted report returned `cleared` |
| Accepted documented example credential | Residual-risk data was accepted, but final Release report remained `blocked` because the temporary copy had no Git provenance |

The final output did not show `cleared-with-residual-risk`; it showed:

```text
Outcome: blocked
Reason:  release mode blocked: provenance checks did not verify the target commit and tree
```

This is why the demo is **Experimental** rather than **Implemented and tested**.

## What is already tested independently

- **Implemented and tested:** the unattended scan → challenge → fix → verify → report loop is covered by the MCP integration test `TestUnattendedAgentLoopReal`.
- **Implemented and tested:** a finding cannot be marked fixed directly; verification evidence is required.
- **Implemented and tested:** review persistence, human-required classes, accepted risk and deterministic policy evaluation have named tests.
- **Implemented and tested:** the real dogfood scan is published in [DOGFOOD.md](DOGFOOD.md).

The demo script itself is a convenience wrapper, not stronger evidence than its output.
