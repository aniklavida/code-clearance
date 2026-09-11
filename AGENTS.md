# Code Clearance contributor instructions

These instructions are public and apply to any coding agent or contributor working in this repository.

## Before changing code

1. Read `docs/SPEC.md`, `docs/ARCHITECTURE.md` and the current milestone in `docs/ROADMAP.md`.
2. Do not claim planned behavior as implemented behavior.
3. Keep the CLI, MCP and CI interfaces backed by the same application core.

## Engineering rules

- Preserve raw scanner evidence; normalization must not destroy source details.
- Never treat skipped, unavailable, crashed or timed-out checks as passing.
- A fix is not verified until affected tests and scanners rerun successfully.
- Policy evaluation must be deterministic for identical evidence and configuration.
- Scanner integrations belong behind adapters; do not embed third-party scanner engines without an explicit licence decision.
- Run external commands with explicit scope, bounded timeouts, cancellation and captured exit state.
- Do not upload source code by default.
- Add fixture-based parser tests for every supported tool output and version behavior.
- Update public documentation and changelog when public behavior changes.

## Before finishing a change

- Run formatting, unit tests and the relevant integration fixtures.
- Check that error paths and unavailable-tool states remain honest.
- Summarize what changed, what was verified and any remaining risk.
