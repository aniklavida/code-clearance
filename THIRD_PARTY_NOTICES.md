# Third-Party Notices

Code Clearance is licensed under the MIT License (see `LICENSE`). This file
lists the third-party software it depends on: tools it invokes as separate
processes, and Go modules compiled into its own binary.

## Scanners invoked as external processes

Code Clearance shells out to these tools; none of their code is compiled
into this project's binary.

| Tool | License | Notes |
|---|---|---|
| [Semgrep Community Edition](https://github.com/semgrep/semgrep) | LGPL-2.1 | Invoked as an external CLI. The LGPL applies to Semgrep itself, not to Code Clearance — no Semgrep source is linked or copied. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Invoked as an external CLI. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Invoked as an external CLI. |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Invoked as an external CLI. |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | Apache-2.0 | Optional; invoked as an external CLI when enabled. |

## Go modules compiled into this binary

Verified against each module's own `LICENSE` file at the exact version
recorded in `go.mod` / `go.sum`, 2026-09-23.

| Module | Version | License |
|---|---|---|
| [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk) | v1.7.0 | Apache-2.0 (the project's own `LICENSE` notes it is mid-transition from MIT to Apache-2.0; contributions not yet relicensed remain MIT — both are permissive and compatible here) |
| github.com/google/jsonschema-go | v0.4.3 | MIT |
| github.com/segmentio/asm | v1.1.3 | MIT |
| github.com/segmentio/encoding | v0.5.4 | MIT |
| github.com/yosida95/uritemplate/v3 | v3.0.2 | BSD-3-Clause |
| golang.org/x/oauth2 | v0.35.0 | BSD-3-Clause |
| golang.org/x/sync | v0.20.0 | BSD-3-Clause |
| golang.org/x/sys | v0.41.0 | BSD-3-Clause |
| golang.org/x/time | v0.15.0 | BSD-3-Clause |

All compiled-in modules are MIT, Apache-2.0, or BSD-3-Clause, consistent
with this project shipping under the MIT License. None of the above
requires reproducing licence text here beyond the notice itself; each
module's own repository carries its full licence.

## Attribution

No source code from any project other than the modules listed above is
reused, copied, or adapted in Code Clearance. No attribution is owed
beyond this notice.
