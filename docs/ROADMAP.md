# Build-to-release roadmap

This roadmap ends at a useful, market-ready v1.0, supporting Linux, macOS and Windows. Capability claims use **Implemented and tested**, **Experimental**, **Planned for v1.0** or **Unsupported**. The README is the current status summary; this file records the remaining acceptance work.

## 0. Foundation and interface validation — **Implemented and tested**

Validated Go process orchestration, SARIF ingestion and the official MCP flow; locked Go, the official MCP Go SDK and the lightweight-core-plus-external-adapters architecture. Windows process-tree termination (job objects, alongside the POSIX process-group approach) and the exact platform/toolchain proof are being finished before implementation starts.

**Done:** one MCP call runs a fixture adapter and returns normalized, commit-bound evidence.

## 1. Evidence engine — **Implemented and tested**

Build discovery, runner, artifacts, normalization, fingerprinting and correlation; integrate Semgrep, Gitleaks and OSV-Scanner/Trivy; support Quick and Full scopes plus terminal/JSON output.

**Done:** representative JS/TS, Python and Go fixtures produce stable results, including honest failures and unavailable-tool states.

## 2. Challenge, fix and verification — **Implemented and tested**

Add review dispositions, fix context, finding-to-patch lineage, targeted reruns, policy outcomes and residual-risk reporting.

**Done:** an MCP-connected agent completes scan → challenge → fix → verify → report on a fixture repository.

## 3. Daily-use integrations — **Implemented and tested**

Complete init/doctor onboarding, GitHub Action and PR annotations, baselines, expiring risk acceptance, HTML report, Release mode and supported-host MCP installation tests.

**Done:** a new user works locally and on a PR without manually operating scanners.

## 4. Hardening and documentation — **Experimental**

Test failure boundaries and malicious configuration; stabilize schemas; complete quick start, architecture, adapter guide, examples, security policy, contribution guide and third-party notices; dogfood Code Clearance on itself.

**Implemented and tested:** failure boundaries, hostile configuration handling, schema compatibility, source-build quick start, architecture/configuration/policy/adapter/report documentation, three language fixtures, security/contribution documentation and a real full-repository dogfood run with its complete blocked result published.

**Still pending:**

- **Planned for v1.0:** all v1.0 acceptance criteria on clean Linux, macOS and Windows environments;
- **Planned for v1.0:** a private working security-reporting path;
- **Planned for v1.0:** published release artifacts and release workflow execution;
- **Planned for v1.0:** live GitHub Actions verification;
- **Planned for v1.0:** an independent documentation walkthrough by a person who did not write the instructions. This acceptance item remains explicitly unchecked because a self-authored run is not independent evidence;
- **Experimental:** Quick changed-file adapter execution, complete required-command policy gating, Semgrep/Trivy real-process verification and Windows release packaging.

## 5. Public release and marketing handoff

Publish tagged binaries, checksums, changelog, demo assets and distribution instructions; launch around the verified evidence loop; seed contributor-friendly issues and establish bug/security intake.

**Done:** v1.0 is publicly installable, demonstrably useful and has no unfinished core promise.

## After v1.0

Maintenance mode: fix reproducible bugs/security issues, update adapters, review community contributions and add features only when repeated user demand or strong evidence justifies them.
