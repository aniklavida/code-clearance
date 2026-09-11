# Build-to-release roadmap

This roadmap ends at a useful, market-ready v1.0. Detailed cards belong in Notion only for the current and next milestone.

## 0. Foundation and interface validation

Validate Go process orchestration, SARIF ingestion and the official MCP flow; then lock the report schema and initial adapter contracts.

**Done:** one MCP call runs a fixture adapter and returns normalized, commit-bound evidence.

## 1. Evidence engine

Build discovery, runner, artifacts, normalization, fingerprinting and correlation; integrate Semgrep, Gitleaks and OSV-Scanner/Trivy; support Quick and Full scopes plus terminal/JSON output.

**Done:** representative JS/TS, Python and Go fixtures produce stable results, including honest failures and unavailable-tool states.

## 2. Challenge, fix and verification

Add review dispositions, fix context, finding-to-patch lineage, targeted reruns, policy outcomes and residual-risk reporting.

**Done:** an MCP-connected agent completes scan → challenge → fix → verify → report on a fixture repository.

## 3. Daily-use integrations

Complete init/doctor onboarding, GitHub Action and PR annotations, baselines, expiring risk acceptance, HTML report, Release mode and supported-host MCP installation tests.

**Done:** a new user works locally and on a PR without manually operating scanners.

## 4. Hardening and documentation

Test failure boundaries and malicious configuration; stabilize schemas; complete quick start, architecture, adapter guide, examples, security policy, contribution guide and third-party notices; dogfood Code Clearance on itself.

**Done:** all v1.0 acceptance criteria pass on clean macOS/Linux environments and an independent documentation walkthrough succeeds.

## 5. Public release and marketing handoff

Publish tagged binaries, checksums, changelog, demo assets and distribution instructions; launch around the verified evidence loop; seed contributor-friendly issues and establish bug/security intake.

**Done:** v1.0 is publicly installable, demonstrably useful and has no unfinished core promise.

## After v1.0

Maintenance mode: fix reproducible bugs/security issues, update adapters, review community contributions and add features only when repeated user demand or strong evidence justifies them.
