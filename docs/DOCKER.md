# Running Code Clearance in a container

`Dockerfile` builds a small image containing the `code-clearance` CLI for
users who prefer an isolated run. It is an optional execution path, not the
supported install path for v1.0.

> **Not verified in this repository.** The image was written and reviewed by
> static inspection only. It has not been built or run in the session that
> added the release tooling. Run `docker build ...` yourself before relying on
> it.

## What is in the image

Only the CLI. Code Clearance invokes scanners as separate processes and does
not vendor their engines, so the image does **not** contain `gitleaks`,
`osv-scanner`, `semgrep` or `trivy`. Provide them by building a derived image
or by mounting them and adding them to `PATH`. A missing required scanner is
reported as `incomplete`; it is never treated as a pass.

## Build and run

```bash
docker build -t code-clearance:dev .

# Mount the repository you want checked at /src.
docker run --rm -v "$PWD:/src" code-clearance:dev scan --scope quick /src
```

## Add scanners with a derived image

```dockerfile
FROM code-clearance:dev
USER root
# Install your pinned scanner binaries here, then drop back to the
# unprivileged user. Pin versions and verify downloads; do not fetch
# "latest" unpinned.
USER clearance
```

## Uninstall

```bash
docker image rm code-clearance:dev
```
