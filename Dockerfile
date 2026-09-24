# syntax=docker/dockerfile:1
#
# Code Clearance container image for users who want an isolated scanner run.
#
# NOTICE: Code Clearance shells out to external scanners (gitleaks,
# osv-scanner, semgrep, trivy). Those engines are deliberately NOT vendored
# into this image — see AGENTS.md and THIRD_PARTY_NOTICES.md. This image
# contains the CLI only. Provide scanners by building a derived image that
# installs them, or by mounting them and putting them on PATH. Without them,
# the report honestly records the checks as unavailable and returns
# `incomplete` for a required adapter, never a pass.
#
# This Dockerfile was reviewed statically and was NOT built or run as part of
# the release-tooling change that added it. Verify it with:
#
#   docker build -t code-clearance:dev .
#   docker run --rm -v "$PWD:/src" code-clearance:dev scan --scope quick /src

FROM golang:1.27-alpine AS build

ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/code-clearance ./cmd/code-clearance

FROM alpine:3.21

# CA certificates so a user who explicitly enables network-backed scanner
# updates is not blocked by a missing trust store. Default scanning opens no
# network connection regardless.
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 clearance

COPY --from=build /out/code-clearance /usr/local/bin/code-clearance

WORKDIR /src
USER clearance

ENTRYPOINT ["/usr/local/bin/code-clearance"]
CMD ["--help"]
