#!/usr/bin/env bash
#
# Install a tagged Code Clearance binary and refuse to install it unless its
# sha256 matches the published checksums.txt.
#
# Usage:
#   scripts/install.sh v1.0.0
#   INSTALL_DIR=/usr/local/bin scripts/install.sh v1.0.0
#
# This downloads over HTTPS from the GitHub release, verifies the checksum,
# and — when the `gh` CLI is available — verifies the build-provenance
# attestation too. It never runs `sudo`.
#
set -euo pipefail

repo="aniklavida/code-clearance"
version="${1:-}"
install_dir="${INSTALL_DIR:-$HOME/.local/bin}"

if [ -z "$version" ]; then
  echo "usage: $0 <tag>            e.g. $0 v1.0.0" >&2
  echo "       INSTALL_DIR=... $0 <tag>" >&2
  exit 2
fi

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *)
    echo "error: unsupported operating system: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *)
    echo "error: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

asset="code-clearance_${version}_${os}_${arch}"
base="https://github.com/${repo}/releases/download/${version}"

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "error: need sha256sum or shasum to verify the download" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/code-clearance-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${asset} (${version})..."
curl -fsSL "${base}/${asset}" -o "${tmp}/${asset}"
curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt"

expected="$(awk -v a="$asset" '$2 == a {print $1}' "${tmp}/checksums.txt")"
if [ -z "$expected" ]; then
  echo "error: ${asset} is not listed in the release's checksums.txt" >&2
  exit 1
fi

actual="$(sha256 "${tmp}/${asset}")"
if [ "$expected" != "$actual" ]; then
  echo "error: checksum mismatch for ${asset}" >&2
  echo "  expected: ${expected}" >&2
  echo "  actual:   ${actual}" >&2
  exit 1
fi
echo "sha256 OK: ${actual}"

if command -v gh >/dev/null 2>&1; then
  echo "Verifying build provenance..."
  gh attestation verify "${tmp}/${asset}" --repo "${repo}"
else
  echo "note: gh CLI not found; skipping provenance attestation check" >&2
fi

mkdir -p "$install_dir"
install -m 0755 "${tmp}/${asset}" "${install_dir}/code-clearance"
echo "Installed ${install_dir}/code-clearance"
echo "Run 'code-clearance version' to confirm the tag and platform."
