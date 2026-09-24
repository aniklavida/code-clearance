#!/usr/bin/env bash
#
# Code Clearance public demo.
#
# Runs the real scan -> challenge -> fix -> verify -> report loop against a
# throwaway copy of this repository's own Go fixture, and prints evidence for
# the four beats the v1.0 release promises, in this locked order:
#
#   1. a confirmed issue
#   2. a rejected false positive
#   3. a verified fix
#   4. residual risk
#
# It needs the `gitleaks` binary on PATH. Nothing here uploads source, calls a
# network service, tags a release or touches your working tree: the fixture is
# copied to a temporary directory that is removed on exit.
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "error: gitleaks is required for the demo (https://github.com/gitleaks/gitleaks)" >&2
  exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/code-clearance-demo.XXXXXX")"
trap 'rm -rf "$work"' EXIT

bin="$work/code-clearance"
demo="$work/repo"
mkdir -p "$demo"

echo "==> Building code-clearance"
(cd "$repo_root" && go build -o "$bin" ./cmd/code-clearance)

echo "==> Seeding the demo repository from testdata/fixtures/go"
cp -R "$repo_root/testdata/fixtures/go/." "$demo/"

# One fixture credential, used three ways so the demo can exercise every beat.
# It is a throwaway key generated for this repository's tests, not a real one.
read -r -d '' demo_key <<'KEY' || true
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAr7ULYO1SLKbXGQpPed/j8GagMnAKymjiN83gyteEOsAAAAKAERs/DBEbP
wwAAAAtzc2gtZWQyNTUxOQAAACAr7ULYO1SLKbXGQpPed/j8GagMnAKymjiN83gyteEOsA
AAAEAx5v50Hayo1sFv5+40AX4g7gAEGUAWsHbx2EPJwB73LCvtQtg7VIsptcZCk953+PwZ
qAycArKaOI3zeDK14Q6wAAAAF2FuaWtATWRzLU1hYy1taW5pLmxvY2FsAQIDBAUG
-----END OPENSSH PRIVATE KEY-----
KEY

mkdir -p "$demo/service" "$demo/docs"

# A: a hardcoded key on a runtime code path -> confirmed, then fixed.
cat > "$demo/service/production_config.go" <<EOF
package service

// productionToken is injected directly into the binary at build time.
const productionToken = \`$demo_key\`
EOF

# B: the same key, but in a test fixture -> a false positive a reviewer rejects.
cat > "$demo/service/production_config_test.go" <<EOF
package service

// testToken is a fixture value used by this package's tests only.
const testToken = \`$demo_key\`
EOF

# C: a documented example credential -> accepted residual risk.
cat > "$demo/docs/example-credentials.md" <<EOF
# Example credentials

The scanner reads this file to prove it can flag a known-bad sample. It is a
documented example, not a live credential.

\`\`\`
$demo_key
\`\`\`
EOF

cat > "$demo/clearance.json" <<'EOF'
{
  "version": "v1",
  "adapters": { "required": ["gitleaks"], "optional": [] },
  "paths": { "include": ["**/*"], "exclude": ["**/.clearance/**"] },
  "scopes": {
    "quick": { "allow_dirty": true },
    "full": { "allow_dirty": true },
    "release": { "allow_dirty": true }
  },
  "policy": {
    "blocking_severities": ["critical", "high"],
    "allow_dirty": true,
    "accepted_risks": []
  },
  "commands": { "required": [], "optional": [] },
  "limits": { "timeout_seconds": 30, "max_concurrency": 2 },
  "outcomes": {
    "minimum_evidence": {
      "cleared": { "required_adapters_must_pass": true, "zero_blocking_findings": true, "clean_tree_required": false },
      "cleared_with_residual_risk": { "accepted_risks_unexpired": true },
      "blocked": { "blocking_finding_present": true },
      "incomplete": { "missing_required_adapter": true, "crashed_or_timed_out": true }
    }
  }
}
EOF

fingerprint_for() {
  # Print the fingerprint of the first finding whose location contains $1.
  "$bin" findings --dir "$demo" | python3 -c '
import json, sys
needle = sys.argv[1]
for f in json.load(sys.stdin):
    for loc in f.get("locations", []):
        if needle in loc.get("uri", ""):
            print(f["fingerprint"])
            sys.exit(0)
sys.exit(1)
' "$1"
}

status_for() {
  "$bin" findings --dir "$demo" | python3 -c '
import json, sys
needle = sys.argv[1]
for f in json.load(sys.stdin):
    for loc in f.get("locations", []):
        if needle in loc.get("uri", ""):
            print(f["challenge_status"])
            sys.exit(0)
sys.exit(1)
' "$1"
}

banner() {
  printf '\n======================================================================\n%s\n======================================================================\n' "$1"
}

banner "BEAT 1/4 - a confirmed issue blocks clearance"

fp_prod="$(fingerprint_for "production_config.go")"
echo "Production finding fingerprint: $fp_prod"
echo "Recording a human confirmation of the hardcoded production key..."
"$bin" record-review --dir "$demo" \
  --fingerprint "$fp_prod" \
  --status confirmed \
  --reason "hardcoded private key on a runtime code path" \
  --reviewer-type human --identity demo-maintainer >/dev/null

"$bin" scan --scope release "$demo" || true
echo

banner "BEAT 2/4 - a rejected false positive stops blocking, with a reason kept"

fp_test="$(fingerprint_for "production_config_test.go")"
echo "Test-fixture finding fingerprint: $fp_test"
echo "Recording the reviewer's rejection of the test fixture..."
"$bin" record-review --dir "$demo" \
  --fingerprint "$fp_test" \
  --status rejected \
  --reason "test fixture, not a real credential" \
  --reviewer-type human --identity demo-maintainer >/dev/null

echo "Test-fixture finding status is now: $(status_for "production_config_test.go")"
"$bin" scan --scope release "$demo" || true
echo

banner "BEAT 3/4 - the fix is verified by a targeted rerun, not asserted"

# Build a real unified diff for the fix so the lineage carries the patch.
cat > "$work/production_config.before" <<EOF
package service

// productionToken is injected directly into the binary at build time.
const productionToken = \`$demo_key\`
EOF
cat > "$work/production_config.after" <<'EOF'
package service

// productionToken is loaded from the environment at runtime.
const productionToken = ""
EOF
patch_file="$work/fix.patch"
diff -u -L a/service/production_config.go -L b/service/production_config.go \
  "$work/production_config.before" "$work/production_config.after" > "$patch_file" || true

cp "$work/production_config.after" "$demo/service/production_config.go"
echo "Applied $patch_file; verifying with a targeted gitleaks rerun..."
"$bin" verify --dir "$demo" \
  --fingerprint "$fp_prod" \
  --diff "$(cat "$patch_file")" \
  --approved || true
echo

banner "BEAT 4/4 - residual risk is declared, not hidden"

echo "Accepting the documented example credential as expiring residual risk..."
python3 - "$demo/clearance.json" <<'PY'
import json, sys
path = sys.argv[1]
cfg = json.load(open(path))
cfg["policy"]["accepted_risks"] = [{
    "rule_id": "private-key",
    "tool": "gitleaks",
    "reason": "documented example credential kept as a scanner fixture",
    "owner": "demo-maintainer",
    "expires_at": "2030-01-01T00:00:00Z",
}]
json.dump(cfg, open(path, "w"), indent=2)
PY

"$bin" scan --scope release "$demo" || true
echo

banner "DEMO COMPLETE"
echo "Beats shown, in order: confirmed issue -> rejected false positive ->"
echo "verified fix -> residual risk."
