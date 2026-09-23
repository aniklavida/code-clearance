package mcpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/code-clearance/internal/app"
	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/mcpserver"
	"github.com/aniklavida/code-clearance/internal/normalize"
	"github.com/aniklavida/code-clearance/internal/policy"
	"github.com/aniklavida/code-clearance/internal/report"
)

// Done-when: secrets planted in scanner output must not leak into the
// normalized finding, the generated report, or the payload an MCP tool hands
// to an agent. The fake secrets are assembled at runtime so no credential
// literal exists in the repository.
func TestSecretRedaction_ScannerOutputReportAndMCPPayload(t *testing.T) {
	slackSecret := strings.Join([]string{"xoxb", "777450471234", "7774504712345", "ZmFrZXNlY3JldG9ubHk"}, "-")
	stripeSecret := strings.Join([]string{"sk", "live", "51H8x9K2eZvKYlo2CkQ7tNGGyRfTeStFiXtUrEsAbCdEfGh"}, "_")

	scannerOutput := `[
		{
			"Description": "Found Slack Bot Token: ` + slackSecret + ` in environment",
			"StartLine": 1,
			"EndLine": 1,
			"StartColumn": 1,
			"EndColumn": 40,
			"Match": "` + slackSecret + `",
			"Secret": "` + slackSecret + `",
			"File": "config/secrets.py",
			"RuleID": "slack-bot-token",
			"Entropy": 3.9
		},
		{
			"Description": "Found Stripe Live Key in source code: ` + stripeSecret + `",
			"StartLine": 2,
			"EndLine": 2,
			"StartColumn": 1,
			"EndColumn": 60,
			"Match": "STRIPE_KEY = \"` + stripeSecret + `\"",
			"Secret": "` + stripeSecret + `",
			"File": "config/stripe.py",
			"RuleID": "stripe-access-token",
			"Entropy": 4.2
		}
	]`

	// Control: the scanner output really does contain the planted values, so a
	// pass here cannot be vacuous.
	if !strings.Contains(scannerOutput, slackSecret) || !strings.Contains(scannerOutput, stripeSecret) {
		t.Fatal("test fixture is malformed: planted secrets are not present in scanner output")
	}

	// A scanner adapter that behaves like a real one: it ingests raw scanner
	// output through the normalization boundary.
	secretAdapter := func(ctx context.Context, targetDir string) []evidence.RunOutcome {
		findings, err := normalize.Ingest("gitleaks", "v8.30.1", "json", []byte(scannerOutput))
		if err != nil {
			return []evidence.RunOutcome{{
				Tool: "gitleaks", ToolVersion: "v8.30.1", Status: evidence.StatusUnavailable,
				StderrTail: "ingest failed: " + err.Error(),
			}}
		}
		return []evidence.RunOutcome{{
			Tool:        "gitleaks",
			ToolVersion: "v8.30.1",
			Command:     "gitleaks detect --report-format json",
			ExitCode:    1,
			Status:      evidence.StatusFindings,
			Findings:    findings,
			RawData:     []byte(scannerOutput),
		}}
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := policy.DefaultConfig()
	cfg.Adapters.Required = []string{"gitleaks"}

	rep, err := app.NewEngine(secretAdapter).ScanWithOptions(context.Background(), dir, app.ScanOptions{
		Scope:  "full",
		Config: &cfg,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no findings produced from scanner output; redaction test would be vacuous")
	}

	secrets := []string{slackSecret, stripeSecret}

	// Raw evidence is preserved locally on disk by design; only the agent-facing
	// surfaces must be redacted. Asserting the raw file still holds the secret
	// keeps that trade-off explicit rather than accidental.
	var rawURI string
	for _, r := range rep.Runs {
		if r.Tool == "gitleaks" && r.RawArtifact != nil {
			rawURI = r.RawArtifact.URI
		}
	}
	if rawURI == "" {
		t.Fatal("raw artifact reference missing; cannot verify evidence preservation")
	}
	rawBytes, err := os.ReadFile(rawURI)
	if err != nil {
		t.Fatalf("read raw artifact: %v", err)
	}
	if !strings.Contains(string(rawBytes), slackSecret) {
		t.Fatal("raw scanner evidence was destroyed; local evidence must be preserved even when agent-facing output is redacted")
	}

	// Surface 1: the normalized finding derived from scanner output.
	for _, f := range rep.Findings {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		assertNoPlantedSecret(t, "normalized finding (scanner-output surface)", string(b), secrets)
	}

	// Surface 2: the generated report as rendered by the report package.
	var buf bytes.Buffer
	if err := report.WriteJSON(rep, &buf); err != nil {
		t.Fatalf("render report: %v", err)
	}
	assertNoPlantedSecret(t, "generated report", buf.String(), secrets)

	// Surface 3: the exact payload type the MCP scan tool hands to an agent.
	var payload mcpserver.ScanOutput = rep
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal MCP payload: %v", err)
	}
	assertNoPlantedSecret(t, "MCP agent payload", string(pb), secrets)
}

func assertNoPlantedSecret(t *testing.T, surface, payload string, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(payload, secret) {
			t.Fatalf("SECURITY VIOLATION: %s leaked a planted secret", surface)
		}
	}
	if !strings.Contains(payload, "[REDACTED]") {
		t.Fatalf("%s does not contain the redaction marker", surface)
	}
}
