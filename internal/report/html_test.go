package report_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/report"
)

type countingTransport struct {
	calls int
}

func (t *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, nil
}

func TestHTMLReportRendersOfflineWithCoverageAndResidualRisk(t *testing.T) {
	r := minimalValidReport()
	r.Coverage.Profile = "team"
	r.Coverage.Summary = "3 files checked; 2 checks ran"
	r.Baseline = &evidence.BaselineReport{Source: ".clearance/baseline.json", FingerprintCount: 4, SuppressedCount: 2, Active: true}
	r.ResidualRisk = []evidence.ResidualRiskItem{{FindingID: "F-1", Severity: evidence.SeverityMedium, Reason: "temporary migration exception", AcceptedBy: "alice", ExpiresAt: "2030-01-01T00:00:00Z"}}
	r.Findings = []evidence.Finding{{Fingerprint: "fp-1", RuleID: "rule-1", Message: "example finding", NormalizedSeverity: evidence.SeverityMedium, ChallengeStatus: evidence.ChallengeUnreviewed, SuppressedByBaseline: true, Evidence: evidence.FindingEvidence{Details: "raw evidence"}}}
	r.Timestamps = evidence.ReportTimestamps{StartedAt: time.Now().Format(time.RFC3339), CompletedAt: time.Now().Format(time.RFC3339)}

	transport := &countingTransport{}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = oldTransport }()

	var output bytes.Buffer
	if err := report.WriteHTML(r, &output); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if transport.calls != 0 {
		t.Fatalf("HTML rendering attempted %d network call(s)", transport.calls)
	}
	for _, forbidden := range []string{"<script", "<link", " src=", " href=", "url(", "http://", "https://"} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("offline HTML contains forbidden network construct %q", forbidden)
		}
	}
	for _, required := range []string{"Coverage", "3 files checked", "Residual risk", "temporary migration exception", "Baseline", "suppressed by baseline", "raw evidence"} {
		if !strings.Contains(html, required) {
			t.Fatalf("HTML report missing %q", required)
		}
	}
}
