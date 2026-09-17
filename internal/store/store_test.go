package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

func TestStore_SaveAndRetrieveArtifact(t *testing.T) {
	dir := t.TempDir()
	st, err := New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatalf("New store: %v", err)
	}

	session, err := st.CreateRun("test-run-1")
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	rawPayload := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}}}]}`)
	ref, err := session.SaveArtifact("gitleaks", "sarif", rawPayload)
	if err != nil {
		t.Fatalf("SaveArtifact: %v", err)
	}

	if ref.Format != "sarif" {
		t.Fatalf("ref.Format = %q, want sarif", ref.Format)
	}
	if ref.URI == "" {
		t.Fatal("ref.URI must not be empty")
	}

	// Verify content retrievable by reference
	retrieved, err := st.GetArtifact(ref)
	if err != nil {
		t.Fatalf("GetArtifact: %v", err)
	}
	if !bytes.Equal(retrieved, rawPayload) {
		t.Fatalf("retrieved bytes do not match saved bytes: %s vs %s", retrieved, rawPayload)
	}
}

func TestStore_DiscardCleansUpTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	st, err := New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatalf("New store: %v", err)
	}

	session, err := st.CreateRun("test-run-interrupted")
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	// Create a synthetic incomplete temp file simulating interrupted write
	tmpFile := filepath.Join(session.ArtifactsDir(), "interrupted.tmp")
	if err := os.WriteFile(tmpFile, []byte("partial content"), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	session.tmpFiles = append(session.tmpFiles, tmpFile)

	// Discard should remove the temp file
	session.Discard()

	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Fatal("incomplete temp file was not removed on discard")
	}
}

func TestStore_RetainsArtifactAfterNormalization(t *testing.T) {
	dir := t.TempDir()
	st, err := New(filepath.Join(dir, ".clearance"))
	if err != nil {
		t.Fatalf("New store: %v", err)
	}

	session, err := st.CreateRun("")
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	sarifBytes := []byte(`{"runs":[{"results":[{"ruleId":"leak-1"}]}]}`)
	ref, err := session.SaveArtifact("osv-scanner", "sarif", sarifBytes)
	if err != nil {
		t.Fatalf("SaveArtifact: %v", err)
	}

	// Simulate normalization creating finding with this artifact reference
	finding := evidence.Finding{
		ID:          "f-001",
		Tool:        "osv-scanner",
		RawArtifact: ref,
		RawIndex:    0,
	}

	// Verify the finding's referenced artifact is intact and readable
	retrieved, err := st.GetArtifact(finding.RawArtifact)
	if err != nil {
		t.Fatalf("GetArtifact from finding.RawArtifact: %v", err)
	}
	if !bytes.Equal(retrieved, sarifBytes) {
		t.Fatalf("retrieved finding raw artifact mismatch: %s", retrieved)
	}
}
