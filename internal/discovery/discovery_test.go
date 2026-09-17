package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aniklavida/code-clearance/internal/adapters"
	"github.com/aniklavida/code-clearance/internal/evidence"
)

func TestDetectStack_GoRepository(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	info := DetectStack(dir)

	foundGo := false
	for _, l := range info.Languages {
		if l == "go" {
			foundGo = true
		}
	}
	if !foundGo {
		t.Fatalf("expected 'go' in detected languages, got %v", info.Languages)
	}
	if len(info.Manifests) == 0 || info.Manifests[0] != "go.mod" {
		t.Fatalf("expected go.mod in manifests, got %v", info.Manifests)
	}
}

func TestDetectStack_MultiLanguage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	info := DetectStack(dir)

	hasJS := false
	hasPy := false
	for _, l := range info.Languages {
		if l == "javascript" {
			hasJS = true
		}
		if l == "python" {
			hasPy = true
		}
	}
	if !hasJS || !hasPy {
		t.Fatalf("expected javascript and python in languages, got %v", info.Languages)
	}
	if len(info.Lockfiles) == 0 || info.Lockfiles[0] != "package-lock.json" {
		t.Fatalf("expected package-lock.json in lockfiles, got %v", info.Lockfiles)
	}
}

func TestDiscoverAdapters_FirstClassAvailabilityRecord(t *testing.T) {
	mockInstalled := &mockAdapterHelper{
		name:      "mock-present",
		available: true,
		reason:    "installed",
	}
	mockMissing := &mockAdapterHelper{
		name:      "mock-missing",
		available: false,
		reason:    "executable missing on PATH",
	}

	results := DiscoverAdapters(context.Background(), []adapters.Adapter{mockInstalled, mockMissing})

	if len(results) != 2 {
		t.Fatalf("expected 2 discovered adapters, got %d", len(results))
	}

	// Missing tool must be present in discovery results as Available=false, never silently omitted
	foundMissing := false
	for _, r := range results {
		if r.Name == "mock-missing" {
			foundMissing = true
			if r.Available {
				t.Error("mock-missing reported as available!")
			}
			if r.Reason != "executable missing on PATH" {
				t.Errorf("mock-missing reason = %q, want %q", r.Reason, "executable missing on PATH")
			}
		}
	}
	if !foundMissing {
		t.Fatal("unavailable adapter was silently omitted from discovery results!")
	}
}

type mockAdapterHelper struct {
	name      string
	available bool
	reason    string
}

func (m *mockAdapterHelper) Name() string                    { return m.name }
func (m *mockAdapterHelper) Capability() adapters.Capability { return adapters.CapabilitySecrets }
func (m *mockAdapterHelper) Version() string                 { return "v1.0.0" }
func (m *mockAdapterHelper) InputScope() adapters.InputScope { return adapters.ScopeRepository }
func (m *mockAdapterHelper) Command(t string) []string       { return []string{m.name} }
func (m *mockAdapterHelper) ExitSemantics() adapters.ExitSemantics {
	return adapters.ExitSemantics{SuccessExitCodes: []int{0}}
}
func (m *mockAdapterHelper) Descriptor(ctx context.Context, t string) adapters.Descriptor {
	return adapters.Descriptor{Name: m.name}
}
func (m *mockAdapterHelper) Availability(ctx context.Context) adapters.Availability {
	path := ""
	if m.available {
		path = "/bin/" + m.name
	}
	return adapters.Availability{
		Available: m.available,
		Reason:    m.reason,
		Path:      path,
	}
}
func (m *mockAdapterHelper) Run(ctx context.Context, target string) evidence.RunOutcome {
	return evidence.RunOutcome{}
}
