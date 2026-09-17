package adapters

import (
	"context"
	"testing"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

func TestAdapters_ContractDeclarations(t *testing.T) {
	adapters := []Adapter{
		NewGitleaksAdapter(),
		NewOSVScannerAdapter(),
	}

	for _, a := range adapters {
		t.Run(a.Name(), func(t *testing.T) {
			// Capability must not be empty
			if a.Capability() == "" {
				t.Errorf("%s declared empty capability", a.Name())
			}

			// Availability is a REQUIRED declaration, not optional
			avail := a.Availability(context.Background())
			if avail.Reason == "" {
				t.Errorf("%s returned empty availability reason", a.Name())
			}
			// When available, Path must be non-empty
			if avail.Available && avail.Path == "" {
				t.Errorf("%s is declared available but path is empty", a.Name())
			}

			// Version must not be empty
			if a.Version() == "" {
				t.Errorf("%s declared empty version", a.Name())
			}

			// InputScope must not be empty
			if a.InputScope() == "" {
				t.Errorf("%s declared empty input scope", a.Name())
			}

			// Command must be declared
			cmd := a.Command("test-target")
			if len(cmd) == 0 {
				t.Errorf("%s declared empty command slice", a.Name())
			}

			// ExitSemantics must define success codes
			exit := a.ExitSemantics()
			if len(exit.SuccessExitCodes) == 0 {
				t.Errorf("%s declared empty success exit codes", a.Name())
			}

			// Descriptor must match individual methods
			desc := a.Descriptor(context.Background(), "test-target")
			if desc.Name != a.Name() {
				t.Errorf("descriptor name %q != %q", desc.Name, a.Name())
			}
			if desc.Capability != a.Capability() {
				t.Errorf("descriptor capability %q != %q", desc.Capability, a.Capability())
			}
			if desc.Version != a.Version() {
				t.Errorf("descriptor version %q != %q", desc.Version, a.Version())
			}
			if desc.InputScope != a.InputScope() {
				t.Errorf("descriptor scope %q != %q", desc.InputScope, a.InputScope())
			}
		})
	}
}

func TestAdapters_UnavailableToolProducesNotInstalledStatus(t *testing.T) {
	// Test that an unavailable adapter returns StatusNotInstalled, never StatusOK
	fakeAdapter := &GitleaksAdapter{version: "v999.0.0"}
	ctx := context.Background()

	// If gitleaks is not on PATH or if we simulate uninstalled
	avail := fakeAdapter.Availability(ctx)
	if !avail.Available {
		outcome := fakeAdapter.Run(ctx, ".")
		if outcome.Status != evidence.StatusNotInstalled {
			t.Fatalf("expected StatusNotInstalled for missing tool, got %s", outcome.Status)
		}
		if outcome.Status == evidence.StatusOK {
			t.Fatal("unavailable adapter produced StatusOK!")
		}
	}
}
