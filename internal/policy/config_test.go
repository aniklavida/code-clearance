package policy

import (
	"reflect"
	"testing"
)

func TestConfig_ProfileFallbackOverrides(t *testing.T) {
	cfg := DefaultConfig()
	// Override the top-level required adapters
	cfg.Adapters.Required = []string{"my-custom-adapter"}

	// Act: resolve active profile for quick scope
	prof := cfg.ActiveProfile("quick")

	// Assert: the active profile should inherit the top-level override
	if !reflect.DeepEqual(prof.Adapters.Required, []string{"my-custom-adapter"}) {
		t.Errorf("Expected ActiveProfile to inherit global Adapters.Required override, got %v", prof.Adapters.Required)
	}
}
