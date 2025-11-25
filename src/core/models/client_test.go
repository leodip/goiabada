package models

import (
	"testing"

	"github.com/leodip/goiabada/core/constants"
)

func TestIsPKCERequired_ClientOverrideTrue(t *testing.T) {
	pkceRequired := true
	client := &Client{
		PKCERequired: &pkceRequired,
	}

	// Client override should take precedence over global setting
	if got := client.IsPKCERequired(false); got != true {
		t.Errorf("IsPKCERequired(false) = %v, want true (client override)", got)
	}
	if got := client.IsPKCERequired(true); got != true {
		t.Errorf("IsPKCERequired(true) = %v, want true (client override)", got)
	}
}

func TestIsPKCERequired_ClientOverrideFalse(t *testing.T) {
	pkceRequired := false
	client := &Client{
		PKCERequired: &pkceRequired,
	}

	// Client override should take precedence over global setting
	if got := client.IsPKCERequired(true); got != false {
		t.Errorf("IsPKCERequired(true) = %v, want false (client override)", got)
	}
	if got := client.IsPKCERequired(false); got != false {
		t.Errorf("IsPKCERequired(false) = %v, want false (client override)", got)
	}
}

func TestIsPKCERequired_ClientNilUsesGlobalTrue(t *testing.T) {
	client := &Client{
		PKCERequired: nil, // No client-level override
	}

	// Should use global setting
	if got := client.IsPKCERequired(true); got != true {
		t.Errorf("IsPKCERequired(true) = %v, want true (global setting)", got)
	}
}

func TestIsPKCERequired_ClientNilUsesGlobalFalse(t *testing.T) {
	client := &Client{
		PKCERequired: nil, // No client-level override
	}

	// Should use global setting
	if got := client.IsPKCERequired(false); got != false {
		t.Errorf("IsPKCERequired(false) = %v, want false (global setting)", got)
	}
}

func TestIsSystemLevelClient(t *testing.T) {
	tests := []struct {
		name             string
		clientIdentifier string
		expected         bool
	}{
		{"AdminConsoleClient", constants.AdminConsoleClientIdentifier, true},
		{"NonSystemClient", "regular-client", false},
		{"EmptyIdentifier", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{ClientIdentifier: tt.clientIdentifier}
			if got := client.IsSystemLevelClient(); got != tt.expected {
				t.Errorf("IsSystemLevelClient() = %v, want %v", got, tt.expected)
			}
		})
	}
}
