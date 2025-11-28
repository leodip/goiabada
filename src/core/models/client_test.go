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

// Tests for IsImplicitGrantEnabled

func TestIsImplicitGrantEnabled_ClientOverrideTrue(t *testing.T) {
	implicitGrantEnabled := true
	client := &Client{
		ImplicitGrantEnabled: &implicitGrantEnabled,
	}

	// Client override should take precedence over global setting
	if got := client.IsImplicitGrantEnabled(false); got != true {
		t.Errorf("IsImplicitGrantEnabled(false) = %v, want true (client override)", got)
	}
	if got := client.IsImplicitGrantEnabled(true); got != true {
		t.Errorf("IsImplicitGrantEnabled(true) = %v, want true (client override)", got)
	}
}

func TestIsImplicitGrantEnabled_ClientOverrideFalse(t *testing.T) {
	implicitGrantEnabled := false
	client := &Client{
		ImplicitGrantEnabled: &implicitGrantEnabled,
	}

	// Client override should take precedence over global setting
	if got := client.IsImplicitGrantEnabled(true); got != false {
		t.Errorf("IsImplicitGrantEnabled(true) = %v, want false (client override)", got)
	}
	if got := client.IsImplicitGrantEnabled(false); got != false {
		t.Errorf("IsImplicitGrantEnabled(false) = %v, want false (client override)", got)
	}
}

func TestIsImplicitGrantEnabled_ClientNilUsesGlobalTrue(t *testing.T) {
	client := &Client{
		ImplicitGrantEnabled: nil, // No client-level override
	}

	// Should use global setting
	if got := client.IsImplicitGrantEnabled(true); got != true {
		t.Errorf("IsImplicitGrantEnabled(true) = %v, want true (global setting)", got)
	}
}

func TestIsImplicitGrantEnabled_ClientNilUsesGlobalFalse(t *testing.T) {
	client := &Client{
		ImplicitGrantEnabled: nil, // No client-level override
	}

	// Should use global setting
	if got := client.IsImplicitGrantEnabled(false); got != false {
		t.Errorf("IsImplicitGrantEnabled(false) = %v, want false (global setting)", got)
	}
}

// Tests for IsResourceOwnerPasswordCredentialsEnabled (ROPC)

func TestIsResourceOwnerPasswordCredentialsEnabled_ClientOverrideTrue(t *testing.T) {
	ropcEnabled := true
	client := &Client{
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	// Client override should take precedence over global setting
	if got := client.IsResourceOwnerPasswordCredentialsEnabled(false); got != true {
		t.Errorf("IsResourceOwnerPasswordCredentialsEnabled(false) = %v, want true (client override)", got)
	}
	if got := client.IsResourceOwnerPasswordCredentialsEnabled(true); got != true {
		t.Errorf("IsResourceOwnerPasswordCredentialsEnabled(true) = %v, want true (client override)", got)
	}
}

func TestIsResourceOwnerPasswordCredentialsEnabled_ClientOverrideFalse(t *testing.T) {
	ropcEnabled := false
	client := &Client{
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	// Client override should take precedence over global setting
	if got := client.IsResourceOwnerPasswordCredentialsEnabled(true); got != false {
		t.Errorf("IsResourceOwnerPasswordCredentialsEnabled(true) = %v, want false (client override)", got)
	}
	if got := client.IsResourceOwnerPasswordCredentialsEnabled(false); got != false {
		t.Errorf("IsResourceOwnerPasswordCredentialsEnabled(false) = %v, want false (client override)", got)
	}
}

func TestIsResourceOwnerPasswordCredentialsEnabled_ClientNilUsesGlobalTrue(t *testing.T) {
	client := &Client{
		ResourceOwnerPasswordCredentialsEnabled: nil, // No client-level override
	}

	// Should use global setting
	if got := client.IsResourceOwnerPasswordCredentialsEnabled(true); got != true {
		t.Errorf("IsResourceOwnerPasswordCredentialsEnabled(true) = %v, want true (global setting)", got)
	}
}

func TestIsResourceOwnerPasswordCredentialsEnabled_ClientNilUsesGlobalFalse(t *testing.T) {
	client := &Client{
		ResourceOwnerPasswordCredentialsEnabled: nil, // No client-level override
	}

	// Should use global setting
	if got := client.IsResourceOwnerPasswordCredentialsEnabled(false); got != false {
		t.Errorf("IsResourceOwnerPasswordCredentialsEnabled(false) = %v, want false (global setting)", got)
	}
}
