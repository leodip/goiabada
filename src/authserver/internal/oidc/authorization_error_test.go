package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAuthorizationErrorCodesAreWireValues holds the three OIDC authorization error codes, which a
// client matches on. They are fixed by OpenID Connect Core 1.0 section 3.1.2.6 rather than by
// this repository, so they are not ours to spell differently.
func TestAuthorizationErrorCodesAreWireValues(t *testing.T) {
	assert.Equal(t, "login_required", ErrorLoginRequired)
	assert.Equal(t, "consent_required", ErrorConsentRequired)
	assert.Equal(t, "interaction_required", ErrorInteractionRequired)
}
