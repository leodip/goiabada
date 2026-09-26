package constants

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGranularScopeConstants verifies that granular scope constants are correctly defined
// and follow the expected naming conventions
func TestGranularScopeConstants(t *testing.T) {
	// Verify the constants exist and have expected values
	assert.Equal(t, "admin-read", AdminReadPermissionIdentifier)
	assert.Equal(t, "manage-users", ManageUsersPermissionIdentifier)
	assert.Equal(t, "manage-clients", ManageClientsPermissionIdentifier)
	assert.Equal(t, "manage-settings", ManageSettingsPermissionIdentifier)

	// Verify backwards-compatible manage permission
	assert.Equal(t, "manage", ManagePermissionIdentifier)

	// Verify authserver resource identifier (used to construct full scope)
	assert.Equal(t, "authserver", AuthServerResourceIdentifier)
}

// TestScopeConstantsAreUnique verifies that the built-in permission identifiers are unique, and
// that they are the seven runtime scope checks name. userinfo left the list in #449: /userinfo
// gates on the openid scope, so nothing checks for that permission.
func TestScopeConstantsAreUnique(t *testing.T) {
	assert.Len(t, BuiltInAuthServerPermissionIdentifiers, 7)
	assert.NotContains(t, BuiltInAuthServerPermissionIdentifiers, "userinfo")

	seen := make(map[string]bool)
	for _, perm := range BuiltInAuthServerPermissionIdentifiers {
		assert.False(t, seen[perm], "Duplicate permission identifier found: %s", perm)
		seen[perm] = true
	}
}
