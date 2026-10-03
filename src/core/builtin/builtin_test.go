package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIdentifiers pins every identifier to its spelling. Each is stored data or wire format: a
// scope a client asks for and a token carries, a row the seeder writes, or the name of a session
// both processes read, so a respelling would orphan what is already stored rather than fail.
func TestIdentifiers(t *testing.T) {
	assert.Equal(t, "authserver", AuthServerResourceIdentifier)
	assert.Equal(t, "manage-account", ManageAccountPermissionIdentifier)
	assert.Equal(t, "manage", ManagePermissionIdentifier)
	assert.Equal(t, "admin-read", AdminReadPermissionIdentifier)
	assert.Equal(t, "manage-users", ManageUsersPermissionIdentifier)
	assert.Equal(t, "manage-clients", ManageClientsPermissionIdentifier)
	assert.Equal(t, "manage-settings", ManageSettingsPermissionIdentifier)
	assert.Equal(t, "browser-sessions", BrowserSessionsPermissionIdentifier)
	assert.Equal(t, "admin-console-client", AdminConsoleClientIdentifier)
	assert.Equal(t, "adminconsole", AdminConsoleSessionName)
}

// TestAuthServerPermissionIdentifiers pins the list to the seven runtime scope checks name, in the
// order the seeder and the admin UI have always read them. userinfo left the list in #449:
// /userinfo gates on the openid scope, so nothing checks for that permission.
func TestAuthServerPermissionIdentifiers(t *testing.T) {
	assert.Equal(t, []string{
		"manage-account",
		"manage",
		"admin-read",
		"manage-users",
		"manage-clients",
		"manage-settings",
		"browser-sessions",
	}, AuthServerPermissionIdentifiers())
}

// TestAuthServerPermissionIdentifiers_EachCallIsItsOwnCopy is why the list is a function rather
// than an exported slice: a caller that sorts, appends to or overwrites what it was handed cannot
// change which permissions the next caller treats as undeletable (#442).
func TestAuthServerPermissionIdentifiers_EachCallIsItsOwnCopy(t *testing.T) {
	first := AuthServerPermissionIdentifiers()
	require.Len(t, first, 7)
	first[0] = "overwritten"
	_ = append(first[:1], "appended")

	assert.Equal(t, "manage-account", AuthServerPermissionIdentifiers()[0])
	assert.Equal(t, "manage", AuthServerPermissionIdentifiers()[1])
}
