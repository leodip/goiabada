// Package builtin holds the identifiers both processes must agree on: the auth server's resource,
// the seven permissions on it that runtime scope checks name and that cannot be renamed or deleted,
// and the admin console's client and session name. Each is stored data or wire format, a row the
// seeder writes, a scope a token carries or a session name both processes read, so its spelling is
// a contract between the two binaries rather than a choice either makes alone.
//
// ARCHITECTURE.md's rule 7 gives every exported symbol here a row saying why core declares it, so
// an identifier only one process names does not settle here by default (#351, #442).
package builtin

const (
	AdminConsoleClientIdentifier = "admin-console-client"

	AuthServerResourceIdentifier = "authserver"

	ManageAccountPermissionIdentifier = "manage-account"
	ManagePermissionIdentifier        = "manage"

	// Granular admin API scopes
	AdminReadPermissionIdentifier      = "admin-read"
	ManageUsersPermissionIdentifier    = "manage-users"
	ManageClientsPermissionIdentifier  = "manage-clients"
	ManageSettingsPermissionIdentifier = "manage-settings"

	// BrowserSessionsPermissionIdentifier is what the admin console's bearer token
	// carries when it reaches its own browser sessions through the auth server. It is
	// deliberately not one of the manage-* scopes above: it permits reading and writing
	// admin console browser sessions and nothing else, so holding the admin console's
	// client secret does not drive the whole admin API (#266).
	BrowserSessionsPermissionIdentifier = "browser-sessions"
)

// AuthServerPermissionIdentifiers lists the permission identifiers on the "authserver" resource
// that are required by Goiabada's runtime scope checks. These cannot be renamed or deleted.
//
// It returns a new slice on every call, so a caller that sorts or overwrites what it was handed
// cannot change which permissions the next caller treats as built in (#442).
func AuthServerPermissionIdentifiers() []string {
	return []string{
		ManageAccountPermissionIdentifier,
		ManagePermissionIdentifier,
		AdminReadPermissionIdentifier,
		ManageUsersPermissionIdentifier,
		ManageClientsPermissionIdentifier,
		ManageSettingsPermissionIdentifier,
		BrowserSessionsPermissionIdentifier,
	}
}
