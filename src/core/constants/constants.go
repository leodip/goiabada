package constants

const (
	AdminConsoleClientIdentifier = "admin-console-client"

	AuthServerResourceIdentifier = "authserver"

	UserinfoPermissionIdentifier      = "userinfo"
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

// BuiltInAuthServerPermissionIdentifiers lists the permission identifiers on the
// "authserver" resource that are required by Goiabada's runtime scope checks.
// These cannot be renamed or deleted.
var BuiltInAuthServerPermissionIdentifiers = []string{
	UserinfoPermissionIdentifier,
	ManageAccountPermissionIdentifier,
	ManagePermissionIdentifier,
	AdminReadPermissionIdentifier,
	ManageUsersPermissionIdentifier,
	ManageClientsPermissionIdentifier,
	ManageSettingsPermissionIdentifier,
	BrowserSessionsPermissionIdentifier,
}

const (
	// OIDC Authorization Error Codes (per OpenID Connect Core 1.0, Section 3.1.2.6)
	ErrorLoginRequired       = "login_required"
	ErrorConsentRequired     = "consent_required"
	ErrorInteractionRequired = "interaction_required"
)
