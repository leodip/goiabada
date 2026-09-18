package constants

const (
	// OIDC Authorization Error Codes (per OpenID Connect Core 1.0, Section 3.1.2.6)
	//
	// The auth server is the only process that answers an authorization request, so it is
	// the only one that names these. The admin console is an OAuth client and reads them
	// off the wire (#351).
	ErrorLoginRequired       = "login_required"
	ErrorConsentRequired     = "consent_required"
	ErrorInteractionRequired = "interaction_required"
)
