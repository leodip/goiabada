package oidc

// The RFC 7591 dynamic client registration types, moved here from core/api by #385 on the
// membership test this package's doc states.
//
// The json tags and the two error-code values are the contract, and dcr_wire_test.go asserts the
// serialized form against a literal rather than leaving it to "nobody touched it".

// DynamicClientRegistrationRequest represents RFC 7591 §3.1 client registration request
type DynamicClientRegistrationRequest struct {
	// OAuth 2.0 core metadata (RFC 7591 §2)
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`  // sign-out redirect URIs (RP-Initiated Logout 1.0 section 3.1), never read at sign-in (#147)
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"` // "none", "client_secret_basic", "client_secret_post"
	GrantTypes              []string `json:"grant_types,omitempty"`                // ["authorization_code", "client_credentials", "refresh_token"]

	// Human-readable metadata (RFC 7591 §2)
	ClientName string `json:"client_name,omitempty"`
	// PolicyURI and TOSURI are the client's privacy policy and terms of service, which the consent
	// screen links. Each is stored only when it is an http or https URL with the scheme and host of
	// one of the redirect URIs (RFC 7591 section 5), and dropped otherwise (#622 decision 12).
	PolicyURI string `json:"policy_uri,omitempty"`
	TOSURI    string `json:"tos_uri,omitempty"`

	// BackchannelLogoutURI is where the auth server POSTs a logout token when a session the client
	// was on ends (OpenID Connect Back-Channel Logout 1.0 section 2.2), and
	// BackchannelLogoutSessionRequired whether every token must name the session, false by default.
	// A self-registered client's URI must use https whatever its type, and the flag is stored only
	// with a URI (#784 decision 10).
	BackchannelLogoutURI             string `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required,omitempty"`

	// All other fields ignored per RFC 7591 §2:
	// "The authorization server MUST ignore any client metadata
	//  sent by the client that it does not understand"
}

// DynamicClientRegistrationResponse represents RFC 7591 §3.2.1 successful registration
type DynamicClientRegistrationResponse struct {
	// REQUIRED (RFC 7591 §3.2.1)
	ClientID string `json:"client_id"`

	// OPTIONAL - only present for confidential clients (RFC 7591 §3.2.1)
	ClientSecret string `json:"client_secret,omitempty"`

	// Timestamps (RFC 7591 §3.2.1)
	ClientIDIssuedAt      int64 `json:"client_id_issued_at"`
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at"` // 0 = never expires

	// Echo back registered metadata (RFC 7591 §3.2.1)
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ClientName              string   `json:"client_name,omitempty"`
	// PolicyURI and TOSURI are what was stored, so a value that was dropped is absent (RFC 7591
	// section 3.2.1 lets the server reject or replace a requested value).
	PolicyURI string `json:"policy_uri,omitempty"`
	TOSURI    string `json:"tos_uri,omitempty"`
	// BackchannelLogoutURI and BackchannelLogoutSessionRequired are what was stored, both present
	// whenever a URI was and both absent otherwise, so the flag is a pointer: false is echoed beside
	// a stored URI (#784 decision 10).
	BackchannelLogoutURI             string `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired *bool  `json:"backchannel_logout_session_required,omitempty"`
}

// DynamicClientRegistrationError represents RFC 7591 §3.2.2 error response
type DynamicClientRegistrationError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// RFC 7591 §3.2.2 error codes
const (
	DCRErrorInvalidRedirectURI    = "invalid_redirect_uri"
	DCRErrorInvalidClientMetadata = "invalid_client_metadata"
)
