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
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"` // "none", "client_secret_basic", "client_secret_post"
	GrantTypes              []string `json:"grant_types,omitempty"`                // ["authorization_code", "client_credentials", "refresh_token"]

	// Human-readable metadata (RFC 7591 §2)
	ClientName string `json:"client_name,omitempty"`

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
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ClientName              string   `json:"client_name,omitempty"`
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
