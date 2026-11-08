package oidc

import (
	"encoding/json"
	"errors"
)

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
	// with a URI (#784 decision 10). The flag is a non-null boolean, so a null is refused as a value
	// that is not a boolean, as the decision refuses one, where a bool would read it as false.
	BackchannelLogoutURI             string                               `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired BackchannelLogoutSessionRequiredFlag `json:"backchannel_logout_session_required,omitempty"`

	// DPoPBoundAccessTokens is RFC 9449 section 5.2's dpop_bound_access_tokens, stored as the
	// client's "Require DPoP for token requests": false when left out, and a value that is not a
	// boolean, null included, refused naming the field (#42 decision 12).
	DPoPBoundAccessTokens DPoPBoundAccessTokensFlag `json:"dpop_bound_access_tokens,omitempty"`

	// All other fields ignored per RFC 7591 §2:
	// "The authorization server MUST ignore any client metadata
	//  sent by the client that it does not understand"
}

// The registration's two boolean members, each of which must be true or false when it is sent. Left
// out, one is false. A JSON null, which encoding/json leaves a bool's zero value for, is refused as
// every other value is, with a *NotABooleanError naming the member (#784 decision 10, #42 decision
// 12). encoding/json does not name the member in an error a decoding method returns, so each member
// has a type of its own that does.
type (
	BackchannelLogoutSessionRequiredFlag bool
	DPoPBoundAccessTokensFlag            bool
)

// NotABooleanError is the refusal of a value that is not true or false for a boolean member.
type NotABooleanError struct {
	// Member is the registration member, such as "dpop_bound_access_tokens".
	Member string
	// Value is the JSON value's kind as encoding/json names it, such as "null" or "string".
	Value string
}

func (e *NotABooleanError) Error() string {
	return "json: cannot read " + e.Value + " as a boolean for " + e.Member
}

// UnmarshalJSON reads true or false, and refuses null and every other value.
func (b *BackchannelLogoutSessionRequiredFlag) UnmarshalJSON(data []byte) error {
	value, err := readNonNullBool(data, "backchannel_logout_session_required")
	*b = BackchannelLogoutSessionRequiredFlag(value)
	return err
}

// UnmarshalJSON reads true or false, and refuses null and every other value.
func (b *DPoPBoundAccessTokensFlag) UnmarshalJSON(data []byte) error {
	value, err := readNonNullBool(data, "dpop_bound_access_tokens")
	*b = DPoPBoundAccessTokensFlag(value)
	return err
}

// readNonNullBool reads data as true or false, and refuses null and every other value with a
// *NotABooleanError naming member.
func readNonNullBool(data []byte, member string) (bool, error) {
	if string(data) == "null" {
		return false, &NotABooleanError{Member: member, Value: "null"}
	}
	var value bool
	if err := json.Unmarshal(data, &value); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return false, &NotABooleanError{Member: member, Value: typeErr.Value}
		}
		return false, err
	}
	return value, nil
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
	// DPoPBoundAccessTokens is what was stored, always echoed, false included (RFC 7591 section
	// 3.2.1, #42 decision 12).
	DPoPBoundAccessTokens bool `json:"dpop_bound_access_tokens"`
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
