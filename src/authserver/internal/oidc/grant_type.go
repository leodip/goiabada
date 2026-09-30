package oidc

// GrantType is an OAuth 2.0 grant type value, spelled as it travels: the token endpoint's
// grant_type parameter (RFC 6749 section 4), a registered client's grant_types (RFC 7591 section
// 2) and the discovery document's grant_types_supported (RFC 8414 section 2). Values are
// case-sensitive, so PASSWORD is not a grant type this server knows.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypePassword          GrantType = "password"
	GrantTypeImplicit          GrantType = "implicit"
)

func (gt GrantType) String() string {
	return string(gt)
}

// grantTraits is what the server does with one grant type.
type grantTraits struct {
	grantType GrantType
	// acceptedAtTokenEndpoint: the token endpoint has an arm for it. Implicit is issued from the
	// authorization endpoint and never redeemed here.
	acceptedAtTokenEndpoint bool
	// readsScope: the token request's scope parameter means something to it. The authorization
	// code grant takes its scope from the stored code; RFC 6749 section 4.1.3 does not define the
	// parameter on that request.
	readsScope bool
	// registrable: a dynamically registered client may ask for it.
	registrable bool
}

// grantTable is the one list of grant types the server names. The validator's and the token
// handler's dispatch, the provided-but-empty scope refusal, the ROPC refusal audit, dynamic client
// registration, discovery and the ROPC rate limiter all read it, where each used to carry its own
// set of literals (#437). Its order is the order grant_types_supported publishes.
//
// Every row is advertised, whatever any setting says: grant_types_supported is the grant types
// "this OP supports" (OIDC Discovery 1.0 section 3, RFC 8414 section 2), which is what the server
// implements, not what a given client is allowed. A client not allowed a grant is refused
// unauthorized_client. Gating a row on a switch again makes the document depend on settings and
// hides password and implicit from a relying party that is allowed them (#437).
//
// Adding a grant is a row here plus its own units; no switch elsewhere learns the name.
var grantTable = []grantTraits{
	{GrantTypeAuthorizationCode, true, false, true},
	{GrantTypeRefreshToken, true, true, true},
	{GrantTypeClientCredentials, true, true, true},
	{GrantTypePassword, true, true, false},
	{GrantTypeImplicit, false, false, false},
}

func (gt GrantType) traits() (grantTraits, bool) {
	for _, row := range grantTable {
		if row.grantType == gt {
			return row, true
		}
	}
	return grantTraits{}, false
}

// AcceptedAtTokenEndpoint reports whether POST /auth/token redeems this grant. Anything else is
// answered unsupported_grant_type (RFC 6749 section 5.2).
func (gt GrantType) AcceptedAtTokenEndpoint() bool {
	row, ok := gt.traits()
	return ok && row.acceptedAtTokenEndpoint
}

// ReadsScope reports whether this grant reads the token request's scope parameter, which is
// where the token endpoint refuses a scope that was provided but holds nothing.
func (gt GrantType) ReadsScope() bool {
	row, ok := gt.traits()
	return ok && row.readsScope
}

// Registrable reports whether a client registering through RFC 7591 may ask for this grant.
func (gt GrantType) Registrable() bool {
	row, ok := gt.traits()
	return ok && row.registrable
}

// GrantTypesSupported is the discovery document's grant_types_supported: every row, in table
// order. It returns a fresh slice, so a caller appending to it cannot reach the table.
func GrantTypesSupported() []string {
	supported := make([]string, 0, len(grantTable))
	for _, row := range grantTable {
		supported = append(supported, row.grantType.String())
	}
	return supported
}
