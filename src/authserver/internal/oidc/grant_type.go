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

// discoveryRule says when grant_types_supported lists a grant.
type discoveryRule int

const (
	discoveryAlways discoveryRule = iota
	discoveryWhenImplicitEnabled
	discoveryNever
)

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
	discovery   discoveryRule
}

// grantTable is the one list of grant types the server names. The validator's and the token
// handler's dispatch, the provided-but-empty scope refusal, the ROPC refusal audit, dynamic client
// registration, discovery and the ROPC rate limiter all read it, where each used to carry its own
// set of literals (#437). Its order is the order grant_types_supported publishes.
//
// Adding a grant is a row here plus its own units; no switch elsewhere learns the name.
var grantTable = []grantTraits{
	{GrantTypeAuthorizationCode, true, false, true, discoveryAlways},
	{GrantTypeRefreshToken, true, true, true, discoveryAlways},
	{GrantTypeClientCredentials, true, true, true, discoveryAlways},
	// Never advertised: the list dates from fb9157a4 and the password grant's commits never
	// touched it. Kept as it is until the discovery change of #437 lists every grant implemented.
	{GrantTypePassword, true, true, false, discoveryNever},
	{GrantTypeImplicit, false, false, false, discoveryWhenImplicitEnabled},
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

// GrantTypesSupported is the discovery document's grant_types_supported, in table order. It
// returns a fresh slice, so a caller appending to it cannot reach the table.
func GrantTypesSupported(implicitFlowEnabled bool) []string {
	supported := []string{}
	for _, row := range grantTable {
		switch row.discovery {
		case discoveryAlways:
			supported = append(supported, row.grantType.String())
		case discoveryWhenImplicitEnabled:
			if implicitFlowEnabled {
				supported = append(supported, row.grantType.String())
			}
		case discoveryNever:
		}
	}
	return supported
}
