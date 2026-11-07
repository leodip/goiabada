package issuance

import "strings"

// TokenType names the typ of a token TokenIssuer produces: the ID token, the access token, and the
// two kinds of refresh token. The two refresh values are also what refresh_tokens.refresh_token_type
// stores, so the branch that chooses the type and every branch that later reads it spell it from
// here rather than from a literal (#433). It is here because TokenIssuer produces every value it
// has, and out of core because the admin console issues nothing (#385).
type TokenType int

const (
	TokenTypeId TokenType = iota
	TokenTypeBearer
	// TokenTypeRefresh is a session-bound refresh token, valid while its browser session is.
	TokenTypeRefresh
	// TokenTypeOffline is an offline_access refresh token, which outlives the session.
	TokenTypeOffline
)

// String returns the label, or "" for a TokenType outside the declared range, rather than
// panicking on the slice index. Not reachable from any int conversion today -- every production
// value is one of the four constants -- but the guard goes on the type so the next caller cannot
// step on it (#385).
func (tt TokenType) String() string {
	if tt < TokenTypeId || tt > TokenTypeOffline {
		return ""
	}
	return []string{"ID", "Bearer", "Refresh", "Offline"}[tt]
}

// IsNotIDTokenTyp reports whether typ is the typ claim of a token this server issues that is not an
// ID Token: an access token's Bearer, or a refresh token's Refresh or Offline. The ID Token carries
// no typ at all, and neither does the short-lived hint the account logout mints, so an
// id_token_hint carrying one of these is no ID Token, which /auth/authorize and logout both refuse
// (#401). It is a denylist rather than a requirement that typ be "ID" for exactly that reason:
// requiring it would refuse every real hint.
func IsNotIDTokenTyp(typ string) bool {
	switch typ {
	case TokenTypeBearer.String(), TokenTypeRefresh.String(), TokenTypeOffline.String():
		return true
	}
	return false
}

// AccessTokenHeaderType is the JOSE header typ every access token carries, from every grant (RFC
// 9068 section 2.1 MUST). The auth server's own access-token check requires it, as section 4 asks of
// every resource server, so an ID or refresh token, which keep the library's default header, and an
// access token issued before #676, whose header said JWT, are never taken for one. The typ CLAIM
// stays TokenTypeBearer, since APIs may read it.
const AccessTokenHeaderType = "at+jwt"

// IDTokenHeaderType is the JOSE header typ every ID Token carries: golang-jwt's default, which the
// ID Token and the account logout's hint keep. RFC 7519 section 5.1 recommends it for a JWT.
const IDTokenHeaderType = "JWT"

// HasIDTokenHeader reports whether a JOSE header is an ID Token's: its typ is JWT, compared as a
// media type, without regard to case and with the application/ prefix optional (RFC 7515 section
// 4.1.9). /auth/authorize and logout require it of an id_token_hint, beside IsNotIDTokenTyp's check
// of the claim, because the claim cannot tell every token apart: a logout token carries no typ
// claim, is signed with the same key and names sub, sid and aud, the cross-JWT confusion
// Back-Channel Logout 1.0 section 4.1 and RFC 8725 section 3.11 describe. A requirement rather than
// a list of what is refused, so a token type added later is refused without joining one (#784
// decision 12). A refresh token keeps the default header too, which is why the claim check stays.
func HasIDTokenHeader(header map[string]interface{}) bool {
	typ, _ := header["typ"].(string)
	return strings.EqualFold(typ, IDTokenHeaderType) || strings.EqualFold(typ, "application/"+IDTokenHeaderType)
}

// responseTokenType is the token_type a token response answers: DPoP for an access token bound to
// a proof key, whose thumbprint dpopThumbprint is (RFC 9449 section 5 MUST), and Bearer otherwise.
func responseTokenType(dpopThumbprint string) string {
	if dpopThumbprint != "" {
		return "DPoP"
	}
	return TokenTypeBearer.String()
}
