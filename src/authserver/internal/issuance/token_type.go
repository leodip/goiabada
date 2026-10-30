package issuance

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
