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
