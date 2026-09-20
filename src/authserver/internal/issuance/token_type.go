package issuance

// TokenType names which of the three tokens an issuance produced. It is here because TokenIssuer
// produces every value it has, and out of core because the admin console issues nothing (#385).
type TokenType int

const (
	TokenTypeId TokenType = iota
	TokenTypeBearer
	TokenTypeRefresh
)

// String returns the label, or "" for a TokenType outside the declared range, rather than
// panicking on the slice index. Not reachable from any int conversion today -- every production
// value is one of the three constants -- but the guard goes on the type so the next caller cannot
// step on it (#385).
func (tt TokenType) String() string {
	if tt < TokenTypeId || tt > TokenTypeRefresh {
		return ""
	}
	return []string{"ID", "Bearer", "Refresh"}[tt]
}
