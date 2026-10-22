package oauthclient

import (
	"math"
	"time"

	"github.com/leodip/goiabada/core/oauth"
)

// refreshMargin is how long before the access token's recorded expiry the console refreshes it,
// at most: a token living less than twice that is refreshed in the last half of its lifetime
// instead (RefreshDue). Its twin is sessionTokenExpiryMargin in session_token_source.go, which
// gives the console's other token, its client-credentials one, the same 30 seconds.
const refreshMargin = 30 * time.Second

// ExpiresAt turns a token response's expires_in into the Unix second at which its access token
// lapses, computed when the response arrives, the way golang.org/x/oauth2 computes Expiry. It
// answers 0, meaning unknown, for a nil response or an expires_in that is not positive: RFC 6749
// section 5.1 makes expires_in "RECOMMENDED", and Go reads an absent one as 0, so absent and
// zero are one case. An unknown expiry is used until the auth server refuses the token. A sum
// past the int64 range saturates rather than wrapping negative, which would make every request
// due for a refresh (#427).
func ExpiresAt(tokenResponse *oauth.TokenResponse, now time.Time) int64 {
	if tokenResponse == nil || tokenResponse.ExpiresIn <= 0 {
		return 0
	}
	nowUnix := now.Unix()
	if tokenResponse.ExpiresIn > math.MaxInt64-nowUnix {
		return math.MaxInt64
	}
	return nowUnix + tokenResponse.ExpiresIn
}

// RefreshDue reports whether the access token of tokenResponse, which lapses at expiresAt,
// should be refreshed now: from the margin before it, inclusive, and never for 0, the unknown
// expiry. The margin is refreshMargin, or half the token's lifetime, its expires_in, when that is
// shorter, so a token set is never due the moment it arrives. With refreshMargin alone, a lifetime
// of 30 seconds or less made every answer due at once: each request sent a grant, and a request
// that waited for another's refresh rotated its answer again rather than carrying it, while the
// first request, holding that answer, could save it back over the second rotation (#621). A
// response with no positive expires_in, which records no expiry either, keeps refreshMargin.
func RefreshDue(tokenResponse *oauth.TokenResponse, expiresAt int64, now time.Time) bool {
	if expiresAt == 0 {
		return false
	}
	margin := int64(refreshMargin / time.Second)
	if tokenResponse != nil && tokenResponse.ExpiresIn > 0 && tokenResponse.ExpiresIn/2 < margin {
		margin = tokenResponse.ExpiresIn / 2
	}
	return now.Unix()+margin >= expiresAt
}

// EffectiveScope is the scope a token response grants: its own scope parameter when it carries
// one, else fallback, which is the requested scope at sign-in and the previous grant at a
// refresh. RFC 6749 section 3.3: "If the issued access token scope is different from the one
// requested by the client, the authorization server MUST include the scope response parameter",
// and section 6: a refresh's scope "if omitted is treated as equal to the scope originally
// granted". A whitespace-only scope is present, and grants nothing: it is not replaced.
func EffectiveScope(responseScope, fallback string) string {
	if responseScope != "" {
		return responseScope
	}
	return fallback
}
