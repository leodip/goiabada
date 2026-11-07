package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// RequireRecentAuthentication is the step-up route guard of RFC 9470: it admits only an access
// token whose sign-in is at most maxAge old and at least at minimum, and answers any other with
// section 3's challenge, 401 insufficient_user_authentication naming minimum as acr_values and
// maxAge as max_age, so the client knows what to sign the user in with. The account download
// mounts it with 300 seconds and urn:goiabada:level2_optional (#782 decision 1); the guard takes
// both as parameters so a later operation can put it in front of itself with its own.
//
// The age is the token's auth_time against now: every user access token carries its sign-in's
// auth_time, and a refresh keeps it, so a refreshed token is as old as the sign-in it came from. A
// sign-in exactly maxAge old passes. The level is the token's acr, compared by the server's own
// ordering of the three levels. The guard fails closed: a token with no auth_time, one that is not
// a whole number of seconds, or an acr it does not know, is refused as a sign-in too old or too
// weak, since a guard that establishes recency and strength must not pass what it cannot read.
// Every refusal names both parameters, whichever was short, so the client signs in once and meets
// both.
//
// It reads the token JwtAuthorizationHeaderToContext stored, after RequireValidSession has judged
// it live, and is mounted after RequireAdminConsoleClient on the download, so another client's
// token is told the client check's answer and is never asked to sign the user in again. now is the
// clock, read on every request. The sentence is English, as every bearer refusal is.
func (m *BearerToken) RequireRecentAuthentication(maxAge time.Duration, minimum record.AcrLevel,
	now func() time.Time) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mirrors RequireBearerTokenScopeAnyOf, so this guard adds no response shape of its
			// own for the "no token" case.
			jwtToken, ok := reqctx.BearerTokenFrom(r.Context())
			if !ok {
				m.refusals.missing(w, r)
				return
			}

			authTime, readable := jwtToken.IntClaim("auth_time")
			recent := readable && now().Sub(time.Unix(authTime, 0)) <= maxAge
			acr := record.AcrLevel(jwtToken.StringClaim("acr"))
			strong := acr.Priority() > 0 && acr.Priority() >= minimum.Priority()
			if !recent || !strong {
				slog.WarnContext(r.Context(), "rejecting bearer token: its sign-in is too old or too weak for the route",
					"auth_time_readable", readable, "recent", recent, "acr", jwtToken.StringClaim("acr"))
				m.refusals.insufficientUserAuthentication(w, r,
					"This endpoint requires a more recent sign-in, or a stronger one.", minimum.String(), maxAge)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
