package middleware

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// RequireBearerTokenScope requires a bearer token carrying requiredScope.
func (m *BearerToken) RequireBearerTokenScope(requiredScope string) func(http.Handler) http.Handler {
	return m.RequireBearerTokenScopeAnyOf([]string{requiredScope})
}

// RequireBearerTokenScopeAnyOf requires a bearer token carrying ANY of requiredScopes (OR logic).
//
// No token in the context is a request that presented no bearer credential, since
// JwtAuthorizationHeaderToContext has already refused every presented token it did not store. It
// is answered 401 with the realm-only challenge: RFC 6750 section 3.1, a request lacking any
// authentication information SHOULD NOT be told an error code (#435).
func (m *BearerToken) RequireBearerTokenScopeAnyOf(requiredScopes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwtToken, ok := reqctx.BearerTokenFrom(r.Context())
			if !ok {
				m.refusals.missing(w, r)
				return
			}

			// Check if token has ANY of the required scopes
			hasRequiredScope := false
			for _, scope := range requiredScopes {
				if jwtToken.HasScope(scope) {
					hasRequiredScope = true
					break
				}
			}

			if !hasRequiredScope {
				m.refusals.forbidden(w, r, "INSUFFICIENT_SCOPE", "Insufficient scope.")
				return
			}

			// Add validated token to context for handlers to use
			next.ServeHTTP(w, r.WithContext(reqctx.WithValidatedToken(r.Context(), jwtToken)))
		})
	}
}

// RequireUserBoundToken rejects bearer tokens that do not represent an authenticated
// user. Endpoints behind this guard resolve the acting user from the `sub` claim, and
// for a client_credentials token `sub` is the CLIENT identifier, not a user subject
// (issuance/grant_client_credentials.go, IssueClientCredentialsGrant). A client whose identifier
// happened to equal a user's subject could therefore act as that user: a 36-character
// UUID is a valid client identifier whenever its first hex digit is a-f.
//
// Neither existing guard catches this. RequireBearerTokenScope checks only the scope
// string, and RequireValidSession deliberately passes through tokens with no `sid`.
//
// The discriminator is the `auth_time` claim, NOT `sid`. `sid` is conditional: it is set
// only when a session exists, so ROPC tokens issued without a browser session have none
// and requiring it would break them. `auth_time` is set unconditionally by
// generateAccessTokenCore, the single generator every user access token passes through
// (authorization code, authorization code refresh, implicit, ROPC, ROPC refresh), while
// the client_credentials claim set is built separately and never contains it.
//
// What reaches it is an access token issued for authserver, a user's or a client's:
// JwtAuthorizationHeaderToContext stores a token in this context key only after
// DecodeAndValidateTokenString succeeds and only when its typ is Bearer and its aud names
// authserver, so refresh and ID tokens never get here (#401), and this guard's one question
// is which of the two access-token kinds it holds.
//
// Presence only, never the value. That is safe because those claims are server-issued and
// cannot be forged. It is also necessary: on
// the ROPC refresh path the value is wrong (createTokenInputFromROPC passes `now`, so a
// refreshed token reports the refresh moment as the authentication moment), a pre-existing
// defect this guard neither depends on nor fixes.
//
// This is a dependency, not an assumption: if a future change ever puts an unvalidated
// token into reqctx.WithBearerToken, this guard weakens with it. And if a sixth user-token
// path is ever added that bypasses generateAccessTokenCore, this guard silently locks it
// out of these endpoints. It fails closed, which is the right direction for a guard whose
// job is to establish that a user is present.
func (m *BearerToken) RequireUserBoundToken() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mirrors RequireBearerTokenScopeAnyOf exactly, so this guard introduces no new
			// response shape for the "no token" case.
			jwtToken, ok := reqctx.BearerTokenFrom(r.Context())
			if !ok {
				m.refusals.missing(w, r)
				return
			}

			if _, hasAuthTime := jwtToken.Claims["auth_time"]; !hasAuthTime {
				slog.WarnContext(r.Context(), "rejecting bearer token on a user-context endpoint: no auth_time claim, so the token was not issued for a user",
					"sub", jwtToken.StringClaim("sub"))
				// RFC 6750 §3.1 defines only invalid_request, invalid_token and
				// insufficient_scope, none of which means "wrong token type". forbidden
				// maps every bearer 403 to insufficient_scope, which keeps the
				// WWW-Authenticate header conformant; on the API the JSON ErrorCode carries the
				// precise reason, which is how every other guard in this file distinguishes its cases.
				m.refusals.forbidden(w, r, "USER_CONTEXT_REQUIRED",
					"This endpoint requires an access token issued for a user. Tokens obtained through the client credentials grant are not accepted.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// apiAuthDatabase is what the API session check needs: the bearer's user row and the session the
// token names.
type apiAuthDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
}

// RequireValidSession rejects bearer tokens that no longer represent live, current
// authentication state.
//
// Four things are checked, and which of them apply depends on the token:
//
//  1. The account is still enabled. Verified that NO handler under /api/v1/account/*
//     checks this for itself, so without it a disabled user keeps working access for the
//     remainder of their access token's lifetime (#106 decision 6).
//  2. For a token carrying a `sid`, the session still exists and belongs to the token's
//     own user. The owner comparison backs up issuance rather than duplicating it: a
//     ceremony can no longer bind a grant to someone else's session, so anything reaching
//     this check was minted before the fix (#133).
//  3. That session is within its idle and max-lifetime bounds. This is what makes deleting
//     a session take effect immediately despite the JWT remaining cryptographically valid.
//  4. The authentication generation still matches. This is the boundary that survives a
//     credential change: a token authenticated under generation N stops working once the
//     user advances to N+1 (#106 decision 11).
//
// The generation check is deliberately ASYMMETRIC, and it looks wrong until you know why:
//
//   - With a `sid`, the SESSION's generation decides and the token's own claim is IGNORED.
//     That is what lets a self-service password change preserve the caller's own session:
//     the session is promoted forward while the access tokens already issued from it still
//     carry the old value. Checking the claim too would sign that caller out, which is the
//     thing decision 4 exists to avoid.
//   - Without one (offline grants and ROPC), the token's own claim decides, since there is
//     no session to defer to.
//
// A token with no generation claim at all reads as generation 0, which is what keeps access
// tokens issued before this feature shipped working until their user's generation first
// advances (#106 decision 15). Presence is tested against the raw claim map rather than
// through IntClaim, because that accessor cannot distinguish absent from malformed and
// conflating the two would reject every legacy token.
//
// Tokens with no `auth_time` claim pass through untouched: that is the client_credentials
// discriminator, and such a token has no user to check anything about. The middleware also
// passes through when the request has no bearer token at all, since enforcing "must be
// authenticated" belongs to a scope middleware running alongside this one.
//
// Reads reqctx.BearerTokenFrom (set by JwtAuthorizationHeaderToContext),
// not reqctx.ValidatedTokenFrom, so it works regardless of whether a scope
// middleware ran first.
func (m *BearerToken) RequireValidSession(database apiAuthDatabase) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwtToken, ok := reqctx.BearerTokenFrom(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// auth_time, not sid, is the "this is a user token" discriminator. sid is
			// conditional: ROPC and offline grants have none, so requiring it would let
			// exactly those tokens past every check below.
			if _, hasAuthTime := jwtToken.Claims["auth_time"]; !hasAuthTime {
				// client_credentials: no user, nothing to enforce.
				next.ServeHTTP(w, r)
				return
			}

			sub, hasSub := reqctx.BearerSubject(r.Context())
			if !hasSub {
				slog.WarnContext(r.Context(), "rejecting bearer token: user token has no sub claim")
				m.refusals.invalidToken(w, r, "Invalid token subject")
				return
			}

			user, err := database.GetUserBySubject(r.Context(), nil, sub)
			if err != nil {
				m.refusals.internalError(w, r,
					errs.Wrap(err, "failed to look up user for bearer token validation"), "")
				return
			}
			if user == nil {
				slog.WarnContext(r.Context(), "rejecting bearer token: subject does not resolve to a user")
				m.refusals.invalidToken(w, r, "Session has been terminated")
				return
			}
			if !user.Enabled {
				slog.WarnContext(r.Context(), "rejecting bearer token: user account is disabled", "user_id", user.Id)
				m.refusals.invalidToken(w, r, "Session has been terminated")
				return
			}

			sid := jwtToken.StringClaim("sid")
			if sid == "" {
				// Offline grant or ROPC: no session to defer to, so the token's own
				// generation claim decides. A malformed claim is rejected on !wellFormed, before
				// the comparison, so it can never collide with a stored generation.
				generation, wellFormed := tokenGeneration(jwtToken)
				if !wellFormed || generation != user.AuthStateGeneration {
					slog.WarnContext(r.Context(), "rejecting bearer token: superseded authentication generation",
						"user_id", user.Id)
					m.refusals.invalidToken(w, r, "Session has been terminated")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			session, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sid)
			if err != nil {
				m.refusals.internalError(w, r,
					errs.Wrap(err, "failed to look up user session for bearer token validation"), sid)
				return
			}

			if session == nil {
				slog.WarnContext(r.Context(), "rejecting bearer token: underlying user session has been terminated",
					"session_identifier", sid)
				m.refusals.invalidToken(w, r, "Session has been terminated")
				return
			}

			// The session has to belong to the token's user. Nothing else here compares the
			// two: the lifetime check reads dates and the generation check reads a counter,
			// so a token whose `sid` names another user's session would otherwise be governed
			// by that session in every respect, ending when its owner's session ends and
			// staying alive while its owner keeps using the browser (#133).
			//
			// Placed before the settings lookup, not merely before the lifetime check it
			// guards: this comparison needs no settings, so a cross-bound token is refused
			// even on the path where missing settings would otherwise produce a 500.
			//
			// Reuses "Session has been terminated" rather than naming the mismatch. A
			// presenter has already proven it holds the token, but the wording still reaches
			// a caller, and a distinct message would say which sessions exist.
			if session.UserId != user.Id {
				slog.WarnContext(r.Context(), "rejecting bearer token: session belongs to a different user",
					"session_identifier", sid, "session_id", session.Id,
					"session_user_id", session.UserId, "user_id", user.Id)
				m.refusals.invalidToken(w, r, "Session has been terminated")
				return
			}

			settings, ok := reqctx.SettingsFrom(r.Context())
			if !ok {
				// Fail closed: without settings we cannot enforce idle/max-lifetime
				// limits, and silently skipping the check would let an expired
				// session ride a still-valid JWT past us.
				m.refusals.internalError(w, r, reqctx.ErrNoSettings, sid)
				return
			}
			if !session.IsValid(time.Now().UTC(), settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil) {
				slog.WarnContext(r.Context(), "rejecting bearer token: underlying user session has expired",
					"session_identifier", sid, "session_id", session.Id)
				m.refusals.invalidToken(w, r, "Session has expired")
				return
			}

			// The SESSION's generation, not the token's. See the asymmetry note above: the
			// token's own claim is deliberately not consulted on this branch.
			if session.AuthStateGeneration != user.AuthStateGeneration {
				slog.WarnContext(r.Context(), "rejecting bearer token: session is on a superseded authentication generation",
					"session_identifier", sid, "session_id", session.Id, "user_id", user.Id)
				m.refusals.invalidToken(w, r, "Session has been terminated")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// tokenGeneration reads a token's authentication generation, reporting validity as a second
// return value rather than in band.
//
// An ABSENT claim is generation 0, and valid. That is what keeps access tokens issued before
// this feature shipped working until their user's generation first advances (#106 decision
// 15). Presence is tested against the raw claim map because IntClaim reports only whether
// a PRESENT claim parsed, so it returns (0, false) for both absent and malformed; conflating
// them would reject every legacy token.
//
// A malformed claim is (0, false), and callers must reject on !ok BEFORE comparing. Do not
// reintroduce an in-band sentinel such as -1: `auth_state_generation` is a signed
// BIGINT/INTEGER on all four engines with no nonnegative constraint, so any sentinel value a
// caller might compare against is also a value a user row can legitimately hold, and a user
// sitting on it would accept every malformed claim.
func tokenGeneration(jwtToken oauth.JwtToken) (int64, bool) {
	if _, present := jwtToken.Claims["auth_state_generation"]; !present {
		return 0, true
	}
	return jwtToken.IntClaim("auth_state_generation")
}
