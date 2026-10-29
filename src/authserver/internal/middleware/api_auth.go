package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/liveness"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
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

// RequireValidSession rejects bearer tokens that no longer represent live, current
// authentication state, as liveness.AccessToken judges it: the user, the session the token names
// and the authentication generation. The check decides; this guard answers and logs. Each
// refusal is 401 invalid_token, and only two descriptions say why: a blank subject and an expired
// session. Every other refusal reuses "Session has been terminated", a session of another user
// included (#133): a presenter has already proven it holds the token, but the wording still
// reaches a caller, and a distinct message would say which sessions exist.
//
// A client credentials token passes through, since the check finds no user to check anything
// about. The middleware also passes through when the request has no bearer token at all, since
// enforcing "must be authenticated" belongs to a scope middleware running alongside this one.
//
// Reads reqctx.BearerTokenFrom (set by JwtAuthorizationHeaderToContext),
// not reqctx.ValidatedTokenFrom, so it works regardless of whether a scope
// middleware ran first.
func (m *BearerToken) RequireValidSession(database liveness.Database) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwtToken, ok := reqctx.BearerTokenFrom(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Missing settings are passed on as nil: the check needs them only for a session's
			// bounds, and refuses what it can decide before them, a session of another user
			// among them, rather than turning it into a 500.
			settings, _ := reqctx.SettingsFrom(r.Context())
			verdict, err := liveness.AccessToken(r.Context(), database, jwtToken, settings, time.Now().UTC())
			if err != nil {
				if errors.Is(err, liveness.ErrNoSettings) {
					// The check reached a session's bounds on a request the settings middleware
					// never ran for: the wiring defect reqctx names.
					err = reqctx.ErrNoSettings
				}
				m.refusals.internalError(w, r, err, verdict.SessionIdentifier)
				return
			}

			// Each refusal is logged here. The two that say why answer at once; the rest share the
			// refusal below the switch.
			sid := verdict.SessionIdentifier
			switch verdict.Refusal {
			case liveness.Live:
				next.ServeHTTP(w, r)
				return
			case liveness.BlankSubject:
				slog.WarnContext(r.Context(), "rejecting bearer token: user token has no sub claim")
				m.refusals.invalidToken(w, r, "Invalid token subject")
				return
			case liveness.UserNotFound:
				slog.WarnContext(r.Context(), "rejecting bearer token: subject does not resolve to a user")
			case liveness.UserDisabled:
				slog.WarnContext(r.Context(), "rejecting bearer token: user account is disabled", "user_id", verdict.User.Id)
			case liveness.TokenGenerationSuperseded:
				slog.WarnContext(r.Context(), "rejecting bearer token: superseded authentication generation",
					"user_id", verdict.User.Id)
			case liveness.SessionNotFound:
				slog.WarnContext(r.Context(), "rejecting bearer token: underlying user session has been terminated",
					"session_identifier", sid)
			case liveness.SessionOfAnotherUser:
				slog.WarnContext(r.Context(), "rejecting bearer token: session belongs to a different user",
					"session_identifier", sid, "session_id", verdict.Session.Id,
					"session_user_id", verdict.Session.UserId, "user_id", verdict.User.Id)
			case liveness.SessionExpired:
				slog.WarnContext(r.Context(), "rejecting bearer token: underlying user session has expired",
					"session_identifier", sid, "session_id", verdict.Session.Id)
				m.refusals.invalidToken(w, r, "Session has expired")
				return
			case liveness.SessionGenerationSuperseded:
				slog.WarnContext(r.Context(), "rejecting bearer token: session is on a superseded authentication generation",
					"session_identifier", sid, "session_id", verdict.Session.Id, "user_id", verdict.User.Id)
			default:
				slog.WarnContext(r.Context(), "rejecting bearer token: liveness check refused it", "refusal", int(verdict.Refusal))
			}
			m.refusals.invalidToken(w, r, "Session has been terminated")
		})
	}
}
