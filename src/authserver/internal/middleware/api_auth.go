package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// emitAuthError writes the §6.3 admin/account API error envelope in English.
// Bearer-token failures on /api/v1/* are a machine surface (Surface B/C):
// responses do not localize. RFC 6750 §3 prescribes a WWW-Authenticate
// Bearer header for 401/403 token failures, which we set when bearer=true.
//
// i18n surface: B — machine.
func emitAuthError(w http.ResponseWriter, code, description string, statusCode int, bearer bool) {
	if bearer {
		errorParam := "invalid_token"
		if statusCode == http.StatusForbidden {
			errorParam = "insufficient_scope"
		}
		w.Header().Set("WWW-Authenticate",
			`Bearer error="`+errorParam+`", error_description="`+description+`"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(api.ErrorResponse{
		ErrorCode:        code,
		ErrorDescription: description,
	})
}

// RequireBearerTokenScope validates JWT token from context and checks required scope
func RequireBearerTokenScope(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from context (set by JwtAuthorizationHeaderToContext middleware)
			bearerTokenValue := r.Context().Value(constants.ContextKeyBearerToken)
			if bearerTokenValue == nil {
				emitAuthError(w, "ACCESS_TOKEN_REQUIRED", "Access token required.", http.StatusUnauthorized, true)
				return
			}

			jwtToken, ok := bearerTokenValue.(oauth.JwtToken)
			if !ok {
				emitAuthError(w, "INVALID_TOKEN_FORMAT", "Invalid token format.", http.StatusUnauthorized, true)
				return
			}

			// Validate scope
			if !jwtToken.HasScope(requiredScope) {
				emitAuthError(w, "INSUFFICIENT_SCOPE", "Insufficient scope.", http.StatusForbidden, true)
				return
			}

			// Add validated token to context for handlers to use
			ctx := context.WithValue(r.Context(), constants.ContextKeyValidatedToken, jwtToken)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireBearerTokenScopeAnyOf validates JWT token from context and checks if it has ANY of the required scopes (OR logic)
func RequireBearerTokenScopeAnyOf(requiredScopes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from context (set by JwtAuthorizationHeaderToContext middleware)
			bearerTokenValue := r.Context().Value(constants.ContextKeyBearerToken)
			if bearerTokenValue == nil {
				emitAuthError(w, "ACCESS_TOKEN_REQUIRED", "Access token required.", http.StatusUnauthorized, true)
				return
			}

			jwtToken, ok := bearerTokenValue.(oauth.JwtToken)
			if !ok {
				emitAuthError(w, "INVALID_TOKEN_FORMAT", "Invalid token format.", http.StatusUnauthorized, true)
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
				emitAuthError(w, "INSUFFICIENT_SCOPE", "Insufficient scope.", http.StatusForbidden, true)
				return
			}

			// Add validated token to context for handlers to use
			ctx := context.WithValue(r.Context(), constants.ContextKeyValidatedToken, jwtToken)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireUserBoundToken rejects bearer tokens that do not represent an authenticated
// user. Endpoints behind this guard resolve the acting user from the `sub` claim, and
// for a client_credentials token `sub` is the CLIENT identifier, not a user subject
// (token_issuer.go GenerateTokenResponseForClientCred). A client whose identifier
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
// Presence only, never the value. That is safe because JwtAuthorizationHeaderToContext
// stores a token in this context key only after DecodeAndValidateTokenString succeeds, so
// claims reaching here are server-issued and cannot be forged. It is also necessary: on
// the ROPC refresh path the value is wrong (createTokenInputFromROPC passes `now`, so a
// refreshed token reports the refresh moment as the authentication moment), a pre-existing
// defect this guard neither depends on nor fixes.
//
// This is a dependency, not an assumption: if a future change ever puts an unvalidated
// token into ContextKeyBearerToken, this guard weakens with it. And if a sixth user-token
// path is ever added that bypasses generateAccessTokenCore, this guard silently locks it
// out of these endpoints. It fails closed, which is the right direction for a guard whose
// job is to establish that a user is present.
func RequireUserBoundToken() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mirrors RequireBearerTokenScope exactly, so this guard introduces no new
			// response shapes for the two "no usable token" cases.
			bearerTokenValue := r.Context().Value(constants.ContextKeyBearerToken)
			if bearerTokenValue == nil {
				emitAuthError(w, "ACCESS_TOKEN_REQUIRED", "Access token required.", http.StatusUnauthorized, true)
				return
			}

			jwtToken, ok := bearerTokenValue.(oauth.JwtToken)
			if !ok {
				emitAuthError(w, "INVALID_TOKEN_FORMAT", "Invalid token format.", http.StatusUnauthorized, true)
				return
			}

			if _, hasAuthTime := jwtToken.Claims["auth_time"]; !hasAuthTime {
				slog.Warn("rejecting bearer token on a user-context endpoint: no auth_time claim, so the token was not issued for a user",
					"sub", jwtToken.GetStringClaim("sub"))
				// RFC 6750 §3.1 defines only invalid_request, invalid_token and
				// insufficient_scope, none of which means "wrong token type". emitAuthError
				// maps every bearer 403 to insufficient_scope, which keeps the
				// WWW-Authenticate header conformant; the JSON ErrorCode carries the precise
				// reason, which is how every other guard in this file distinguishes its cases.
				emitAuthError(w, "USER_CONTEXT_REQUIRED",
					"This endpoint requires an access token issued for a user. Tokens obtained through the client credentials grant are not accepted.",
					http.StatusForbidden, true)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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
// through GetIntClaim, because that accessor cannot distinguish absent from malformed and
// conflating the two would reject every legacy token.
//
// Tokens with no `auth_time` claim pass through untouched: that is the client_credentials
// discriminator, and such a token has no user to check anything about. The middleware also
// passes through when the request has no bearer token at all, since enforcing "must be
// authenticated" belongs to a scope middleware running alongside this one.
//
// Reads constants.ContextKeyBearerToken (set by JwtAuthorizationHeaderToContext),
// not ContextKeyValidatedToken, so it works regardless of whether a scope
// middleware ran first.
func RequireValidSession(database data.Database) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearerTokenValue := r.Context().Value(constants.ContextKeyBearerToken)
			if bearerTokenValue == nil {
				next.ServeHTTP(w, r)
				return
			}

			jwtToken, ok := bearerTokenValue.(oauth.JwtToken)
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

			sub := strings.TrimSpace(jwtToken.GetStringClaim("sub"))
			if sub == "" {
				slog.Warn("rejecting bearer token: user token has no sub claim")
				rejectInvalidToken(w, "Invalid token subject")
				return
			}

			user, err := database.GetUserBySubject(nil, sub)
			if err != nil {
				slog.Error("failed to look up user for bearer token validation", "err", err)
				emitAuthError(w, "INTERNAL_ERROR", "Internal server error.", http.StatusInternalServerError, false)
				return
			}
			if user == nil {
				slog.Warn("rejecting bearer token: subject does not resolve to a user")
				rejectInvalidToken(w, "Session has been terminated")
				return
			}
			if !user.Enabled {
				slog.Warn("rejecting bearer token: user account is disabled", "userId", user.Id)
				rejectInvalidToken(w, "Session has been terminated")
				return
			}

			sid := jwtToken.GetStringClaim("sid")
			if sid == "" {
				// Offline grant or ROPC: no session to defer to, so the token's own
				// generation claim decides. A malformed claim is rejected on !ok, before
				// the comparison, so it can never collide with a stored generation.
				generation, ok := tokenGeneration(jwtToken)
				if !ok || generation != user.AuthStateGeneration {
					slog.Warn("rejecting bearer token: superseded authentication generation",
						"userId", user.Id)
					rejectInvalidToken(w, "Session has been terminated")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			session, err := database.GetUserSessionBySessionIdentifier(nil, sid)
			if err != nil {
				slog.Error("failed to look up user session for bearer token validation",
					"sid", sid, "err", err)
				emitAuthError(w, "INTERNAL_ERROR", "Internal server error.", http.StatusInternalServerError, false)
				return
			}

			if session == nil {
				slog.Warn("rejecting bearer token: underlying user session has been terminated",
					"sid", sid)
				rejectInvalidToken(w, "Session has been terminated")
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
				slog.Warn("rejecting bearer token: session belongs to a different user",
					"sid", sid, "sessionId", session.Id, "sessionUserId", session.UserId,
					"userId", user.Id)
				rejectInvalidToken(w, "Session has been terminated")
				return
			}

			settingsValue := r.Context().Value(constants.ContextKeySettings)
			settings, ok := settingsValue.(*models.Settings)
			if !ok || settings == nil {
				// Fail closed: without settings we cannot enforce idle/max-lifetime
				// limits, and silently skipping the check would let an expired
				// session ride a still-valid JWT past us.
				slog.Error("missing or malformed settings in context; cannot validate session lifetime",
					"sid", sid)
				emitAuthError(w, "INTERNAL_ERROR", "Internal server error.", http.StatusInternalServerError, false)
				return
			}
			if !session.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil) {
				slog.Warn("rejecting bearer token: underlying user session has expired",
					"sid", sid, "sessionId", session.Id)
				rejectInvalidToken(w, "Session has expired")
				return
			}

			// The SESSION's generation, not the token's. See the asymmetry note above: the
			// token's own claim is deliberately not consulted on this branch.
			if session.AuthStateGeneration != user.AuthStateGeneration {
				slog.Warn("rejecting bearer token: session is on a superseded authentication generation",
					"sid", sid, "sessionId", session.Id, "userId", user.Id)
				rejectInvalidToken(w, "Session has been terminated")
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
// 15). Presence is tested against the raw claim map because GetIntClaim reports only whether
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
	return jwtToken.GetIntClaim("auth_state_generation")
}

// rejectInvalidToken sends an RFC 6750 §3 compliant 401 Unauthorized for the
// bearer-token validation failure cases handled by RequireValidSession.
//
// i18n surface: B — machine.
func rejectInvalidToken(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="`+description+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(api.ErrorResponse{
		ErrorCode:        "INVALID_TOKEN",
		ErrorDescription: description,
	})
}

// GetValidatedToken extracts the validated JWT token from request context
func GetValidatedToken(r *http.Request) (*oauth.JwtToken, bool) {
	token, ok := r.Context().Value(constants.ContextKeyValidatedToken).(oauth.JwtToken)
	if !ok {
		return nil, false
	}
	return &token, true
}
