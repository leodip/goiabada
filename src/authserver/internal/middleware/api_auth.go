package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

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

// RequireValidSession rejects bearer tokens whose `sid` claim no longer
// resolves to an active, non-expired UserSession. This closes the gap left
// open by stateless JWT access tokens: when an authorization code is replayed
// (RFC 6749 §4.1.2) we delete the underlying UserSession, but the JWT itself
// remains cryptographically valid until expiry. This middleware checks the
// session each request, so a deleted session immediately invalidates every
// linked access token.
//
// Tokens without a `sid` claim (client_credentials, ROPC) pass through
// unchanged. The middleware also passes through if the request has no bearer
// token at all: enforcement of "must be authenticated" belongs to a scope
// middleware that runs alongside this one.
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

			sid := jwtToken.GetStringClaim("sid")
			if sid == "" {
				// Non-session-bound token (client_credentials, ROPC): no session to check.
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

			next.ServeHTTP(w, r)
		})
	}
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
