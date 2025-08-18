package middleware

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

// RequireBearerTokenScope validates JWT token from context and checks required scope
func RequireBearerTokenScope(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from context (set by JwtAuthorizationHeaderToContext middleware)
			bearerTokenValue := r.Context().Value(constants.ContextKeyBearerToken)
			if bearerTokenValue == nil {
				http.Error(w, "Access token required", http.StatusUnauthorized)
				return
			}

			jwtToken, ok := bearerTokenValue.(oauth.JwtToken)
			if !ok {
				http.Error(w, "Invalid token format", http.StatusUnauthorized)
				return
			}

			// Validate scope
			if !jwtToken.HasScope(requiredScope) {
				http.Error(w, "Insufficient scope", http.StatusForbidden)
				return
			}

			// Add validated token to context for handlers to use
			ctx := context.WithValue(r.Context(), constants.ContextKeyValidatedToken, jwtToken)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetValidatedToken extracts the validated JWT token from request context
func GetValidatedToken(r *http.Request) (*oauth.JwtToken, bool) {
	token, ok := r.Context().Value(constants.ContextKeyValidatedToken).(oauth.JwtToken)
	if !ok {
		return nil, false
	}
	return &token, true
}