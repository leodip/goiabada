package handlers

import (
	"context"
	"fmt"
	"go-webapp/auth"
	"go-webapp/constants"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
)

type TokenClaims struct {
	IDTokenClaims      map[string]interface{}
	AccessTokenClaims  map[string]interface{}
	RefreshTokenClaims map[string]interface{}
}

// ExtractClaims middleware attempts to extract and validate claims from all tokens
// in the session if they exist, but doesn't require authentication
func ExtractClaims(
	next http.HandlerFunc,
	store sessions.Store,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			// Don't fail on session error, just proceed without claims
			next.ServeHTTP(w, r)
			return
		}

		tokenClaims := &TokenClaims{}

		// Process ID Token
		if rawIDToken, ok := session.Values["id_token"].(string); ok && rawIDToken != "" {
			if idToken, err := auth.VerifyIdToken(r.Context(), rawIDToken); err == nil {
				var claims map[string]interface{}
				if err := idToken.Claims(&claims); err == nil {
					tokenClaims.IDTokenClaims = claims
				}
			}
		}

		// Process Access Token
		if accessToken, ok := session.Values["access_token"].(string); ok && accessToken != "" {
			if claims, err := auth.VerifyJWTToken(r.Context(), accessToken); err == nil {
				tokenClaims.AccessTokenClaims = claims
			}
		}

		// Process Refresh Token
		if refreshToken, ok := session.Values["refresh_token"].(string); ok && refreshToken != "" {
			if claims, err := auth.VerifyJWTToken(r.Context(), refreshToken); err == nil {
				tokenClaims.RefreshTokenClaims = claims
			}
		}

		// Create new context keys for access and refresh token claims
		ctx := r.Context()
		if tokenClaims.IDTokenClaims != nil {
			ctx = context.WithValue(ctx, constants.ContextKeyIdTokenClaims, tokenClaims.IDTokenClaims)
		}
		if tokenClaims.AccessTokenClaims != nil {
			ctx = context.WithValue(ctx, constants.ContextKeyAccessTokenClaims, tokenClaims.AccessTokenClaims)
		}
		if tokenClaims.RefreshTokenClaims != nil {
			ctx = context.WithValue(ctx, constants.ContextKeyRefreshTokenClaims, tokenClaims.RefreshTokenClaims)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// RequiresAuthentication middleware ensures the user is authenticated
// This should be used after ExtractClaims when both authentication and claims are needed
func RequiresAuthentication(
	next http.HandlerFunc,
	store sessions.Store,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for verified claims in context
		verifiedClaims, ok := r.Context().Value(constants.ContextKeyIdTokenClaims).(map[string]interface{})
		if !ok || verifiedClaims == nil {
			redirectToForbidden(w, r, store, "No ID token in session")
			return
		}

		next.ServeHTTP(w, r)
	}
}

// Helper function to handle forbidden redirects
func redirectToForbidden(w http.ResponseWriter, r *http.Request, store sessions.Store, reason string) {
	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	session.Values["forbidden_reason"] = reason
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/forbidden", http.StatusFound)
}

func RequiresScope(
	next http.HandlerFunc,
	store sessions.Store,
	requiredScope string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get access token claims from context
		accessTokenClaims, ok := r.Context().Value(constants.ContextKeyAccessTokenClaims).(map[string]interface{})
		if !ok || accessTokenClaims == nil {
			redirectToForbidden(w, r, store, "No access token present")
			return
		}

		// Check for scope in the access token
		scopesInterface, ok := accessTokenClaims["scope"]
		if !ok {
			redirectToForbidden(w, r, store, "No scopes in access token")
			return
		}

		// Convert scopes to string and check if required scope is present
		scopesString, ok := scopesInterface.(string)
		if !ok {
			redirectToForbidden(w, r, store, "Invalid scope format in access token")
			return
		}

		// Split scopes string into slice and check for required scope
		scopes := strings.Split(scopesString, " ")
		hasRequiredScope := false
		for _, scope := range scopes {
			if scope == requiredScope {
				hasRequiredScope = true
				break
			}
		}

		if !hasRequiredScope {
			redirectToForbidden(w, r, store, fmt.Sprintf("Missing required scope: %s", requiredScope))
			return
		}

		next.ServeHTTP(w, r)
	}
}
