package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
)

func RequiresAuthentication(
	next http.HandlerFunc,
	store sessions.Store,
	authHelper authHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth-session")

		redirectToForbidden := func(reason string) {
			if session != nil {
				session.Values["forbidden_reason"] = reason
				session.Save(r, w)
			}
			http.Redirect(w, r, "/forbidden", http.StatusFound)
		}

		if session == nil {
			redirectToForbidden("No session found")
			return
		}

		rawIDToken, ok := session.Values["id_token_raw"].(string)
		if !ok || rawIDToken == "" {
			redirectToForbidden("No ID token found")
			return
		}

		// Verify the Id token
		idToken, err := authHelper.VerifyIdToken(r.Context(), rawIDToken)
		if err != nil {
			redirectToForbidden("Failed to verify ID token")
			return
		}

		// Verify the nonce
		nonce, ok := session.Values["nonce"].(string)
		if !ok || nonce == "" {
			redirectToForbidden("No nonce found")
			return
		}

		if idToken.Nonce != nonce {
			// Nonce does not match
			redirectToForbidden("Nonce does not match")
			return
		}

		// Check if the token is expired
		if idToken.Expiry.Before(time.Now()) {
			// Token is expired
			redirectToForbidden("Token is expired")
			return
		}

		// User is authenticated, proceed to the next handler
		next.ServeHTTP(w, r)
	}
}

func RequiresScope(
	next http.HandlerFunc,
	scope string,
	store sessions.Store,
	authHelper authHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth-session")

		redirectToForbidden := func(reason string) {
			if session != nil {
				session.Values["forbidden_reason"] = reason
				session.Save(r, w)
			}
			http.Redirect(w, r, "/forbidden", http.StatusFound)
		}

		if session == nil {
			redirectToForbidden("No session found")
			return
		}

		rawAccessToken, ok := session.Values["access_token_raw"].(string)
		if !ok || rawAccessToken == "" {
			redirectToForbidden("No access token found")
			return
		}

		// Verify the access token
		accessToken, err := authHelper.ParseAndValidateJWT(rawAccessToken)
		if err != nil {
			redirectToForbidden("Failed to parse and validate access token. " + err.Error())
			return
		}

		// Verify the nonce
		nonce, ok := session.Values["nonce"].(string)
		if !ok || nonce == "" {
			redirectToForbidden("No nonce found")
			return
		}

		var claims = accessToken.Claims.(jwt.MapClaims)
		if claims["nonce"] != nonce {
			// Nonce does not match
			redirectToForbidden("Nonce does not match")
			return
		}

		// Check if the token is expired
		exp, ok := claims["exp"].(float64)
		if !ok {
			redirectToForbidden("No expiry found")
			return
		}

		if time.Unix(int64(exp), 0).Before(time.Now()) {
			// Token is expired
			redirectToForbidden("Token is expired")
			return
		}

		// check the scope
		scopes, ok := claims["scope"].(string)
		if !ok {
			redirectToForbidden("No scope found")
			return
		}

		scopeArray := strings.Split(scopes, " ")
		scopeFound := false
		for _, s := range scopeArray {
			if s == scope {
				scopeFound = true
				break
			}
		}

		if !scopeFound {
			redirectToForbidden("Scope not present in token")
			return
		}

		// User has the required scope, proceed to the next handler
		next.ServeHTTP(w, r)
	}
}
