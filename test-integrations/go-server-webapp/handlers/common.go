package handlers

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

func getCommonData(r *http.Request, store sessions.Store) CommonData {
	session, _ := store.Get(r, "auth-session")

	commonData := CommonData{
		CurrentPage: r.URL.Path,
	}

	now := time.Now()

	// Check and validate ID Token
	if idTokenClaims, ok := session.Values["id_token_claims"].(map[string]interface{}); ok {
		if exp, ok := idTokenClaims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).After(now) {
				commonData.IdTokenClaims = idTokenClaims
			}
		}
	}

	// Check and validate Access Token
	if accessTokenClaims, ok := session.Values["access_token_claims"].(map[string]interface{}); ok {
		if exp, ok := accessTokenClaims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).After(now) {
				commonData.AccessTokenClaims = accessTokenClaims
			}
		}
	}

	// Check and validate Refresh Token
	if refreshTokenClaims, ok := session.Values["refresh_token_claims"].(map[string]interface{}); ok {
		if exp, ok := refreshTokenClaims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).After(now) {
				commonData.RefreshTokenClaims = refreshTokenClaims
			}
		}
	}

	// Check if refresh token exists
	if _, ok := session.Values["refresh_token_raw"].(string); ok {
		commonData.HasRefreshToken = true
	}

	return commonData
}
