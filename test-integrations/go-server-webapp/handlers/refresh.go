package handlers

import (
	"GoServerWebApp/config"
	"log/slog"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func RefreshHandler(store sessions.Store, authHelper authHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}

		refreshToken, ok := session.Values["refresh_token_raw"].(string)
		if !ok || refreshToken == "" {
			http.Error(w, "No refresh token available", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		oauthConfig := &oauth2.Config{
			ClientID:     config.ClientId,
			ClientSecret: config.ClientSecret,
			Endpoint: oauth2.Endpoint{
				TokenURL: config.OidcProvider + "/auth/token",
			},
		}

		token := &oauth2.Token{
			RefreshToken: refreshToken,
		}

		newToken, err := oauthConfig.TokenSource(ctx, token).Token()
		if err != nil {
			slog.Error("Failed to refresh token: " + err.Error())
			http.Error(w, "Failed to refresh token", http.StatusInternalServerError)
			return
		}

		err = processAndStoreTokens(w, r, store, authHelper, newToken)
		if err != nil {
			slog.Error("Failed to process and store tokens: " + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
