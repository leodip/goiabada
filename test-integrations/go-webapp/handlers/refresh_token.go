package handlers

import (
	"context"
	"go-webapp/auth"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func RefreshTokenHandler(oauth2Config *oauth2.Config, store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}

		// Get refresh token from session
		refreshToken, ok := session.Values["refresh_token"].(string)
		if !ok || refreshToken == "" {
			http.Error(w, "No refresh token in session", http.StatusBadRequest)
			return
		}

		// Create token with refresh token
		token := &oauth2.Token{
			RefreshToken: refreshToken,
		}

		// Get new token using refresh token
		newToken, err := oauth2Config.TokenSource(context.Background(), token).Token()
		if err != nil {
			http.Error(w, "Failed to refresh token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Store new tokens in session
		if newToken.AccessToken != "" {
			// Verify new access token
			_, err := auth.VerifyJWTToken(r.Context(), newToken.AccessToken)
			if err != nil {
				http.Error(w, "Failed to verify new access token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			session.Values["access_token"] = newToken.AccessToken
		}

		// Check if we got a new refresh token
		if newToken.RefreshToken != "" && newToken.RefreshToken != refreshToken {
			// Verify new refresh token
			_, err := auth.VerifyJWTToken(r.Context(), newToken.RefreshToken)
			if err != nil {
				http.Error(w, "Failed to verify new refresh token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			session.Values["refresh_token"] = newToken.RefreshToken
		}

		// Extract and verify ID Token if present
		if rawIDToken, ok := newToken.Extra("id_token").(string); ok && rawIDToken != "" {
			idToken, err := auth.VerifyIdToken(r.Context(), rawIDToken)
			if err != nil {
				http.Error(w, "Failed to verify new ID token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			var idTokenClaims map[string]interface{}
			if err := idToken.Claims(&idTokenClaims); err != nil {
				http.Error(w, "Failed to get ID token claims: "+err.Error(), http.StatusInternalServerError)
				return
			}

			session.Values["id_token"] = rawIDToken
		}

		// Save session
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect back to index page
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
