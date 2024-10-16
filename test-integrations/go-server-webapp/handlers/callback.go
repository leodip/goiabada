package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func CallbackHandler(store sessions.Store, authHelper authHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		state := getParameter(r, "state")
		slog.Info("Received state: " + state)

		session, err := store.Get(r, "auth-session")
		if err != nil {
			errMsg := "Failed to get session: " + err.Error()
			slog.Error(errMsg)
			http.Error(w, errMsg, http.StatusInternalServerError)
			return
		}

		if state != session.Values["state"] {
			err := "Invalid state"
			slog.Error(err)
			http.Error(w, err, http.StatusBadRequest)
			return
		}

		code := getParameter(r, "code")
		if len(code) == 0 {
			error := getParameter(r, "error")
			errorDescription := getParameter(r, "error_description")
			errMsg := "Error: " + error + " - " + errorDescription
			slog.Error(errMsg)
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}

		slog.Info("Received code: " + code)

		verifier, ok := session.Values["verifier"].(string)
		if !ok {
			errMsg := "No verifier found in session"
			slog.Error(errMsg)
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}

		slog.Info("Verifier from session: " + verifier)

		token, err := authHelper.ExchangeAuthCodeWithToken(r.Context(), code, verifier)
		if err != nil {
			errMsg := "Failed to exchange token: " + err.Error()
			slog.Error(errMsg)
			http.Error(w, errMsg, http.StatusInternalServerError)
			return
		}

		err = processAndStoreTokens(w, r, store, authHelper, token)
		if err != nil {
			slog.Error("Failed to process and store tokens: " + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func getParameter(r *http.Request, paramName string) string {
	// Check query string
	if value := r.URL.Query().Get(paramName); value != "" {
		return value
	}

	// Check form post data
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			if value := r.PostForm.Get(paramName); value != "" {
				return value
			}
		}
	}

	// Parameter not found
	return ""
}

func processAndStoreTokens(w http.ResponseWriter, r *http.Request, store sessions.Store, authHelper authHelper, newToken *oauth2.Token) error {
	session, err := store.Get(r, "auth-session")
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	ctx := r.Context()

	if newToken.AccessToken != "" {
		session.Values["access_token_raw"] = newToken.AccessToken
		accessToken, err := authHelper.ParseAndValidateJWT(newToken.AccessToken)
		if err == nil {
			if accessTokenClaims, ok := accessToken.Claims.(jwt.MapClaims); ok {
				session.Values["access_token_claims"] = map[string]interface{}(accessTokenClaims)
			}
		}
	}

	if newToken.RefreshToken != "" {
		session.Values["refresh_token_raw"] = newToken.RefreshToken
		refreshToken, err := authHelper.ParseAndValidateJWT(newToken.RefreshToken)
		if err == nil {
			if refreshTokenClaims, ok := refreshToken.Claims.(jwt.MapClaims); ok {
				session.Values["refresh_token_claims"] = map[string]interface{}(refreshTokenClaims)
			}
		}
	}

	if rawIDToken, ok := newToken.Extra("id_token").(string); ok {
		session.Values["id_token_raw"] = rawIDToken
		idToken, err := authHelper.VerifyIdToken(ctx, rawIDToken)
		if err == nil {
			idTokenClaims := make(map[string]interface{})
			if err := idToken.Claims(&idTokenClaims); err == nil {
				session.Values["id_token_claims"] = idTokenClaims
			}
		}
	}

	err = session.Save(r, w)
	if err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}
