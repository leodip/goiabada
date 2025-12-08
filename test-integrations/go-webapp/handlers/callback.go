package handlers

import (
	"context"
	"go-webapp/auth"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// getParam checks both URL query parameters and form data
func getParam(r *http.Request, key string) string {
	// If the auth server response is query, the data will be in the URL query parameters
	// But if the auth server response is form_post, the data will be in the form data

	// Try to get from URL query parameters first
	if value := r.URL.Query().Get(key); value != "" {
		return value
	}

	// If not found in URL, parse form data if not already parsed
	if r.Form == nil {
		r.ParseForm()
	}

	// Return from form data (will be empty string if not found)
	return r.Form.Get(key)
}

func CallbackHandler(oauth2Config *oauth2.Config, store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for errors in the callback
		if errType := getParam(r, "error"); errType != "" {
			errDesc := getParam(r, "error_description")

			// Unescape the error description if it's URL encoded
			if unescaped, err := url.QueryUnescape(errDesc); err == nil {
				errDesc = unescaped
			}

			// Render the error template
			tmpl, err := template.ParseFiles(
				filepath.Join("templates", "layout.html"),
				filepath.Join("templates", "error.html"),
			)
			if err != nil {
				http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
				return
			}

			data := map[string]interface{}{
				"ErrorType":        errType,
				"ErrorDescription": errDesc,
			}

			w.WriteHeader(http.StatusBadRequest)
			if err := tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
				http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Store tokens and claims in session
		session, err := store.Get(r, "auth-session")
		if err != nil {
			renderError(w, "session_error", "Failed to get session", err)
			return
		}

		// Validate state parameter to prevent CSRF attacks
		returnedState := getParam(r, "state")
		expectedState, ok := session.Values["state"].(string)
		if !ok || expectedState == "" {
			renderError(w, "state_error", "No state found in session", nil)
			return
		}
		if returnedState != expectedState {
			renderError(w, "state_error", "State mismatch - possible CSRF attack", nil)
			return
		}

		// Get the authorization code from either query params or form data
		code := getParam(r, "code")
		if code == "" {
			renderError(w, "authorization_error", "No authorization code received", nil)
			return
		}

		verifier, ok := session.Values["verifier"].(string)
		if !ok {
			renderError(w, "verifier_error", "No verifier in session", nil)
			return
		}

		// Exchange code for tokens
		token, err := oauth2Config.Exchange(context.Background(), code, oauth2.VerifierOption(verifier))
		if err != nil {
			renderError(w, "token_exchange_error", "Failed to exchange code for token", err)
			return
		}

		// Extract and verify ID Token if present
		if rawIDToken, ok := token.Extra("id_token").(string); ok && rawIDToken != "" {
			// Verify the ID token
			idToken, err := auth.VerifyIdToken(r.Context(), rawIDToken)
			if err != nil {
				renderError(w, "token_verification_error", "Failed to verify ID token", err)
				return
			}

			// Get ID token claims
			var idTokenClaims map[string]interface{}
			if err := idToken.Claims(&idTokenClaims); err != nil {
				renderError(w, "claims_error", "Failed to get ID token claims", err)
				return
			}

			// Store ID token in session
			session.Values["id_token"] = rawIDToken
		}

		// Verify Access Token if present
		if token.AccessToken != "" {
			_, err := auth.VerifyJWTToken(r.Context(), token.AccessToken)
			if err != nil {
				renderError(w, "access_token_verification_error", "Failed to verify access token", err)
				return
			}
			session.Values["access_token"] = token.AccessToken
		}

		// Verify Refresh Token if present
		if token.RefreshToken != "" {
			_, err := auth.VerifyJWTToken(r.Context(), token.RefreshToken)
			if err != nil {
				renderError(w, "refresh_token_verification_error", "Failed to verify refresh token", err)
				return
			}
			session.Values["refresh_token"] = token.RefreshToken
		}

		if err := session.Save(r, w); err != nil {
			renderError(w, "session_error", "Failed to save session", err)
			return
		}

		// Redirect to home page
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func renderError(w http.ResponseWriter, errType, errDesc string, err error) {
	tmpl, templateErr := template.ParseFiles(
		filepath.Join("templates", "layout.html"),
		filepath.Join("templates", "error.html"),
	)
	if templateErr != nil {
		http.Error(w, "Template error: "+templateErr.Error(), http.StatusInternalServerError)
		return
	}

	description := errDesc
	if err != nil {
		description += ": " + err.Error()
	}

	data := map[string]interface{}{
		"ErrorType":        errType,
		"ErrorDescription": description,
	}

	w.WriteHeader(http.StatusBadRequest)
	if err := tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
	}
}
