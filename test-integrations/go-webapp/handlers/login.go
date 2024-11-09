package handlers

import (
	"go-webapp/auth"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func LoginGetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "login.html"),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := map[string]interface{}{}
		err = tmpl.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func LoginPostHandler(oauth2Config *oauth2.Config, store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		// Get selected scopes
		scopes := []string{}

		// Standard OIDC scopes
		standardScopes := []string{
			"openid",
			"profile",
			"email",
			"address",
			"phone",
			"groups",
			"attributes",
			"offline_access",
		}

		// Add selected standard scopes
		for _, scope := range standardScopes {
			if r.FormValue(scope) == "on" {
				scopes = append(scopes, scope)
			}
		}

		// Add custom scopes
		customScopes := r.Form["custom_scope[]"] // Changed from custom_scope to custom_scope[]
		for _, scope := range customScopes {
			if scope != "" {
				scopes = append(scopes, scope)
			}
		}
		// Generate state and nonce
		state, err := auth.GenerateRandomString()
		if err != nil {
			http.Error(w, "Failed to generate state", http.StatusInternalServerError)
			return
		}

		nonce, err := auth.GenerateRandomString()
		if err != nil {
			http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
			return
		}

		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Store state and nonce in session
		session.Values["state"] = state
		session.Values["nonce"] = nonce

		// Generate PKCE verifier and store it in session
		verifier := oauth2.GenerateVerifier()
		session.Values["verifier"] = verifier

		if err := session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Configure OAuth2 with selected scopes
		oauth2Config.Scopes = scopes

		// Redirect to authorization endpoint
		authURL := oauth2Config.AuthCodeURL(
			state,
			oauth2.SetAuthURLParam("nonce", nonce),
			oauth2.SetAuthURLParam("response_mode", "form_post"),
			oauth2.S256ChallengeOption(verifier))

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
