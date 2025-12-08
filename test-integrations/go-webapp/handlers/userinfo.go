package handlers

import (
	"encoding/json"
	"go-webapp/config"
	"go-webapp/constants"
	"html/template"
	"io"
	"net/http"
	"path/filepath"

	"github.com/gorilla/sessions"
)

func UserInfoHandler(store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated
		_, ok := r.Context().Value(constants.ContextKeyIdTokenClaims).(map[string]interface{})
		if !ok {
			redirectToForbidden(w, r, store, "No ID token in session - authentication required")
			return
		}

		// Get access token from session
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}

		accessToken, ok := session.Values["access_token"].(string)
		if !ok || accessToken == "" {
			renderUserInfoError(w, "No access token in session")
			return
		}

		// Call the UserInfo endpoint
		req, err := http.NewRequest("GET", config.UserInfoURL, nil)
		if err != nil {
			renderUserInfoError(w, "Failed to create request: "+err.Error())
			return
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			renderUserInfoError(w, "Failed to call UserInfo endpoint: "+err.Error())
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			renderUserInfoError(w, "Failed to read response: "+err.Error())
			return
		}

		if resp.StatusCode != http.StatusOK {
			renderUserInfoError(w, "UserInfo endpoint returned status "+resp.Status+": "+string(body))
			return
		}

		// Parse the JSON response
		var userInfo map[string]interface{}
		if err := json.Unmarshal(body, &userInfo); err != nil {
			renderUserInfoError(w, "Failed to parse UserInfo response: "+err.Error())
			return
		}

		// Render the template
		tmpl, err := template.ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "userinfo.html"),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Pretty print the JSON for display
		prettyJSON, _ := json.MarshalIndent(userInfo, "", "  ")

		data := map[string]interface{}{
			"UserInfo":       userInfo,
			"UserInfoJSON":   string(prettyJSON),
			"UserInfoURL":    config.UserInfoURL,
			"StatusCode":     resp.StatusCode,
			"ContentType":    resp.Header.Get("Content-Type"),
		}

		if err := tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func renderUserInfoError(w http.ResponseWriter, errorMsg string) {
	tmpl, err := template.ParseFiles(
		filepath.Join("templates", "layout.html"),
		filepath.Join("templates", "userinfo.html"),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Error":       errorMsg,
		"UserInfoURL": config.UserInfoURL,
	}

	if err := tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
