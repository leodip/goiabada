package handlers

import (
	"fmt"
	"go-webapp/constants"
	"html/template"
	"net/http"
	"path/filepath"
	"time"
)

// formatUnixTime converts Unix timestamp to a readable format while preserving the original value
func formatUnixTime(timestamp float64) string {
	t := time.Unix(int64(timestamp), 0)
	return fmt.Sprintf("%.0f (%s)", timestamp, t.Format("2006-01-02 15:04:05 MST"))
}

// formatClaim formats specific claim types appropriately
func formatClaim(key string, value interface{}) string {
	// Time-related claims
	timeFields := map[string]bool{
		"auth_time":  true,
		"exp":        true,
		"iat":        true,
		"updated_at": true,
	}

	if timeFields[key] {
		if timestamp, ok := value.(float64); ok {
			return formatUnixTime(timestamp)
		}
	}

	return fmt.Sprintf("%v", value)
}

func IndexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		funcMap := template.FuncMap{
			"formatClaim": formatClaim,
		}

		tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "index.html"),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		idTokenClaims, _ := r.Context().Value(constants.ContextKeyIdTokenClaims).(map[string]interface{})
		accessTokenClaims, _ := r.Context().Value(constants.ContextKeyAccessTokenClaims).(map[string]interface{})
		refreshTokenClaims, _ := r.Context().Value(constants.ContextKeyRefreshTokenClaims).(map[string]interface{})

		data := map[string]interface{}{
			"LoggedIn":           idTokenClaims != nil,
			"IdTokenClaims":      idTokenClaims,
			"AccessTokenClaims":  accessTokenClaims,
			"RefreshTokenClaims": refreshTokenClaims,
		}

		if idTokenClaims != nil {
			data["Subject"] = idTokenClaims["sub"]
			data["Name"] = idTokenClaims["name"]
			data["Email"] = idTokenClaims["email"]
			data["Username"] = idTokenClaims["preferred_username"]
		}

		err = tmpl.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
