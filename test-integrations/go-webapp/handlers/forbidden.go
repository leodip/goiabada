package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/gorilla/sessions"
)

func ForbiddenHandler(store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "forbidden.html"),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		reason, ok := session.Values["forbidden_reason"].(string)
		if !ok {
			reason = "Unknown"
		}

		data := map[string]interface{}{
			"Reason": reason,
		}

		err = tmpl.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
