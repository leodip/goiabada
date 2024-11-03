package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"
)

func ProtectedAuthenticatedPlusScopeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "protected-authenticated-plus-scope.html"),
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
