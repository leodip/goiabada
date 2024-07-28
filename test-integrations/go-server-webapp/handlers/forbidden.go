package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/gorilla/sessions"
)

type ForbiddenData struct {
	CommonData
	Reason string
}

func ForbiddenGet(store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("index").Funcs(TemplateFuncs).ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "forbidden.html"),
			filepath.Join("templates", "token_printer.html"),
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

		data := ForbiddenData{
			CommonData: getCommonData(r, store),
		}

		reason, ok := session.Values["forbidden_reason"].(string)
		if ok {
			data.Reason = reason
		}

		err = tmpl.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
