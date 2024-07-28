package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/gorilla/sessions"
)

type ProtectedData struct {
	CommonData
}

func ProtectedGet(store sessions.Store, pageName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("protected").Funcs(TemplateFuncs).ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "protected.html"),
			filepath.Join("templates", "token_printer.html"),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := ProtectedData{
			CommonData: getCommonData(r, store),
		}
		data.CommonData.CurrentPage = pageName

		err = tmpl.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
