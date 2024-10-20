package handlers

import (
	"GoServerWebApp/config"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/gorilla/sessions"
)

type CommonData struct {
	CurrentPage        string
	IdTokenClaims      map[string]interface{}
	AccessTokenClaims  map[string]interface{}
	RefreshTokenClaims map[string]interface{}
	HasRefreshToken    bool
}

type IndexData struct {
	CommonData
	ClientId     string
	ClientSecret string
	Scopes       []string
	OidcProvider string
	RedirectURL  string
}

func IndexGet(store sessions.Store, authHelper authHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("index").Funcs(TemplateFuncs).ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "index.html"),
			filepath.Join("templates", "token_printer.html"),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := IndexData{
			CommonData:   getCommonData(r, store),
			ClientId:     config.ClientId,
			ClientSecret: config.ClientSecret,
			Scopes:       config.DefaultScopes,
			OidcProvider: config.OidcProvider,
			RedirectURL:  config.RedirectURL,
		}

		err = tmpl.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
