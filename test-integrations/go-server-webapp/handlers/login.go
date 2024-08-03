package handlers

import (
	"GoServerWebApp/config"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

func LoginHandlerGet(store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("login").Funcs(TemplateFuncs).ParseFiles(
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", "login.html"),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := struct {
			CommonData
			DefaultScopes string
		}{
			CommonData:    CommonData{CurrentPage: "login"},
			DefaultScopes: strings.Join(config.DefaultScopes, " "),
		}

		err = tmpl.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func LoginHandlerPost(store sessions.Store, authHelper authHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		scopes := r.Form.Get("scopes")
		if scopes == "" {
			scopes = strings.Join(config.DefaultScopes, " ")
		}

		state := randomString(16)
		nonce := randomString(16)
		verifier := authHelper.GenerateVerifier()

		slog.Info("State: " + state)
		slog.Info("Nonce: " + nonce)
		slog.Info("Verifier: " + verifier)

		authorizeUrl := authHelper.GenerateAuthCodeURL(state, nonce, verifier, strings.Split(scopes, " "))
		slog.Info("Authorize URL: " + authorizeUrl)

		session, _ := store.Get(r, "auth-session")
		session.Values["state"] = state
		session.Values["nonce"] = nonce
		session.Values["verifier"] = verifier
		session.Save(r, w)

		http.Redirect(w, r, authorizeUrl, http.StatusFound)
	}
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().UnixNano()%1000000) // fallback
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
