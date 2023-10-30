package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientAuthenticationGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		client, err := s.database.GetClientById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.New("client not found"))
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		clientSecretDecrypted := ""
		if !client.IsPublic {
			clientSecretDecrypted, err = lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		adminClientAuthentication := struct {
			ClientId            uint
			ClientIdentifier    string
			IsPublic            bool
			ClientSecret        string
			IsSystemLevelClient bool
		}{
			ClientId:            client.Id,
			ClientIdentifier:    client.ClientIdentifier,
			IsPublic:            client.IsPublic,
			ClientSecret:        clientSecretDecrypted,
			IsSystemLevelClient: client.IsSystemLevelClient(),
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		clientAuthenticationSavedSuccessfully := sess.Flashes("clientAuthenticationSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"client":                                adminClientAuthentication,
			"clientAuthenticationSavedSuccessfully": len(clientAuthenticationSavedSuccessfully) > 0,
			"csrfField":                             csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_authentication.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientAuthenticationPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		client, err := s.database.GetClientById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.New("client not found"))
			return
		}

		isSystemLevelClient := client.IsSystemLevelClient()
		if isSystemLevelClient {
			s.internalServerError(w, r, errors.New("trying to edit a system level client"))
			return
		}

		isPublic := false
		publicConfidential := r.FormValue("publicConfidential")
		if publicConfidential == "public" {
			isPublic = true
		} else if publicConfidential == "confidential" {
			isPublic = false
		} else {
			s.internalServerError(w, r, errors.New("invalid value for publicConfidential"))
			return
		}

		adminClientAuthentication := struct {
			ClientId            uint
			ClientIdentifier    string
			IsPublic            bool
			ClientSecret        string
			IsSystemLevelClient bool
		}{
			ClientId:            client.Id,
			ClientIdentifier:    client.ClientIdentifier,
			IsPublic:            isPublic,
			ClientSecret:        r.FormValue("clientSecret"),
			IsSystemLevelClient: isSystemLevelClient,
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"client":    adminClientAuthentication,
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_authentication.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if len(adminClientAuthentication.ClientSecret) != 60 && !adminClientAuthentication.IsPublic {
			renderError("Invalid client secret. Please generate a new one.")
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		if adminClientAuthentication.IsPublic {
			client.IsPublic = true
			client.ClientSecretEncrypted = nil
			client.ClientCredentialsEnabled = false
		} else {
			client.IsPublic = false
			clientSecretEncrypted, err := lib.EncryptText(adminClientAuthentication.ClientSecret, settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			client.ClientSecretEncrypted = clientSecretEncrypted
		}

		_, err = s.database.UpdateClient(client)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "clientAuthenticationSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/authentication", lib.GetBaseUrl(), client.Id), http.StatusFound)
	}
}

func (s *Server) handleAdminClientGenerateNewSecretGet() http.HandlerFunc {

	type generateNewSecretResult struct {
		NewSecret string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := generateNewSecretResult{}

		result.NewSecret = lib.GenerateSecureRandomString(60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}