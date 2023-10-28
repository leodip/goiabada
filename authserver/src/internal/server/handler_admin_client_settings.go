package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientSettingsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			if s.isLoggedIn(jwtInfo) {
				http.Redirect(w, r, lib.GetBaseUrl()+"/unauthorized", http.StatusFound)
				return
			} else {
				s.redirToAuthorize(w, r, "admin-website", lib.GetBaseUrl()+r.RequestURI)
				return
			}
		}

		idStr := chi.URLParam(r, "clientID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientID is required"))
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

		adminClientSettings := struct {
			ClientID            uint
			ClientIdentifier    string
			Description         string
			Enabled             bool
			ConsentRequired     bool
			IsSystemLevelClient bool
		}{
			ClientID:            client.ID,
			ClientIdentifier:    client.ClientIdentifier,
			Description:         client.Description,
			Enabled:             client.Enabled,
			ConsentRequired:     client.ConsentRequired,
			IsSystemLevelClient: client.IsSystemLevelClient(),
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		clientSettingsSavedSuccessfully := sess.Flashes("clientSettingsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"client":                          adminClientSettings,
			"clientSettingsSavedSuccessfully": len(clientSettingsSavedSuccessfully) > 0,
			"csrfField":                       csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientSettingsPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		idStr := chi.URLParam(r, "clientID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientID is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		enabled := false
		if r.FormValue("enabled") == "on" {
			enabled = true
		}
		consentRequired := false
		if r.FormValue("consentRequired") == "on" {
			consentRequired = true
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

		adminClientSettings := struct {
			ClientID            uint
			ClientIdentifier    string
			Description         string
			Enabled             bool
			ConsentRequired     bool
			IsSystemLevelClient bool
		}{
			ClientID:            uint(id),
			ClientIdentifier:    r.FormValue("clientIdentifier"),
			Description:         r.FormValue("description"),
			Enabled:             enabled,
			ConsentRequired:     consentRequired,
			IsSystemLevelClient: isSystemLevelClient,
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"client":    adminClientSettings,
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			renderError("Your authentication session has expired. To continue, please reload the page and re-authenticate to start a new session.")
			return
		}

		err = identifierValidator.ValidateIdentifier(adminClientSettings.ClientIdentifier)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				renderError(valError.Description)
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		existingClient, err := s.database.GetClientByClientIdentifier(adminClientSettings.ClientIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingClient != nil && existingClient.ID != client.ID {
			renderError("The client identifier is already in use.")
			return
		}

		const maxLengthDescription = 100
		if len(adminClientSettings.Description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		client.ClientIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(adminClientSettings.ClientIdentifier))
		client.Description = strings.TrimSpace(inputSanitizer.Sanitize(adminClientSettings.Description))
		client.Enabled = adminClientSettings.Enabled
		client.ConsentRequired = adminClientSettings.ConsentRequired
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

		sess.AddFlash("true", "clientSettingsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/settings", lib.GetBaseUrl(), client.ID), http.StatusFound)
	}
}
