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
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientSettingsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientId is required"))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		client, err := s.databasev2.GetClientById(nil, int64(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.New("client not found"))
			return
		}

		adminClientSettings := struct {
			ClientId                 int64
			ClientIdentifier         string
			Description              string
			Enabled                  bool
			ConsentRequired          bool
			AuthorizationCodeEnabled bool
			DefaultAcrLevel          string
			IsSystemLevelClient      bool
		}{
			ClientId:                 client.Id,
			ClientIdentifier:         client.ClientIdentifier,
			Description:              client.Description,
			Enabled:                  client.Enabled,
			ConsentRequired:          client.ConsentRequired,
			AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
			DefaultAcrLevel:          client.DefaultAcrLevel.String(),
			IsSystemLevelClient:      client.IsSystemLevelClient(),
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            adminClientSettings,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
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
		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientId is required"))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
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

		client, err := s.databasev2.GetClientById(nil, int64(id))
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
			ClientId                 int64
			ClientIdentifier         string
			Description              string
			Enabled                  bool
			ConsentRequired          bool
			AuthorizationCodeEnabled bool
			DefaultAcrLevel          string
			IsSystemLevelClient      bool
		}{
			ClientId:                 int64(id),
			ClientIdentifier:         r.FormValue("clientIdentifier"),
			Description:              r.FormValue("description"),
			Enabled:                  enabled,
			ConsentRequired:          consentRequired,
			AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
			DefaultAcrLevel:          r.FormValue("defaultAcrLevel"),
			IsSystemLevelClient:      isSystemLevelClient,
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

		err = identifierValidator.ValidateIdentifier(adminClientSettings.ClientIdentifier, true)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				renderError(valError.Description)
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		existingClient, err := s.databasev2.GetClientByClientIdentifier(nil, adminClientSettings.ClientIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingClient != nil && existingClient.Id != client.Id {
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

		if client.AuthorizationCodeEnabled {
			defaultAcrLevel := r.FormValue("defaultAcrLevel")
			acrLevel, err := enums.AcrLevelFromString(defaultAcrLevel)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			client.DefaultAcrLevel = acrLevel
		}

		err = s.databasev2.UpdateClient(nil, client)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedClientSettings, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/settings", lib.GetBaseUrl(), client.Id), http.StatusFound)
	}
}
