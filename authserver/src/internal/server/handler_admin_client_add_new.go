package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientAddNewGet() http.HandlerFunc {

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

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_add_new.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientAddNewPost(identifierValidator identifierValidator) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":            message,
				"clientIdentifier": r.FormValue("clientIdentifier"),
				"description":      r.FormValue("description"),
				"csrfField":        csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_add_new.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			renderError("Your authentication session has expired. To continue, please reload the page and re-authenticate to start a new session.")
			return
		}

		clientIdentifier := r.FormValue("clientIdentifier")
		description := strings.TrimSpace(r.FormValue("description"))

		if strings.TrimSpace(clientIdentifier) == "" {
			renderError("Client identifier is required.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		err := identifierValidator.ValidateIdentifier(clientIdentifier)
		if err != nil {
			renderError(err.Error())
			return
		}

		existingClient, err := s.database.GetClientByClientIdentifier(clientIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingClient != nil {
			renderError("The client identifier is already in use.")
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		clientSecret := lib.GenerateSecureRandomString(60)
		clientSecretEncrypted, err := lib.EncryptText(clientSecret, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, err)
		}

		authorizationCodeEnabled := false
		if r.FormValue("authorizationCodeEnabled") == "on" {
			authorizationCodeEnabled = true
		}

		clientCredentialsEnabled := false
		if r.FormValue("clientCredentialsEnabled") == "on" {
			clientCredentialsEnabled = true
		}

		client := &entities.Client{
			ClientIdentifier:         clientIdentifier,
			Description:              description,
			ClientSecretEncrypted:    clientSecretEncrypted,
			IsPublic:                 false,
			ConsentRequired:          false,
			Enabled:                  true,
			AuthorizationCodeEnabled: authorizationCodeEnabled,
			ClientCredentialsEnabled: clientCredentialsEnabled,
		}
		_, err = s.database.CreateClient(client)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients", lib.GetBaseUrl()), http.StatusFound)
	}
}
