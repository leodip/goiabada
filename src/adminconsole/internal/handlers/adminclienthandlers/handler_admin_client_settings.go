package adminclienthandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
)

func HandleAdminClientSettingsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		client, err := database.GetClientById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
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

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            adminClientSettings,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientSettingsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
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

		client, err := database.GetClientById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
			return
		}

		isSystemLevelClient := client.IsSystemLevelClient()
		if isSystemLevelClient {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("trying to edit a system level client")))
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
			ClientId:                 id,
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

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		err = identifierValidator.ValidateIdentifier(adminClientSettings.ClientIdentifier, true)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				renderError(valError.GetDescription())

			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		existingClient, err := database.GetClientByClientIdentifier(nil, adminClientSettings.ClientIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
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
				httpHelper.InternalServerError(w, r, err)
				return
			}
			client.DefaultAcrLevel = acrLevel
		}

		err = database.UpdateClient(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedClientSettings, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/settings", config.Get().BaseURL, client.Id), http.StatusFound)
	}
}
