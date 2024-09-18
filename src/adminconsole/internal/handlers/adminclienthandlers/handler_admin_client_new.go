package adminclienthandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
)

func HandleAdminClientNewGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientNewPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":            message,
				"clientIdentifier": r.FormValue("clientIdentifier"),
				"description":      r.FormValue("description"),
				"csrfField":        csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_new.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		clientIdentifier := r.FormValue("clientIdentifier")
		description := r.FormValue("description")

		if strings.TrimSpace(clientIdentifier) == "" {
			renderError("Client identifier is required.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		err := identifierValidator.ValidateIdentifier(clientIdentifier, true)
		if err != nil {
			renderError(err.Error())
			return
		}

		existingClient, err := database.GetClientByClientIdentifier(nil, clientIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if existingClient != nil {
			renderError("The client identifier is already in use.")
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		clientSecret := stringutil.GenerateSecureRandomString(60)
		clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
		}

		authorizationCodeEnabled := false
		if r.FormValue("authorizationCodeEnabled") == "on" {
			authorizationCodeEnabled = true
		}

		clientCredentialsEnabled := false
		if r.FormValue("clientCredentialsEnabled") == "on" {
			clientCredentialsEnabled = true
		}

		client := &models.Client{
			ClientIdentifier:         strings.TrimSpace(inputSanitizer.Sanitize(clientIdentifier)),
			Description:              strings.TrimSpace(inputSanitizer.Sanitize(description)),
			ClientSecretEncrypted:    clientSecretEncrypted,
			IsPublic:                 false,
			ConsentRequired:          false,
			Enabled:                  true,
			DefaultAcrLevel:          enums.AcrLevel2Optional,
			AuthorizationCodeEnabled: authorizationCodeEnabled,
			ClientCredentialsEnabled: clientCredentialsEnabled,
		}
		err = database.CreateClient(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditCreatedClient, map[string]interface{}{
			"clientId":         client.Id,
			"clientIdentifier": client.ClientIdentifier,
			"loggedInUser":     authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients", config.Get().BaseURL), http.StatusFound)
	}
}
