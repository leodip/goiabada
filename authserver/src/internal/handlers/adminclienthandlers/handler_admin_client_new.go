package adminclienthandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
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

		clientSecret := lib.GenerateSecureRandomString(60)
		clientSecretEncrypted, err := lib.EncryptText(clientSecret, settings.AESEncryptionKey)
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
			DefaultAcrLevel:          enums.AcrLevel2,
			AuthorizationCodeEnabled: authorizationCodeEnabled,
			ClientCredentialsEnabled: clientCredentialsEnabled,
		}
		err = database.CreateClient(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditCreatedClient, map[string]interface{}{
			"clientId":         client.Id,
			"clientIdentifier": client.ClientIdentifier,
			"loggedInUser":     authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients", lib.GetBaseUrl()), http.StatusFound)
	}
}
