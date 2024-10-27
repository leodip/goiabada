package adminclienthandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
)

func HandleAdminClientAuthenticationGet(
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

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		clientSecretDecrypted := ""
		if !client.IsPublic {
			clientSecretDecrypted, err = encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		adminClientAuthentication := struct {
			ClientId            int64
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
			"client":            adminClientAuthentication,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_authentication.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientAuthenticationPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
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

		isPublic := client.IsPublic // Default to current state
		if !isSystemLevelClient {
			// Only process publicConfidential for non-system-level clients
			publicConfidential := r.FormValue("publicConfidential")
			switch publicConfidential {
			case "public":
				isPublic = true
			case "confidential":
				isPublic = false
			default:
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("invalid value for publicConfidential")))
				return
			}
		}

		adminClientAuthentication := struct {
			ClientId            int64
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

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_authentication.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if len(adminClientAuthentication.ClientSecret) != 60 && !adminClientAuthentication.IsPublic {
			renderError("Invalid client secret. Please generate a new one.")
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		if adminClientAuthentication.IsPublic {
			client.IsPublic = true
			client.ClientSecretEncrypted = nil
			client.ClientCredentialsEnabled = false
		} else {
			client.IsPublic = false
			clientSecretEncrypted, err := encryption.EncryptText(adminClientAuthentication.ClientSecret, settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			client.ClientSecretEncrypted = clientSecretEncrypted
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

		auditLogger.Log(constants.AuditUpdatedClientAuthentication, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/authentication", config.Get().BaseURL, client.Id), http.StatusFound)
	}
}

func HandleAdminClientGenerateNewSecretGet(httpHelper handlers.HttpHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		newSecret := stringutil.GenerateSecurityRandomString(60)

		result := map[string]string{
			"NewSecret": newSecret,
		}

		httpHelper.EncodeJson(w, r, result)
	}
}
