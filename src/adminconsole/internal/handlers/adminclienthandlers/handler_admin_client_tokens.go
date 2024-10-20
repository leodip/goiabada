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
	"github.com/leodip/goiabada/core/enums"
)

func HandleAdminClientTokensGet(
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

		settingsInfo := struct {
			TokenExpirationInSeconds                int
			RefreshTokenOfflineIdleTimeoutInSeconds int
			RefreshTokenOfflineMaxLifetimeInSeconds int
			IncludeOpenIDConnectClaimsInAccessToken string
		}{
			TokenExpirationInSeconds:                client.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: client.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: client.RefreshTokenOfflineMaxLifetimeInSeconds,
			IncludeOpenIDConnectClaimsInAccessToken: client.IncludeOpenIDConnectClaimsInAccessToken,
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
			"settings":          settingsInfo,
			"client":            client,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientTokensPost(
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
		if isSystemLevelClient {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("trying to edit a system level client")))
			return
		}

		settingsInfo := struct {
			TokenExpirationInSeconds                string
			RefreshTokenOfflineIdleTimeoutInSeconds string
			RefreshTokenOfflineMaxLifetimeInSeconds string
			IncludeOpenIDConnectClaimsInAccessToken string
		}{
			TokenExpirationInSeconds:                r.FormValue("tokenExpirationInSeconds"),
			RefreshTokenOfflineIdleTimeoutInSeconds: r.FormValue("refreshTokenOfflineIdleTimeoutInSeconds"),
			RefreshTokenOfflineMaxLifetimeInSeconds: r.FormValue("refreshTokenOfflineMaxLifetimeInSeconds"),
			IncludeOpenIDConnectClaimsInAccessToken: r.FormValue("includeOpenIDConnectClaimsInAccessToken"),
		}

		renderError := func(message string) {

			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"client":    client,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		tokenExpirationInSeconds, err := strconv.Atoi(settingsInfo.TokenExpirationInSeconds)
		if err != nil {
			settingsInfo.TokenExpirationInSeconds = strconv.Itoa(client.TokenExpirationInSeconds)
			renderError("Invalid value for token expiration in seconds.")
			return
		}

		const maxValue = 160000000
		if tokenExpirationInSeconds > maxValue {
			renderError(fmt.Sprintf("Token expiration in seconds cannot be greater than %v.", maxValue))
			return
		}

		refreshTokenOfflineIdleTimeoutInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds)
		if err != nil {
			settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds = strconv.Itoa(client.RefreshTokenOfflineIdleTimeoutInSeconds)
			renderError("Invalid value for refresh token offline - idle timeout in seconds.")
			return
		}

		if refreshTokenOfflineIdleTimeoutInSeconds > maxValue {
			renderError(fmt.Sprintf("Refresh token offline - idle timeout in seconds cannot be greater than %v.", maxValue))
			return
		}

		refreshTokenOfflineMaxLifetimeInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds)
		if err != nil {
			settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds = strconv.Itoa(client.RefreshTokenOfflineMaxLifetimeInSeconds)
			renderError("Invalid value for refresh token offline - max lifetime in seconds.")
			return
		}

		if refreshTokenOfflineMaxLifetimeInSeconds > maxValue {
			renderError(fmt.Sprintf("Refresh token offline - max lifetime in seconds cannot be greater than %v.", maxValue))
			return
		}

		if refreshTokenOfflineIdleTimeoutInSeconds > refreshTokenOfflineMaxLifetimeInSeconds {
			renderError("Refresh token offline - idle timeout cannot be greater than max lifetime.")
			return
		}

		threeStateSetting, err := enums.ThreeStateSettingFromString(settingsInfo.IncludeOpenIDConnectClaimsInAccessToken)
		if err != nil {
			threeStateSetting = enums.ThreeStateSettingDefault
		}

		client.TokenExpirationInSeconds = tokenExpirationInSeconds
		client.RefreshTokenOfflineIdleTimeoutInSeconds = refreshTokenOfflineIdleTimeoutInSeconds
		client.RefreshTokenOfflineMaxLifetimeInSeconds = refreshTokenOfflineMaxLifetimeInSeconds
		client.IncludeOpenIDConnectClaimsInAccessToken = threeStateSetting.String()

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

		auditLogger.Log(constants.AuditUpdatedClientTokens, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/tokens", config.Get().BaseURL, client.Id), http.StatusFound)
	}
}
