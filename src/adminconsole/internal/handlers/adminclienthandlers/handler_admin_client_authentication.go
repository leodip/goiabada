package adminclienthandlers

import (
    "fmt"
    "net/http"
    "strconv"

    "github.com/pkg/errors"

    "github.com/go-chi/chi/v5"
    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
    "github.com/leodip/goiabada/core/stringutil"
)

func HandleAdminClientAuthenticationGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
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
        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }
        client, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }
        if client == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
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
            ClientSecret:        client.ClientSecret,
            IsSystemLevelClient: client.IsSystemLevelClient,
        }

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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
    apiClient apiclient.ApiClient,
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

        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }
        client, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }
        if client == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
        }

        isSystemLevelClient := client.IsSystemLevelClient

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

        // Build API request
        req := &api.UpdateClientAuthenticationRequest{
            IsPublic:     adminClientAuthentication.IsPublic,
            ClientSecret: adminClientAuthentication.ClientSecret,
        }

        _, err = apiClient.UpdateClientAuthentication(jwtInfo.TokenResponse.AccessToken, client.Id, req)
        if err != nil {
            handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
            return
        }

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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

        http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/authentication", config.GetAdminConsole().BaseURL, client.Id), http.StatusFound)
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
