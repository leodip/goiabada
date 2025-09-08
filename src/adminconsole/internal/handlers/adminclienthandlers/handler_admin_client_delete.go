package adminclienthandlers

import (
    "fmt"
    "net/http"
    "strconv"

    "github.com/pkg/errors"

    "github.com/go-chi/chi/v5"
    "github.com/gorilla/csrf"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
)

func HandleAdminClientDeleteGet(
    httpHelper handlers.HttpHelper,
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
            httpHelper.InternalServerError(w, r, err)
            return
        }
        if client == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
        }

		bind := map[string]interface{}{
			"client":    client,
			"csrfField": csrf.TemplateField(r),
		}

        err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_delete.html", bind)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
    }
}

func HandleAdminClientDeletePost(
    httpHelper handlers.HttpHelper,
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
            httpHelper.InternalServerError(w, r, err)
            return
        }
        if client == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
        }

        if client.IsSystemLevelClient {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("cannot delete system level client")))
            return
        }

		renderError := func(message string) {
            bind := map[string]interface{}{
                "client":    client,
                "error":     message,
                "csrfField": csrf.TemplateField(r),
            }

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_delete.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		clientIdentifier := r.FormValue("clientIdentifier")
		if len(clientIdentifier) == 0 {
			renderError("Client identifier is required.")
			return
		}

        if client.ClientIdentifier != clientIdentifier {
            renderError("Client identifier does not match the client being deleted.")
            return
        }

        err = apiClient.DeleteClient(jwtInfo.TokenResponse.AccessToken, client.Id)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        http.Redirect(w, r, fmt.Sprintf("%v/admin/clients", config.GetAdminConsole().BaseURL), http.StatusFound)
    }
}
