package adminclienthandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/stringutil"
)

func HandleAdminClientAuthenticationGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}
		client, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
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

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            adminClientAuthentication,
			"savedSuccessfully": savedSuccessfully,
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
	httpSession sessionstore.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}
		client, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
			return
		}

		isSystemLevelClient := client.IsSystemLevelClient

		// Process publicConfidential for all clients
		publicConfidential := r.FormValue("publicConfidential")
		var isPublic bool
		switch publicConfidential {
		case "public":
			isPublic = true
		case "confidential":
			isPublic = false
		default:
			httpHelper.InternalServerError(w, r, errs.New("invalid value for publicConfidential"))
			return
		}

		// ClientSecret reads with r.PostFormValue rather than r.FormValue: r.Form merges the URL
		// query behind the request body, so
		// /admin/clients/{clientId}/authentication?clientSecret=... would have set a client
		// credential, leaving it in the browser's history, in the Referer of anything the page loads,
		// and in the access log of every proxy in front of the deployment. This route is POST-only
		// with a separate GET handler rendering the form, so the query was never a submission (#202).
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
			ClientSecret:        r.PostFormValue("clientSecret"),
			IsSystemLevelClient: isSystemLevelClient,
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"client": adminClientAuthentication,
				"error":  message,
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

		sess.SetFlash("savedSuccessfully", "true")
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
