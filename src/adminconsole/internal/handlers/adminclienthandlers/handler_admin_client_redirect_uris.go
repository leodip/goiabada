package adminclienthandlers

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "sort"
    "strconv"

    "github.com/pkg/errors"

    "github.com/go-chi/chi/v5"
    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
)

func HandleAdminClientRedirectURIsGet(
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

        clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }
        if clientResp == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
        }

		adminClientRedirectURIs := struct {
			ClientId                 int64
			ClientIdentifier         string
			AuthorizationCodeEnabled bool
			RedirectURIs             map[int64]string
			IsSystemLevelClient      bool
        }{
            ClientId:                 clientResp.Id,
            ClientIdentifier:         clientResp.ClientIdentifier,
            AuthorizationCodeEnabled: clientResp.AuthorizationCodeEnabled,
            IsSystemLevelClient:      clientResp.IsSystemLevelClient,
        }

        sort.Slice(clientResp.RedirectURIs, func(i, j int) bool {
            return clientResp.RedirectURIs[i].URI < clientResp.RedirectURIs[j].URI
        })

        adminClientRedirectURIs.RedirectURIs = make(map[int64]string)
        for _, redirectURI := range clientResp.RedirectURIs {
            adminClientRedirectURIs.RedirectURIs[redirectURI.Id] = redirectURI.URI
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
			"client":            adminClientRedirectURIs,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

        err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_redirect_uris.html", bind)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
    }
}

func HandleAdminClientRedirectURIsPost(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

        var data RedirectURIsPostInput
        err = json.Unmarshal(body, &data)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }

        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        // Build API request and call auth server
        req := &api.UpdateClientRedirectURIsRequest{
            RedirectURIs: data.RedirectURIs,
        }
        _, err = apiClient.UpdateClientRedirectURIs(jwtInfo.TokenResponse.AccessToken, data.ClientId, req)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }

        sess, err := httpSession.Get(r, constants.SessionName)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

        result := struct {
            Success bool
        }{
            Success: true,
        }
        httpHelper.EncodeJson(w, r, result)
    }
}
