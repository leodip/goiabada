package adminclienthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/securerandom"
	"github.com/leodip/goiabada/core/sessionstore"
)

// clientAuthenticationAPI is what the client authentication page needs: the client, its secret,
// which the client detail does not carry (#403), and its authentication write.
type clientAuthenticationAPI interface {
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	GetClientSecret(ctx context.Context, accessToken string, clientId int64) (string, error)
	UpdateClientAuthentication(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error)
}

// ClientAuthentication is what the Authentication tab is drawn from. The tab binds two: "client",
// the values its inputs show, and "storedClient", the client as the auth server holds it, which the
// page title and the original state and secret its confirmation dialogs compare against are drawn
// from. They differ only when a refused save is drawn again, with the inputs keeping what was
// submitted, so the same change attempted again is asked again (#562 decision 6).
type ClientAuthentication struct {
	ClientId            int64
	ClientIdentifier    string
	IsPublic            bool
	ClientSecret        string
	IsSystemLevelClient bool
}

// clientAuthenticationFrom draws the Authentication tab from the client and its secret as the auth
// server answers them.
func clientAuthenticationFrom(c *api.ClientResponse, clientSecret string) ClientAuthentication {
	return ClientAuthentication{
		ClientId:            c.Id,
		ClientIdentifier:    c.ClientIdentifier,
		IsPublic:            c.IsPublic,
		ClientSecret:        clientSecret,
		IsSystemLevelClient: c.IsSystemLevelClient,
	}
}

func HandleAuthenticationGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientAuthenticationAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("clientId")
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
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		client, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// A public client holds no secret, so none is read: each read of one is audited as
		// viewed_client_secret.
		clientSecret := ""
		if !client.IsPublic {
			clientSecret, err = apiClient.GetClientSecret(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
			if err != nil {
				render.HandleAPIError(httpHelper, w, r, err)
				return
			}
		}

		adminClientAuthentication := clientAuthenticationFrom(client, clientSecret)

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
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
			"storedClient":      adminClientAuthentication,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_authentication.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAuthenticationPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientAuthenticationAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("clientId")
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
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		client, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// The stored secret is read only for a refusal, as the first draw reads it, so a save that
		// succeeds records no viewed_client_secret of its own; a public client holds none. The
		// inputs show what was submitted, or the client as stored when submitted is nil.
		renderPage := func(submitted *ClientAuthentication, message, errorField string) {
			storedSecret := ""
			if !client.IsPublic {
				var secretErr error
				storedSecret, secretErr = apiClient.GetClientSecret(r.Context(), jwtInfo.TokenResponse.AccessToken, client.Id)
				if secretErr != nil {
					render.HandleAPIError(httpHelper, w, r, secretErr)
					return
				}
			}
			storedClient := clientAuthenticationFrom(client, storedSecret)
			shown := storedClient
			if submitted != nil {
				shown = *submitted
			}

			bind := map[string]interface{}{
				"client":       shown,
				"storedClient": storedClient,
				"error":        message,
				"errorField":   errorField,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_authentication.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		// The page's radios always send one of the two types, so only a hand-made request reaches
		// the default. With no type to draw the submission under, the tab is drawn as stored, and
		// the refusal marks no field (#632).
		publicConfidential := r.FormValue("publicConfidential")
		var isPublic bool
		switch publicConfidential {
		case "public":
			isPublic = true
		case "confidential":
			isPublic = false
		default:
			renderPage(nil, i18n.T(r.Context(), "adminconsole.refusal.client_authentication.type_required"), "")
			return
		}

		// ClientSecret reads with r.PostFormValue rather than r.FormValue: r.Form merges the URL
		// query behind the request body, so
		// /admin/clients/{clientId}/authentication?clientSecret=... would have set a client
		// credential, leaving it in the browser's history, in the Referer of anything the page loads,
		// and in the access log of every proxy in front of the deployment. This route is POST-only
		// with a separate GET handler rendering the form, so the query was never a submission (#202).
		adminClientAuthentication := ClientAuthentication{
			ClientId:            client.Id,
			ClientIdentifier:    client.ClientIdentifier,
			IsPublic:            isPublic,
			ClientSecret:        r.PostFormValue("clientSecret"),
			IsSystemLevelClient: client.IsSystemLevelClient,
		}

		// A refusal of the save keeps what was submitted in the inputs.
		renderError := func(message, errorField string) {
			renderPage(&adminClientAuthentication, message, errorField)
		}

		// Build API request
		req := &api.UpdateClientAuthenticationRequest{
			IsPublic:     adminClientAuthentication.IsPublic,
			ClientSecret: adminClientAuthentication.ClientSecret,
		}

		_, err = apiClient.UpdateClientAuthentication(r.Context(), jwtInfo.TokenResponse.AccessToken, client.Id, req)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, clientAuthenticationErrorFields))
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/authentication", baseURL, client.Id), http.StatusFound)
	}
}

func HandleGenerateNewSecretGet(httpHelper HttpHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		newSecret := securerandom.String(60)

		result := map[string]string{
			"NewSecret": newSecret,
		}

		httpHelper.EncodeJSON(w, r, result)
	}
}
