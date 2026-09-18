package accounthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/stringutil"
)

func HandleAccountLogoutGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		session, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Clear the local session
		session.Options.MaxAge = -1
		if err = httpSession.Save(r, w, session); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// If we don't have a valid ID token, just go back to the console home
		if jwtInfo.IdToken == nil || jwtInfo.AccessToken == nil {
			http.Redirect(w, r, config.GetAdminConsole().BaseURL, http.StatusFound)
			return
		}

		// Ask for the form binding. A redirect would put the id_token_hint in the address bar
		// of a top-level navigation, and so in the browser's history and in the access log of
		// every proxy between here and the auth server; a self-submitting form carries it in a
		// request body instead. The console is the one relying party shipped beside this server
		// and has to follow the advice the integration docs give everyone else (#350 decision 2).
		accessToken := jwtInfo.AccessToken.TokenBase64
		req := &api.AccountLogoutRequest{
			PostLogoutRedirectUri: config.GetAdminConsole().BaseURL,
			State:                 stringutil.GenerateSecurityRandomString(32),
			ResponseMode:          api.AccountLogoutResponseModeFormPost,
		}

		formResp, redirectResp, err := apiClient.CreateAccountLogoutRequest(accessToken, req)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// An older auth server answers the redirect shape whatever this asked for, so the
		// redirect arm stays reachable and is not a fallback nobody takes. Both arms are checked
		// rather than one assumed: the client returns exactly one of the two, and dereferencing
		// the other is a nil panic on the page that ends a session.
		if formResp != nil {
			// The parameters are ranged out of the map the API sent rather than named here,
			// so a parameter it starts sending reaches the form with no console edit.
			err = httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/account_logout_form_post.html",
				map[string]interface{}{
					"endpoint": formResp.Endpoint,
					"params":   formResp.Params,
				})
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		http.Redirect(w, r, redirectResp.LogoutUrl, http.StatusFound)
	}
}
