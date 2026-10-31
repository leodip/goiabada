package accounthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/securerandom"
	"github.com/leodip/goiabada/core/sessionstore"
)

// accountLogoutAPI is what the account logout page needs: the logout request the auth server
// answers with a URL.
type accountLogoutAPI interface {
	CreateAccountLogoutRequest(ctx context.Context, accessToken string, request *api.AccountLogoutRequest) (*api.AccountLogoutFormPostResponse, *api.AccountLogoutRedirectResponse, error)
}

// HandleLogoutConfirmGet renders the page that asks the administrator to confirm signing out,
// and is the GET a navigation to /auth/logout arrives at, which the menu's link is. The redirect
// the general settings save issues after an issuer change (#473) arrives here too, but with its
// tokens already cleared, so it takes the no-token arm below and is sent home, as before #411.
// The sessions pages post the sign-out directly once their own modal has confirmed it.
//
// It writes nothing and signs nobody out — the handler is not even handed a session store, so
// the confirmation cannot destroy anything — and it calls no API. A state-changing GET on this
// route was #411's cross-site logout: a top-level navigation carries the Lax session cookie
// (#408), nothing distinguishes the console's own link from any other site's, and the origin
// check reads unsafe methods only, so a GET it never sees. The page's form is what signs out, as
// a POST that check protects.
//
// The auth server's own /auth/logout is a different endpoint and keeps its GET: OIDC
// RP-Initiated Logout 1.0 section 2 has the relying party initiate it by navigating the user
// agent, and its consent screen (#109) stands in for the confirmation this page adds here.
// Recorded so a later reader does not "fix" the compliant one (#411).
//
// A visitor with no token set is not asked to confirm what they cannot do, and is sent home
// exactly as the sign-out below sends them.
func HandleLogoutConfirmGet(
	httpHelper HttpHelper,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// An absent token set is this page's unauthenticated arm, not a fault: the zero value has
		// no ID token, and the visitor is sent home below.
		jwtInfo, _ := reqctx.JwtInfoFrom(r.Context())

		if jwtInfo.IdToken == nil || jwtInfo.TokenResponse.AccessToken == "" {
			http.Redirect(w, r, baseURL, http.StatusFound)
			return
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/account_logout_confirm.html", nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}

// HandleLogoutPost clears the console's session and binds the auth server's end-session request,
// answering the confirmation page's form.
//
// A POST, and the method is the whole of this route's CSRF answer (#411): httpmw.CSRF, the
// net/http.CrossOriginProtection the console mounts, reads unsafe methods, so a cross-site form
// is refused before this body runs, and the console's CSRF policy exempts nothing here. The same
// body answering a bare GET, as it did before #411, let any site's top-level navigation carry
// the Lax session cookie to it and sign the administrator out of the console and of SSO.
//
// The console is the one relying party shipped beside this server and asks for the form binding
// rather than a redirect: a redirect would put the id_token_hint in the address bar of a top-level
// navigation, and so in the browser's history and in the access log of every proxy between here
// and the auth server; a self-submitting form carries it in a request body instead (#350
// decision 2).
func HandleLogoutPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountLogoutAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// An absent token set is this page's unauthenticated arm, not a fault: the zero value has
		// no ID token, and the visitor is sent home below.
		jwtInfo, _ := reqctx.JwtInfoFrom(r.Context())

		session, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
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
		if jwtInfo.IdToken == nil || jwtInfo.TokenResponse.AccessToken == "" {
			http.Redirect(w, r, baseURL, http.StatusFound)
			return
		}

		// Ask for the form binding, for the reason the function's own comment records. The console
		// names its own client by the built-in identifier no setting changes, so the auth server
		// checks the base URL against the console's sign-out redirect URIs only: another client
		// listing the same URL can't make the lookup ambiguous and break this sign-out (#147
		// decision 11).
		accessToken := jwtInfo.TokenResponse.AccessToken
		req := &api.AccountLogoutRequest{
			PostLogoutRedirectUri: baseURL,
			ClientIdentifier:      builtin.AdminConsoleClientIdentifier,
			State:                 securerandom.String(32),
			ResponseMode:          api.AccountLogoutResponseModeFormPost,
		}

		formResp, redirectResp, err := apiClient.CreateAccountLogoutRequest(r.Context(), accessToken, req)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
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
