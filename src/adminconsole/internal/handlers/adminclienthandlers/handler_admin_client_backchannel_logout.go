package adminclienthandlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
)

// clientBackchannelLogoutAPI is what the Back-channel logout tab needs: the client, the global
// switches its gate reads against, and the write.
type clientBackchannelLogoutAPI interface {
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	GetSettingsGeneral(ctx context.Context, accessToken string) (*api.SettingsGeneralResponse, error)
	UpdateClientBackchannelLogout(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientBackchannelLogoutRequest) (*api.ClientResponse, error)
}

// manageScopeRequiredCode is the admin API's refusal of a write only authserver:manage may make,
// answered 403. On this tab it is the ceiling on setting or changing the URI (#784 decision 15).
const manageScopeRequiredCode = "MANAGE_SCOPE_REQUIRED"

// backchannelLogoutErrorFields maps the tab's refusals to the field each is about. Every refusal the
// save meets is about the URI: the flag is always sent, so its own refusal never comes back.
var backchannelLogoutErrorFields = map[string]string{
	i18n.ErrCodeClientBackchannelLogoutURIRequired:         "backchannelLogoutUri",
	i18n.ErrCodeClientBackchannelLogoutNoSignInFlow:        "backchannelLogoutUri",
	i18n.ErrCodeClientBackchannelLogoutURITooLong:          "backchannelLogoutUri",
	i18n.ErrCodeClientBackchannelLogoutURIInvalid:          "backchannelLogoutUri",
	i18n.ErrCodeClientBackchannelLogoutURISchemeInvalid:    "backchannelLogoutUri",
	i18n.ErrCodeClientBackchannelLogoutURIUserinfo:         "backchannelLogoutUri",
	i18n.ErrCodeClientBackchannelLogoutURIHTTPPublicClient: "backchannelLogoutUri",
	i18n.ErrCodeClientBackchannelLogoutChangedSinceLoaded:  "backchannelLogoutUri",
	manageScopeRequiredCode:                                "backchannelLogoutUri",
}

// ClientBackchannelLogout is what the Back-channel logout tab is drawn from: the URI the auth server
// POSTs a logout token to when a session the client was on ends, and whether the client requires the
// session identifier in every one (OpenID Connect Back-Channel Logout 1.0 section 2.2). A refused
// save draws it again with the inputs as typed. CanManageBackchannelLogout gates the form as the
// auth server gates the save, and as the Sign-out redirect URIs tab beside it is gated: a client
// with no flow that signs users in through a browser has no session to end (#784 decision 9).
type ClientBackchannelLogout struct {
	ClientId                         int64
	ClientIdentifier                 string
	CanManageBackchannelLogout       bool
	BackchannelLogoutURI             string
	BackchannelLogoutSessionRequired bool
	IsSystemLevelClient              bool
	// IsPublic is not edited here; the tab bar reads it to leave out a public client's
	// Introspection tab.
	IsPublic bool
}

// clientBackchannelLogoutFrom draws the tab from the client as the auth server answers it, the form
// drawn when canManage says so.
func clientBackchannelLogoutFrom(c *api.ClientResponse, canManage bool) ClientBackchannelLogout {
	return ClientBackchannelLogout{
		ClientId:                         c.Id,
		ClientIdentifier:                 c.ClientIdentifier,
		CanManageBackchannelLogout:       canManage,
		BackchannelLogoutURI:             c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: c.BackchannelLogoutSessionRequired,
		IsSystemLevelClient:              c.IsSystemLevelClient,
		IsPublic:                         c.IsPublic,
	}
}

// HandleBackchannelLogoutGet draws a client's Back-channel logout tab: the URI and the session
// identifier checkbox as stored, or, for a client with no flow that signs users in, the note saying
// which flows the URI is for (#784 decision 9).
func HandleBackchannelLogoutGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientBackchannelLogoutAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.ParseInt(r.PathValue("clientId"), 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		clientResp, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}
		settingsResp, err := apiClient.GetSettingsGeneral(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		client := clientBackchannelLogoutFrom(clientResp, usesARedirectFlow(clientResp, settingsResp))

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
			"client":            client,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_backchannel_logout.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// HandleBackchannelLogoutPost saves the tab through the auth server's own route for both settings,
// PUT /clients/{id}/backchannel-logout, which takes both, so a save always sends both: the URI as
// typed, trimmed, an emptied field clearing it, and the checkbox, on only for its own value. Both are
// read from the body alone: a browser submits an unticked checkbox as nothing, and a value in the
// query is no submission of this form.
//
// A refusal draws the tab again with the inputs as typed and the refusal on the field it is about.
// Setting or changing the URI takes authserver:manage, and the auth server answers any other token's
// try 403 MANAGE_SCOPE_REQUIRED (#784 decision 15). That one 403 is drawn on the URI in the console's
// own sentence, which says what the administrator can still do; the API's own sentence is English
// and speaks of administrators. Any other 403 is a server error, as on every tab.
func HandleBackchannelLogoutPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientBackchannelLogoutAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.ParseInt(r.PathValue("clientId"), 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		clientResp, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		uri := strings.TrimSpace(r.PostFormValue("backchannelLogoutUri"))
		sessionRequired := r.PostFormValue("backchannelLogoutSessionRequired") == "on"

		// A refusal is drawn on the form it answers, whatever the auth server said: the form was
		// drawn to be submitted, and a client that lost its sign-in flow since is refused on the URI.
		renderError := func(message, errorField string) {
			typed := clientBackchannelLogoutFrom(clientResp, true)
			typed.BackchannelLogoutURI = r.PostFormValue("backchannelLogoutUri")
			typed.BackchannelLogoutSessionRequired = sessionRequired
			bind := map[string]interface{}{
				"client":     typed,
				"error":      message,
				"errorField": errorField,
			}
			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_backchannel_logout.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		_, err = apiClient.UpdateClientBackchannelLogout(r.Context(), jwtInfo.TokenResponse.AccessToken, id,
			&api.UpdateClientBackchannelLogoutRequest{
				BackchannelLogoutURI:             &uri,
				BackchannelLogoutSessionRequired: &sessionRequired,
			})
		if err != nil {
			if isManageScopeRequired(err) {
				renderError(i18n.T(r.Context(), "adminconsole.admin_clients.backchannel_logout.manage_required"),
					backchannelLogoutErrorFields[manageScopeRequiredCode])
				return
			}
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, backchannelLogoutErrorFields))
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/backchannel-logout", baseURL, id), http.StatusFound)
	}
}

// isManageScopeRequired reports whether the admin API refused the write as one only an
// authserver:manage token may make.
func isManageScopeRequired(err error) bool {
	var apiErr *apiclient.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden && apiErr.Code == manageScopeRequiredCode
}
