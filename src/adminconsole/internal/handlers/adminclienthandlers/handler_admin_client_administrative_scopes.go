package adminclienthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// administrativeScopesSavedFlash announces a saved allowance on the Settings tab, apart from the
// settings form's own savedSuccessfully.
const administrativeScopesSavedFlash = "administrativeScopesSaved"

// clientAdministrativeScopesAPI is what the allowance's form needs: the client, to draw the Settings
// tab again after a refusal, and the allowance's own write.
type clientAdministrativeScopesAPI interface {
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	UpdateClientAdministrativeScopes(ctx context.Context, accessToken string, clientId int64,
		request *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error)
}

// HandleAdministrativeScopesPost saves the switch on the Settings tab that says whether the client
// may request the administrative authserver scopes. It is a form of its own, posting the switch and
// nothing else to the auth server's route for it, which reserves the switch to authserver:manage and
// refuses switching the admin console's client off (#499 decisions 4 and 5).
//
// The switch is read from the body alone: a browser submits an unticked checkbox as nothing, so its
// absence means "not allowed", and a value in the query is no submission of this form.
func HandleAdministrativeScopesPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientAdministrativeScopesAPI,
	baseURL string,
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

		allowed := r.PostFormValue("administrativeScopesAllowed") == "on"

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

		// A refusal draws the Settings tab again from the client as stored, the allowance included,
		// and puts the reason beside the allowance's own Save.
		renderError := func(message string) {
			bind := map[string]interface{}{
				"client":                    clientSettingsFrom(clientResp),
				"administrativeScopesError": message,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		_, err = apiClient.UpdateClientAdministrativeScopes(r.Context(), jwtInfo.TokenResponse.AccessToken, id,
			&api.UpdateClientAdministrativeScopesRequest{Allowed: &allowed})
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash(administrativeScopesSavedFlash, "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/settings", baseURL, id), http.StatusFound)
	}
}
