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
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

// effectiveWebOrigin is one row of the server-wide list the page renders beside the client's own.
// ClientIdentifier is a label saying which app the origin was registered for, not a boundary:
// every row in the list is honoured for every client.
type effectiveWebOrigin struct {
	Origin           string
	ClientIdentifier string
}

func HandleAdminClientWebOriginsGet(
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

		// The effective list, which is the page's honest answer to "what may call these
		// endpoints from a browser today". MiddlewareCors checks an incoming Origin against
		// every row in the table regardless of which client it was registered against, because
		// a CORS preflight carries no client identity, so an origin listed on the least-trusted
		// client is permitted for every client. The page used to show only this client's rows,
		// which implied a scoping the server does not honour, and an administrator could not
		// answer the question without opening every client in turn (#250).
		//
		// This needs no new endpoint: GET /api/v1/admin/clients already loads WebOrigins for
		// every client it returns. Assembled here rather than in the template, so the template
		// displays a list it is handed and holds no rule.
		allClients, err := apiClient.GetAllClients(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		effectiveWebOrigins := make([]effectiveWebOrigin, 0)
		for _, c := range allClients {
			for _, origin := range c.WebOrigins {
				effectiveWebOrigins = append(effectiveWebOrigins, effectiveWebOrigin{
					Origin:           origin.Origin,
					ClientIdentifier: c.ClientIdentifier,
				})
			}
		}
		sort.Slice(effectiveWebOrigins, func(i, j int) bool {
			if effectiveWebOrigins[i].Origin != effectiveWebOrigins[j].Origin {
				return effectiveWebOrigins[i].Origin < effectiveWebOrigins[j].Origin
			}
			return effectiveWebOrigins[i].ClientIdentifier < effectiveWebOrigins[j].ClientIdentifier
		})

		// No AuthorizationCodeEnabled in this bind. The page no longer gates on it: a web origin
		// is needed when the client's app is JavaScript in a browser, which no flow flag
		// expresses, and the auth server's own endpoint stopped asking too (#250).
		adminClientWebOrigins := struct {
			ClientId            int64
			ClientIdentifier    string
			WebOrigins          map[int64]string
			EffectiveWebOrigins []effectiveWebOrigin
			IsSystemLevelClient bool
		}{
			ClientId:            clientResp.Id,
			ClientIdentifier:    clientResp.ClientIdentifier,
			EffectiveWebOrigins: effectiveWebOrigins,
			IsSystemLevelClient: clientResp.IsSystemLevelClient,
		}

		sort.Slice(clientResp.WebOrigins, func(i, j int) bool {
			return clientResp.WebOrigins[i].Origin < clientResp.WebOrigins[j].Origin
		})

		adminClientWebOrigins.WebOrigins = make(map[int64]string)
		for _, origin := range clientResp.WebOrigins {
			adminClientWebOrigins.WebOrigins[origin.Id] = origin.Origin
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
			"client":            adminClientWebOrigins,
			"savedSuccessfully": len(savedSuccessfully) > 0,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_web_origins.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientWebOriginsPost(
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

		var data WebOriginsPostInput
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
		req := &api.UpdateClientWebOriginsRequest{
			WebOrigins: data.WebOrigins,
		}
		_, err = apiClient.UpdateClientWebOrigins(jwtInfo.TokenResponse.AccessToken, data.ClientId, req)
		if err != nil {
			// Not JsonError directly: the API refuses a web origin with a 400 whose description
			// names the offending value and says what an origin should look like, and that
			// sentence is the only thing telling the administrator what to type instead. Handed
			// to JsonError as a plain error it becomes a generic 500 and the sentence goes to
			// the log. This is the same defect #122 fixed on the Redirect URIs page, and it
			// bites here now that the API refuses shapes this page's own new URL().origin
			// happily produces, such as a non-ASCII host or an IPv6 literal (#250).
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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
