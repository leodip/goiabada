package adminclienthandlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/audit"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/data"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/models"
)

func HandleAdminClientRedirectURIsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
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
		client, err := database.GetClientById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
			return
		}

		err = database.ClientLoadRedirectURIs(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		adminClientRedirectURIs := struct {
			ClientId                 int64
			ClientIdentifier         string
			AuthorizationCodeEnabled bool
			RedirectURIs             map[int64]string
			IsSystemLevelClient      bool
		}{
			ClientId:                 client.Id,
			ClientIdentifier:         client.ClientIdentifier,
			AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
			IsSystemLevelClient:      client.IsSystemLevelClient(),
		}

		sort.Slice(client.RedirectURIs, func(i, j int) bool {
			return client.RedirectURIs[i].URI < client.RedirectURIs[j].URI
		})

		adminClientRedirectURIs.RedirectURIs = make(map[int64]string)
		for _, redirectURI := range client.RedirectURIs {
			adminClientRedirectURIs.RedirectURIs[redirectURI.Id] = redirectURI.URI
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
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
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	type redirectURIsPostInput struct {
		ClientId     int64    `json:"clientId"`
		RedirectURIs []string `json:"redirectURIs"`
		Ids          []int64  `json:"ids"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var data redirectURIsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		client, err := database.GetClientById(nil, data.ClientId)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", data.ClientId))))
			return
		}

		if client.IsSystemLevelClient() {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("trying to edit a system level client")))
			return
		}

		err = database.ClientLoadRedirectURIs(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		for idx, redirURI := range data.RedirectURIs {
			_, err := url.ParseRequestURI(redirURI)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}
			id := data.Ids[idx]
			if id == 0 {
				// new redirect URI (add)
				err := database.CreateRedirectURI(nil, &models.RedirectURI{
					ClientId: client.Id,
					URI:      strings.TrimSpace(redirURI),
				})
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}
			} else {
				// existing redirect URI
				found := false
				for _, redirectURI := range client.RedirectURIs {
					if redirectURI.Id == id {
						found = true
						break
					}
				}

				if !found {
					httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("redirect URI with Id %d not found in client %v", id, client.ClientIdentifier)))
					return
				}
			}
		}

		// delete redirect URIs that have been removed
		toDelete := []int64{}
		for _, redirectURI := range client.RedirectURIs {
			found := false
			for _, id := range data.Ids {
				if redirectURI.Id == id {
					found = true
					break
				}
			}
			if !found {
				toDelete = append(toDelete, redirectURI.Id)
			}
		}

		for _, id := range toDelete {
			err := database.DeleteRedirectURI(nil, id)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		audit.Log(constants.AuditUpdatedRedirectURIs, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
