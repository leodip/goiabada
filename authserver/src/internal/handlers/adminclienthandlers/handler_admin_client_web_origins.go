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
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
)

func HandleAdminClientWebOriginsGet(
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

		err = database.ClientLoadWebOrigins(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		adminClientWebOrigins := struct {
			ClientId                 int64
			ClientIdentifier         string
			AuthorizationCodeEnabled bool
			WebOrigins               map[int64]string
			IsSystemLevelClient      bool
		}{
			ClientId:                 client.Id,
			ClientIdentifier:         client.ClientIdentifier,
			AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
			IsSystemLevelClient:      client.IsSystemLevelClient(),
		}

		sort.Slice(client.WebOrigins, func(i, j int) bool {
			return client.WebOrigins[i].Origin < client.WebOrigins[j].Origin
		})

		adminClientWebOrigins.WebOrigins = make(map[int64]string)
		for _, origin := range client.WebOrigins {
			adminClientWebOrigins.WebOrigins[origin.Id] = origin.Origin
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
			"client":            adminClientWebOrigins,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
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
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	type webOriginsPostInput struct {
		ClientId   int64    `json:"clientId"`
		WebOrigins []string `json:"webOrigins"`
		Ids        []int64  `json:"ids"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var data webOriginsPostInput
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

		err = database.ClientLoadWebOrigins(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		for idx, redirURI := range data.WebOrigins {
			_, err := url.ParseRequestURI(redirURI)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}
			id := data.Ids[idx]
			if id == 0 {
				// new web origin (add)
				err := database.CreateWebOrigin(nil, &models.WebOrigin{
					ClientId: client.Id,
					Origin:   strings.ToLower(strings.TrimSpace(strings.ToLower(redirURI))),
				})
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}
			} else {
				// existing web origin
				found := false
				for _, webOrigin := range client.WebOrigins {
					if webOrigin.Id == id {
						found = true
						break
					}
				}

				if !found {
					httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("web origin with Id %d not found in client %v", id, client.ClientIdentifier)))
					return
				}
			}
		}

		// delete web origin that have been removed
		toDelete := []int64{}
		for _, webOrigin := range client.WebOrigins {
			found := false
			for _, id := range data.Ids {
				if webOrigin.Id == id {
					found = true
					break
				}
			}
			if !found {
				toDelete = append(toDelete, webOrigin.Id)
			}
		}

		for _, id := range toDelete {
			err := database.DeleteWebOrigin(nil, id)
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

		lib.LogAudit(constants.AuditUpdatedWebOrigins, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
