package server

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
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientWebOriginsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		client, err := s.database.GetClientById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

		err = s.database.ClientLoadWebOrigins(nil, client)
		if err != nil {
			s.internalServerError(w, r, err)
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

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            adminClientWebOrigins,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_web_origins.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientWebOriginsPost() http.HandlerFunc {

	type webOriginsPostInput struct {
		ClientId   int64    `json:"clientId"`
		WebOrigins []string `json:"webOrigins"`
		Ids        []int64  `json:"ids"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		var data webOriginsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		client, err := s.database.GetClientById(nil, data.ClientId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if client == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

		if client.IsSystemLevelClient() {
			s.jsonError(w, r, errors.WithStack(errors.New("trying to edit a system level client")))
			return
		}

		err = s.database.ClientLoadWebOrigins(nil, client)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		for idx, redirURI := range data.WebOrigins {
			_, err := url.ParseRequestURI(redirURI)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
			id := data.Ids[idx]
			if id == 0 {
				// new web origin (add)
				err := s.database.CreateWebOrigin(nil, &entities.WebOrigin{
					ClientId: client.Id,
					Origin:   strings.ToLower(strings.TrimSpace(strings.ToLower(redirURI))),
				})
				if err != nil {
					s.jsonError(w, r, err)
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
					s.jsonError(w, r, errors.WithStack(fmt.Errorf("web origin with Id %d not found in client %v", id, client.ClientIdentifier)))
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
			err := s.database.DeleteWebOrigin(nil, id)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedWebOrigins, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": s.getLoggedInSubject(r),
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
