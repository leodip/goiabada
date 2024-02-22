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
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientRedirectURIsGet() http.HandlerFunc {

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
		client, err := s.databasev2.GetClientById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

		err = s.databasev2.ClientLoadRedirectURIs(nil, client)
		if err != nil {
			s.internalServerError(w, r, err)
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
			"client":            adminClientRedirectURIs,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_redirect_uris.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientRedirectURIsPost() http.HandlerFunc {

	type redirectURIsPostInput struct {
		ClientId     int64    `json:"clientId"`
		RedirectURIs []string `json:"redirectURIs"`
		Ids          []int64  `json:"ids"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		var data redirectURIsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		client, err := s.databasev2.GetClientById(nil, data.ClientId)
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

		err = s.databasev2.ClientLoadRedirectURIs(nil, client)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		for idx, redirURI := range data.RedirectURIs {
			_, err := url.ParseRequestURI(redirURI)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
			id := data.Ids[idx]
			if id == 0 {
				// new redirect URI (add)
				err := s.databasev2.CreateRedirectURI(nil, &entitiesv2.RedirectURI{
					ClientId: client.Id,
					URI:      strings.TrimSpace(redirURI),
				})
				if err != nil {
					s.jsonError(w, r, err)
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
					s.jsonError(w, r, errors.WithStack(fmt.Errorf("redirect URI with Id %d not found in client %v", id, client.ClientIdentifier)))
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
			err := s.databasev2.DeleteRedirectURI(nil, id)
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

		lib.LogAudit(constants.AuditUpdatedRedirectURIs, map[string]interface{}{
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
