package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
)

func (s *Server) handleAdminClientRedirectURIsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		client, err := s.database.GetClientById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.New("client not found"))
			return
		}

		adminClientRedirectURIs := struct {
			ClientId                 uint
			ClientIdentifier         string
			AuthorizationCodeEnabled bool
			RedirectURIs             map[uint]string
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

		adminClientRedirectURIs.RedirectURIs = make(map[uint]string)
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
		ClientId     uint     `json:"clientId"`
		RedirectURIs []string `json:"redirectURIs"`
		Ids          []uint   `json:"ids"`
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

		client, err := s.database.GetClientById(data.ClientId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if client == nil {
			s.jsonError(w, r, errors.New("client not found"))
			return
		}

		if client.IsSystemLevelClient() {
			s.jsonError(w, r, errors.New("trying to edit a system level client"))
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
				_, err := s.database.SaveRedirectURI(&entities.RedirectURI{
					ClientId: client.Id,
					URI:      strings.TrimSpace(strings.ToLower(redirURI)),
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
					s.jsonError(w, r, fmt.Errorf("redirect URI with Id %d not found in client %v", id, client.ClientIdentifier))
					return
				}
			}
		}

		// delete redirect URIs that have been removed
		toDelete := []uint{}
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
			err := s.database.DeleteRedirectURI(id)
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

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
