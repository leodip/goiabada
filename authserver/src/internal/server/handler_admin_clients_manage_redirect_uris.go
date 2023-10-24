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
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientManageRedirectURIsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			if s.isLoggedIn(jwtInfo) {
				http.Redirect(w, r, lib.GetBaseUrl()+"/unauthorized", http.StatusFound)
				return
			} else {
				s.redirToAuthorize(w, r, "admin-website", lib.GetBaseUrl()+r.RequestURI)
				return
			}
		}

		idStr := chi.URLParam(r, "clientID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientID is required"))
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

		adminClientRedirectURIs := dtos.AdminClientRedirectUris{
			ClientID:                 client.ID,
			ClientIdentifier:         client.ClientIdentifier,
			AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
		}

		sort.Slice(client.RedirectUris, func(i, j int) bool {
			return client.RedirectUris[i].Uri < client.RedirectUris[j].Uri
		})

		adminClientRedirectURIs.RedirectUris = make(map[uint]string)
		for _, redirectUri := range client.RedirectUris {
			adminClientRedirectURIs.RedirectUris[redirectUri.ID] = redirectUri.Uri
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		clientRedirectUrisSavedSuccessfully := sess.Flashes("clientRedirectUrisSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"client":                              adminClientRedirectURIs,
			"clientRedirectUrisSavedSuccessfully": len(clientRedirectUrisSavedSuccessfully) > 0,
			"csrfField":                           csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_redirect_uris.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientManageRedirectURIsPost() http.HandlerFunc {

	type redirectUrisPostInput struct {
		ClientID     uint     `json:"clientID"`
		RedirectUris []string `json:"redirectUris"`
		Ids          []uint   `json:"ids"`
	}

	type redirectUrisPostResult struct {
		RequiresAuth      bool
		SavedSuccessfully bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := redirectUrisPostResult{
			RequiresAuth: true,
		}

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			result.RequiresAuth = false
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		var data redirectUrisPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		client, err := s.database.GetClientById(data.ClientID)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if client == nil {
			s.jsonError(w, r, errors.New("client not found"))
			return
		}

		for idx, redirUri := range data.RedirectUris {
			_, err := url.ParseRequestURI(redirUri)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
			id := data.Ids[idx]
			if id == 0 {
				// new redirect URI (add)
				_, err := s.database.CreateRedirectUri(&entities.RedirectUri{
					ClientID: client.ID,
					Uri:      strings.TrimSpace(strings.ToLower(redirUri)),
				})
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
			} else {
				// existing redirect URI
				found := false
				for _, redirectUri := range client.RedirectUris {
					if redirectUri.ID == id {
						found = true
						break
					}
				}

				if !found {
					s.jsonError(w, r, fmt.Errorf("redirect URI with ID %d not found in client %v", id, client.ClientIdentifier))
					return
				}
			}
		}

		// delete redirect URIs that have been removed
		toDelete := []uint{}
		for _, redirectUri := range client.RedirectUris {
			found := false
			for _, id := range data.Ids {
				if redirectUri.ID == id {
					found = true
					break
				}
			}
			if !found {
				toDelete = append(toDelete, redirectUri.ID)
			}
		}

		for _, id := range toDelete {
			err := s.database.DeleteRedirectUri(id)
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

		sess.AddFlash("true", "clientRedirectUrisSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result.SavedSuccessfully = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
