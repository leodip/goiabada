package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientOAuth2Get() http.HandlerFunc {

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

		adminClientOAuth2Flows := struct {
			ClientId                 uint
			ClientIdentifier         string
			IsPublic                 bool
			AuthorizationCodeEnabled bool
			ClientCredentialsEnabled bool
			IsSystemLevelClient      bool
		}{
			ClientId:                 client.Id,
			ClientIdentifier:         client.ClientIdentifier,
			IsPublic:                 client.IsPublic,
			AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
			ClientCredentialsEnabled: client.ClientCredentialsEnabled,
			IsSystemLevelClient:      client.IsSystemLevelClient(),
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		clientOAuth2FlowsSavedSuccessfully := sess.Flashes("clientOAuth2FlowsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"client":                             adminClientOAuth2Flows,
			"clientOAuth2FlowsSavedSuccessfully": len(clientOAuth2FlowsSavedSuccessfully) > 0,
			"csrfField":                          csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_oauth2_flows.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientOAuth2Post() http.HandlerFunc {

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

		isSystemLevelClient := client.IsSystemLevelClient()
		if isSystemLevelClient {
			s.internalServerError(w, r, errors.New("trying to edit a system level client"))
			return
		}

		authCodeEnabled := false
		if r.FormValue("authCodeEnabled") == "on" {
			authCodeEnabled = true
		}
		clientCredentialsEnabled := false
		if r.FormValue("clientCredentialsEnabled") == "on" {
			clientCredentialsEnabled = true
		}

		client.AuthorizationCodeEnabled = authCodeEnabled
		client.ClientCredentialsEnabled = clientCredentialsEnabled
		if client.IsPublic {
			client.ClientCredentialsEnabled = false
		}

		_, err = s.database.UpdateClient(client)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "clientOAuth2FlowsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/oauth2-flows", lib.GetBaseUrl(), client.Id), http.StatusFound)
	}
}
