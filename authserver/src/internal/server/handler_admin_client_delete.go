package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientDeleteGet() http.HandlerFunc {

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

		bind := map[string]interface{}{
			"client":    client,
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_delete.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientDeletePost() http.HandlerFunc {

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

		if client.IsSystemLevelClient() {
			s.internalServerError(w, r, errors.New("cannot delete system level client"))
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"client":    client,
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_delete.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		clientIdentifier := r.FormValue("clientIdentifier")
		if len(clientIdentifier) == 0 {
			renderError("Client identifier is required.")
			return
		}

		if client.ClientIdentifier != clientIdentifier {
			renderError("Client identifier does not match the client being deleted.")
			return
		}

		err = s.database.DeleteClient(client.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditDeletedClient, map[string]interface{}{
			"clientId":         client.Id,
			"clientIdentifier": client.ClientIdentifier,
			"loggedInUser":     s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients", lib.GetBaseUrl()), http.StatusFound)
	}
}
