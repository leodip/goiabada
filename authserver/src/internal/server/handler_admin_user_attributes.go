package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserAttributesGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.databasev2.GetUserById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		attributes, err := s.databasev2.GetUserAttributesByUserId(nil, user.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":       user,
			"attributes": attributes,
			"page":       r.URL.Query().Get("page"),
			"query":      r.URL.Query().Get("query"),
			"csrfField":  csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserAttributesRemovePost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user, err := s.databasev2.GetUserById(nil, id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if user == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		attributes, err := s.databasev2.GetUserAttributesByUserId(nil, user.Id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		attributeIdStr := chi.URLParam(r, "attributeId")
		if len(attributeIdStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("attribute id is required")))
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		found := false
		for _, attribute := range attributes {
			if attribute.Id == attributeId {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, errors.WithStack(errors.New("attribute not found")))
			return
		}

		err = s.databasev2.DeleteUserAttribute(nil, attributeId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditDeleteUserAttribute, map[string]interface{}{
			"userId":          user.Id,
			"userAttributeId": attributeId,
			"loggedInUser":    s.getLoggedInSubject(r),
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
