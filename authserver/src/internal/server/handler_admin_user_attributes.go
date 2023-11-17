package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
)

func (s *Server) handleAdminUserAttributesGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("userId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.database.GetUserById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user == nil {
			s.internalServerError(w, r, errors.New("user not found"))
			return
		}

		attributes, err := s.database.GetUserAttributesByUserId(user.Id)
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
			s.jsonError(w, r, errors.New("userId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user, err := s.database.GetUserById(uint(id))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if user == nil {
			s.jsonError(w, r, errors.New("user not found"))
			return
		}

		attributes, err := s.database.GetUserAttributesByUserId(user.Id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		attributeIdStr := chi.URLParam(r, "attributeId")
		if len(attributeIdStr) == 0 {
			s.jsonError(w, r, errors.New("attribute id is required"))
			return
		}

		attributeId, err := strconv.ParseUint(attributeIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		found := false
		for _, attribute := range attributes {
			if attribute.Id == uint(attributeId) {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, errors.New("attribute not found"))
			return
		}

		err = s.database.DeleteUserAttributeById(uint(attributeId))
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
