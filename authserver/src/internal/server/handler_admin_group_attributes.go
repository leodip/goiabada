package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminGroupAttributesGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("groupId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		group, err := s.database.GetGroupById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if group == nil {
			s.internalServerError(w, r, errors.New("group not found"))
			return
		}

		attributes, err := s.database.GetGroupAttributesByGroupId(group.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"description":     group.Description,
			"attributes":      attributes,
			"csrfField":       csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminGroupAttributesRemovePost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.New("groupId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		group, err := s.database.GetGroupById(uint(id))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if group == nil {
			s.jsonError(w, r, errors.New("group not found"))
			return
		}

		attributes, err := s.database.GetGroupAttributesByGroupId(group.Id)
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

		err = s.database.DeleteGroupAttributeById(uint(attributeId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditDeleteGroupAttribute, map[string]interface{}{
			"groupAttributeId": attributeId,
			"groupId":          group.Id,
			"groupIdentifier":  group.GroupIdentifier,
			"loggedInUser":     s.getLoggedInSubject(r),
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
