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

func (s *Server) handleAdminGroupAttributesEditGet() http.HandlerFunc {

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

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("attributeId is required"))
			return
		}

		id, err = strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		attribute, err := s.database.GetGroupAttributeById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if attribute == nil || attribute.GroupId != group.Id {
			s.internalServerError(w, r, errors.New("attribute not found"))
			return
		}

		bind := map[string]interface{}{
			"group":     group,
			"attribute": attribute,
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_edit.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminGroupAttributesEditPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

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

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("attributeId is required"))
			return
		}

		id, err = strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		attribute, err := s.database.GetGroupAttributeById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if attribute == nil || attribute.GroupId != group.Id {
			s.internalServerError(w, r, errors.New("attribute not found"))
			return
		}

		attribute.Key = r.FormValue("attributeKey")
		attribute.Value = r.FormValue("attributeValue")
		attribute.IncludeInAccessToken = r.FormValue("includeInAccessToken") == "on"
		attribute.IncludeInIdToken = r.FormValue("includeInIdToken") == "on"

		renderError := func(message string) {
			bind := map[string]interface{}{
				"group":     group,
				"attribute": attribute,
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_edit.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if len(attribute.Key) == 0 {
			renderError("Attribute key is required")
			return
		}

		err = identifierValidator.ValidateIdentifier(attribute.Key, false)
		if err != nil {
			renderError(err.Error())
			return
		}

		const maxLengthAttrValue = 250
		if len(attribute.Value) > maxLengthAttrValue {
			renderError("The attribute value cannot exceed a maximum length of " + strconv.Itoa(maxLengthAttrValue) + " characters. Please make the value shorter.")
			return
		}

		_, err = s.database.SaveGroupAttribute(attribute)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedGroupAttribute, map[string]interface{}{
			"groupAttributeId": attribute.Id,
			"groupId":          group.Id,
			"groupIdentifier":  group.GroupIdentifier,
			"loggedInUser":     s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("/admin/groups/%v/attributes", group.Id), http.StatusFound)
	}
}
