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

func (s *Server) handleAdminUserAttributesEditGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("userId is required"))
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
			s.internalServerError(w, r, errors.New("user not found"))
			return
		}

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("attributeId is required"))
			return
		}

		id, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		attribute, err := s.databasev2.GetUserAttributeById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if attribute == nil || attribute.UserId != user.Id {
			s.internalServerError(w, r, errors.New("attribute not found"))
			return
		}

		bind := map[string]interface{}{
			"user":      user,
			"attribute": attribute,
			"page":      r.URL.Query().Get("page"),
			"query":     r.URL.Query().Get("query"),
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserAttributesEditPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("userId is required"))
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
			s.internalServerError(w, r, errors.New("user not found"))
			return
		}

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("attributeId is required"))
			return
		}

		id, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		attribute, err := s.databasev2.GetUserAttributeById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if attribute == nil || attribute.UserId != user.Id {
			s.internalServerError(w, r, errors.New("attribute not found"))
			return
		}

		attribute.Key = r.FormValue("attributeKey")
		attribute.Value = r.FormValue("attributeValue")
		attribute.IncludeInAccessToken = r.FormValue("includeInAccessToken") == "on"
		attribute.IncludeInIdToken = r.FormValue("includeInIdToken") == "on"

		renderError := func(message string) {
			bind := map[string]interface{}{
				"user":      user,
				"attribute": attribute,
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", bind)
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

		err = s.databasev2.UpdateUserAttribute(nil, attribute)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedUserAttribute, map[string]interface{}{
			"userId":          user.Id,
			"userAttributeId": attribute.Id,
			"loggedInUser":    s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/attributes?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
