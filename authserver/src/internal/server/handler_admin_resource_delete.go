package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminResourceDeleteGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("resourceId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.New("resource not found"))
			return
		}

		permissions, err := s.database.GetResourcePermissions(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"resource":    resource,
			"permissions": permissions,
			"csrfField":   csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_delete.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourceDeletePost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("resourceId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.New("resource not found"))
			return
		}

		if resource.IsSystemLevelResource() {
			s.internalServerError(w, r, errors.New("system level resources cannot be deleted"))
			return
		}

		permissions, err := s.database.GetResourcePermissions(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"resource":    resource,
				"permissions": permissions,
				"error":       message,
				"csrfField":   csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_delete.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		resourceIdentifier := r.FormValue("resourceIdentifier")
		if len(resourceIdentifier) == 0 {
			renderError("Resource identifier is required.")
			return
		}

		if resource.ResourceIdentifier != resourceIdentifier {
			renderError("Resource identifier does not match the resource being deleted.")
			return
		}

		err = s.database.DeleteResource(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", lib.GetBaseUrl()), http.StatusFound)
	}
}
