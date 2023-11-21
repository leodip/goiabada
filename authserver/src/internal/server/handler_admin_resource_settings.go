package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminResourceSettingsGet() http.HandlerFunc {

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
			"resourceId":            resource.Id,
			"resourceIdentifier":    resource.ResourceIdentifier,
			"description":           resource.Description,
			"isSystemLevelResource": resource.IsSystemLevelResource(),
			"savedSuccessfully":     len(savedSuccessfully) > 0,
			"csrfField":             csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_settings.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourceSettingsPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

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
			s.internalServerError(w, r, errors.New("cannot update settings for a system level resource"))
			return
		}

		resourceIdentifier := r.FormValue("resourceIdentifier")
		description := r.FormValue("description")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"resourceId":         resource.Id,
				"resourceIdentifier": resourceIdentifier,
				"description":        description,
				"error":              message,
				"csrfField":          csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_settings.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		err = identifierValidator.ValidateIdentifier(resourceIdentifier, true)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				renderError(valError.Description)
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		existingResource, err := s.database.GetResourceByResourceIdentifier(resourceIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingResource != nil && existingResource.Id != resource.Id {
			renderError("The resource identifier is already in use.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		resource.ResourceIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(resourceIdentifier))
		resource.Description = strings.TrimSpace(inputSanitizer.Sanitize(description))

		_, err = s.database.SaveResource(resource)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources/%v/settings", lib.GetBaseUrl(), resource.Id), http.StatusFound)
	}
}
