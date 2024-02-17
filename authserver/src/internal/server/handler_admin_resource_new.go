package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminResourceNewGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_new.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourceNewPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":              message,
				"resourceIdentifier": r.FormValue("resourceIdentifier"),
				"description":        r.FormValue("description"),
				"csrfField":          csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_new.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		resourceIdentifier := r.FormValue("resourceIdentifier")
		description := r.FormValue("description")

		if strings.TrimSpace(resourceIdentifier) == "" {
			renderError("Resource identifier is required.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		err := identifierValidator.ValidateIdentifier(resourceIdentifier, true)
		if err != nil {
			renderError(err.Error())
			return
		}

		existingResource, err := s.databasev2.GetResourceByResourceIdentifier(nil, resourceIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingResource != nil {
			renderError("The resource identifier is already in use.")
			return
		}

		resource := &entitiesv2.Resource{
			ResourceIdentifier: strings.TrimSpace(inputSanitizer.Sanitize(resourceIdentifier)),
			Description:        strings.TrimSpace(inputSanitizer.Sanitize(description)),
		}
		err = s.databasev2.CreateResource(nil, resource)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditCreatedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", lib.GetBaseUrl()), http.StatusFound)
	}
}
