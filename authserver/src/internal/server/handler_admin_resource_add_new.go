package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminResourceAddNewGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_add_new.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourceAddNewPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":              message,
				"resourceIdentifier": r.FormValue("resourceIdentifier"),
				"description":        r.FormValue("description"),
				"csrfField":          csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_add_new.html", bind)
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

		err := identifierValidator.ValidateIdentifier(resourceIdentifier)
		if err != nil {
			renderError(err.Error())
			return
		}

		existingResource, err := s.database.GetResourceByResourceIdentifier(resourceIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingResource != nil {
			renderError("The resource identifier is already in use.")
			return
		}

		resource := &entities.Resource{
			ResourceIdentifier: strings.TrimSpace(inputSanitizer.Sanitize(resourceIdentifier)),
			Description:        strings.TrimSpace(inputSanitizer.Sanitize(description)),
		}
		_, err = s.database.CreateResource(resource)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", lib.GetBaseUrl()), http.StatusFound)
	}
}