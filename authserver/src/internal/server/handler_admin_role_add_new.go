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

func (s *Server) handleAdminRoleAddNewGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_roles_add_new.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminRoleAddNewPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":          message,
				"roleIdentifier": r.FormValue("roleIdentifier"),
				"description":    r.FormValue("description"),
				"csrfField":      csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_roles_add_new.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		roleIdentifier := r.FormValue("roleIdentifier")
		description := strings.TrimSpace(r.FormValue("description"))

		if strings.TrimSpace(roleIdentifier) == "" {
			renderError("Role identifier is required.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		err := identifierValidator.ValidateIdentifier(roleIdentifier)
		if err != nil {
			renderError(err.Error())
			return
		}

		existingRole, err := s.database.GetRoleByRoleIdentifier(roleIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingRole != nil {
			renderError("The role identifier is already in use.")
			return
		}

		role := &entities.Role{
			RoleIdentifier: strings.TrimSpace(inputSanitizer.Sanitize(roleIdentifier)),
			Description:    strings.TrimSpace(inputSanitizer.Sanitize(description)),
		}
		_, err = s.database.CreateRole(role)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/roles", lib.GetBaseUrl()), http.StatusFound)
	}
}
