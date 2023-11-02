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

func (s *Server) handleAdminGroupNewGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_new.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminGroupNewPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":           message,
				"groupIdentifier": r.FormValue("groupIdentifier"),
				"description":     r.FormValue("description"),
				"csrfField":       csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_new.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		groupIdentifier := r.FormValue("groupIdentifier")
		description := strings.TrimSpace(r.FormValue("description"))

		if strings.TrimSpace(groupIdentifier) == "" {
			renderError("Group identifier is required.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		err := identifierValidator.ValidateIdentifier(groupIdentifier, true)
		if err != nil {
			renderError(err.Error())
			return
		}

		existingGroup, err := s.database.GetGroupByGroupIdentifier(groupIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingGroup != nil {
			renderError("The group identifier is already in use.")
			return
		}

		includeInIdToken := r.FormValue("includeInIdToken") == "on"
		includeInAccessToken := r.FormValue("includeInAccessToken") == "on"

		group := &entities.Group{
			GroupIdentifier:      strings.TrimSpace(inputSanitizer.Sanitize(groupIdentifier)),
			Description:          strings.TrimSpace(inputSanitizer.Sanitize(description)),
			IncludeInIdToken:     includeInIdToken,
			IncludeInAccessToken: includeInAccessToken,
		}
		_, err = s.database.CreateGroup(group)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups", lib.GetBaseUrl()), http.StatusFound)
	}
}
