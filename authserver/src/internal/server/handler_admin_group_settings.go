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
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminGroupSettingsGet() http.HandlerFunc {

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

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		groupSettingsSavedSuccessfully := sess.Flashes("groupSettingsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"groupId":                        group.Id,
			"groupIdentifier":                group.GroupIdentifier,
			"description":                    group.Description,
			"includeInIdToken":               group.IncludeInIdToken,
			"includeInAccessToken":           group.IncludeInAccessToken,
			"groupSettingsSavedSuccessfully": len(groupSettingsSavedSuccessfully) > 0,
			"csrfField":                      csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_settings.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminGroupSettingsPost(identifierValidator identifierValidator,
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

		groupIdentifier := r.FormValue("groupIdentifier")
		description := r.FormValue("description")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"groupId":         group.Id,
				"groupIdentifier": groupIdentifier,
				"description":     description,
				"error":           message,
				"csrfField":       csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_settings.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		err = identifierValidator.ValidateIdentifier(groupIdentifier)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				renderError(valError.Description)
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		existingGroup, err := s.database.GetGroupByGroupIdentifier(groupIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingGroup != nil && existingGroup.Id != group.Id {
			renderError("The group identifier is already in use.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		group.GroupIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(groupIdentifier))
		group.Description = strings.TrimSpace(inputSanitizer.Sanitize(description))
		group.IncludeInIdToken = r.FormValue("includeInIdToken") == "on"
		group.IncludeInAccessToken = r.FormValue("includeInAccessToken") == "on"

		_, err = s.database.UpdateGroup(group)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "groupSettingsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups/%v/settings", lib.GetBaseUrl(), group.Id), http.StatusFound)
	}
}
