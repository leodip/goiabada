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
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminRoleSettingsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			s.redirToAuthorize(w, r, "system-website", lib.GetBaseUrl()+r.RequestURI)
			return
		}

		idStr := chi.URLParam(r, "roleID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("roleID is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		role, err := s.database.GetRoleById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if role == nil {
			s.internalServerError(w, r, errors.New("role not found"))
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		roleSettingsSavedSuccessfully := sess.Flashes("roleSettingsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"roleID":                        role.ID,
			"roleIdentifier":                role.RoleIdentifier,
			"description":                   role.Description,
			"roleSettingsSavedSuccessfully": len(roleSettingsSavedSuccessfully) > 0,
			"csrfField":                     csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_roles_settings.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminRoleSettingsPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		idStr := chi.URLParam(r, "roleID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("roleID is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		role, err := s.database.GetRoleById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if role == nil {
			s.internalServerError(w, r, errors.New("role not found"))
			return
		}

		roleIdentifier := r.FormValue("roleIdentifier")
		description := r.FormValue("description")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"roleID":         role.ID,
				"roleIdentifier": roleIdentifier,
				"description":    description,
				"error":          message,
				"csrfField":      csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_roles_settings.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			renderError("Your authentication session has expired. To continue, please reload the page and re-authenticate to start a new session.")
			return
		}

		err = identifierValidator.ValidateIdentifier(roleIdentifier)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				renderError(valError.Description)
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		existingRole, err := s.database.GetRoleByRoleIdentifier(roleIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if existingRole != nil && existingRole.ID != role.ID {
			renderError("The role identifier is already in use.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		role.RoleIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(roleIdentifier))
		role.Description = strings.TrimSpace(inputSanitizer.Sanitize(description))

		_, err = s.database.UpdateRole(role)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "roleSettingsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/roles/%v/settings", lib.GetBaseUrl(), role.ID), http.StatusFound)
	}
}
