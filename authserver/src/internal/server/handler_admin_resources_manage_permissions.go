package server

import (
	"encoding/json"
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

func (s *Server) handleAdminResourceManagePermissionsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			if s.isLoggedIn(jwtInfo) {
				http.Redirect(w, r, lib.GetBaseUrl()+"/unauthorized", http.StatusFound)
				return
			} else {
				s.redirToAuthorize(w, r, "admin-website", lib.GetBaseUrl()+r.RequestURI, "openid authserver:admin-website")
				return
			}
		}

		idStr := chi.URLParam(r, "resourceID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("resourceID is required"))
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

		resourcePermissionsSavedSuccessfully := sess.Flashes("resourcePermissionsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		permissions, err := s.database.GetResourcePermissions(resource.ID)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"resourceID":                           resource.ID,
			"resourceIdentifier":                   resource.ResourceIdentifier,
			"resourceDescription":                  resource.Description,
			"resourcePermissionsSavedSuccessfully": len(resourcePermissionsSavedSuccessfully) > 0,
			"permissions":                          permissions,
			"csrfField":                            csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/admin_resources_permissions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourceManagePermissionsPost(identifierValidator identifierValidator) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		idStr := chi.URLParam(r, "resourceID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("resourceID is required"))
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

		resourceIdentifier := strings.TrimSpace(r.FormValue("resourceIdentifier"))
		description := strings.TrimSpace(r.FormValue("description"))

		renderError := func(message string) {
			bind := map[string]interface{}{
				"resourceID":         resource.ID,
				"resourceIdentifier": resourceIdentifier,
				"description":        description,
				"error":              message,
				"csrfField":          csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/admin_layout.html", "/admin_resources_settings.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			renderError("Your authentication session has expired. To continue, please reload the page and re-authenticate to start a new session.")
			return
		}

		err = identifierValidator.ValidateIdentifier(resourceIdentifier)
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
		if existingResource != nil && existingResource.ID != resource.ID {
			renderError("The resource identifier is already in use.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		resource.ResourceIdentifier = resourceIdentifier
		resource.Description = description

		_, err = s.database.UpdateResource(resource)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "resourceSettingsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources/%v/settings", lib.GetBaseUrl(), resource.ID), http.StatusFound)
	}
}

func (s *Server) handleValidatePermissionPost(identifierValidator identifierValidator) http.HandlerFunc {

	type validatePermissionResult struct {
		RequiresAuth bool
		Valid        bool
		Error        string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := validatePermissionResult{
			RequiresAuth: true,
		}

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			result.RequiresAuth = false
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		var data map[string]string
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissionIdentifier := data["permissionIdentifier"]
		description := data["description"]

		if len(permissionIdentifier) == 0 {
			result.Error = "Permission identifier is required."
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		err = identifierValidator.ValidateIdentifier(permissionIdentifier)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				result.Error = valError.Description
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
				return
			} else {
				s.jsonError(w, r, err)
				return
			}
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			result.Error = "The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters."
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		result.Valid = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)

	}
}
