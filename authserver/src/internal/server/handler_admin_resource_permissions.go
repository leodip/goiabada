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
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"golang.org/x/exp/slices"
)

func (s *Server) handleAdminResourcePermissionsGet() http.HandlerFunc {

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
				s.redirToAuthorize(w, r, "admin-website", lib.GetBaseUrl()+r.RequestURI)
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

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_permissions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourcePermissionsPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	type permission struct {
		Id          int    `json:"id"`
		Identifier  string `json:"permissionIdentifier"`
		Description string `json:"description"`
	}

	type savePermissionsInput struct {
		Permissions []permission `json:"permissions"`
		ResourceId  uint         `json:"resourceID"`
	}

	type savePermissionsResult struct {
		RequiresAuth      bool
		SavedSuccessfully bool
		Error             string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := savePermissionsResult{
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

		idStr := chi.URLParam(r, "resourceID")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.New("resourceID is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(uint(id))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if resource == nil {
			s.jsonError(w, r, errors.New("resource not found"))
			return
		}

		var data savePermissionsInput
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if data.ResourceId != resource.ID {
			s.jsonError(w, r, errors.New("resourceID mismatch"))
			return
		}

		visitedPermissionIdentifier := []string{}
		for _, perm := range data.Permissions {

			// sanitize and trim just in case
			perm.Identifier = inputSanitizer.Sanitize(strings.TrimSpace(perm.Identifier))
			perm.Description = inputSanitizer.Sanitize(strings.TrimSpace(perm.Description))

			if slices.Contains(visitedPermissionIdentifier, perm.Identifier) {
				result.Error = fmt.Sprintf("Permission %v is duplicated.", perm.Identifier)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
				return
			}
			visitedPermissionIdentifier = append(visitedPermissionIdentifier, perm.Identifier)
		}

		for _, perm := range data.Permissions {
			if len(perm.Identifier) == 0 {
				result.Error = "Permission identifier is required."
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
				return
			}

			err = identifierValidator.ValidateIdentifier(perm.Identifier)
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
			if len(perm.Description) > maxLengthDescription {
				result.Error = "The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters."
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
				return
			}

			if perm.Id < 0 {
				// create new permission
				permissionToAdd := &entities.Permission{
					ResourceID:           resource.ID,
					Description:          perm.Description,
					PermissionIdentifier: perm.Identifier,
				}
				_, err := s.database.CreatePermission(permissionToAdd)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
			} else {
				// updating existing permission
				existingPermission, err := s.database.GetPermissionById(uint(perm.Id))
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
				if existingPermission == nil {
					s.jsonError(w, r, errors.New("permission not found"))
					return
				}
				existingPermission.PermissionIdentifier = perm.Identifier
				existingPermission.Description = perm.Description
				_, err = s.database.UpdatePermission(existingPermission)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
			}
		}

		toDelete := []uint{}
		resourcePermissions, err := s.database.GetResourcePermissions(resource.ID)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		for _, permission := range resourcePermissions {
			found := false
			for _, perm := range data.Permissions {
				if permission.PermissionIdentifier == perm.Identifier {
					found = true
					break
				}
			}
			if !found {
				toDelete = append(toDelete, permission.ID)
			}
		}

		for _, permissionID := range toDelete {
			err = s.database.DeletePermission(permissionID)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "resourcePermissionsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result.SavedSuccessfully = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAdminResourceValidatePermissionPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

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

		permissionIdentifier := inputSanitizer.Sanitize(strings.TrimSpace(data["permissionIdentifier"]))

		originalDescription := strings.TrimSpace(data["description"])
		description := inputSanitizer.Sanitize(strings.TrimSpace(data["description"]))

		if originalDescription != description {
			result.Error = "The description contains invalid characters, as we do not permit the use of HTML in the description."
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

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
