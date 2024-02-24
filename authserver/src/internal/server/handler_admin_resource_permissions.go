package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminResourcePermissionsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("resource not found")))
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

		permissions, err := s.database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"resourceId":            resource.Id,
			"resourceIdentifier":    resource.ResourceIdentifier,
			"resourceDescription":   resource.Description,
			"isSystemLevelResource": resource.IsSystemLevelResource(),
			"savedSuccessfully":     len(savedSuccessfully) > 0,
			"permissions":           permissions,
			"csrfField":             csrf.TemplateField(r),
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
		Id          int64  `json:"id"`
		Identifier  string `json:"permissionIdentifier"`
		Description string `json:"description"`
	}

	type savePermissionsInput struct {
		Permissions []permission `json:"permissions"`
		ResourceId  int64        `json:"resourceId"`
	}

	type savePermissionsResult struct {
		Success bool
		Error   string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := savePermissionsResult{}

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(nil, id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if resource == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		if resource.IsSystemLevelResource() {
			s.jsonError(w, r, errors.WithStack(errors.New("system level resources cannot be modified")))
			return
		}

		var data savePermissionsInput
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if data.ResourceId != resource.Id {
			s.jsonError(w, r, errors.WithStack(errors.New("resourceId mismatch")))
			return
		}

		visitedPermissionIdentifier := []string{}
		for _, perm := range data.Permissions {

			// trim and sanitize just in case
			perm.Identifier = strings.TrimSpace(inputSanitizer.Sanitize(perm.Identifier))
			perm.Description = strings.TrimSpace(inputSanitizer.Sanitize(perm.Description))

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

			err = identifierValidator.ValidateIdentifier(perm.Identifier, true)
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
					ResourceId:           resource.Id,
					Description:          perm.Description,
					PermissionIdentifier: perm.Identifier,
				}
				err := s.database.CreatePermission(nil, permissionToAdd)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
			} else {
				// updating existing permission
				existingPermission, err := s.database.GetPermissionById(nil, perm.Id)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
				if existingPermission == nil {
					s.jsonError(w, r, errors.WithStack(errors.New("permission not found")))
					return
				}
				existingPermission.PermissionIdentifier = perm.Identifier
				existingPermission.Description = perm.Description
				err = s.database.UpdatePermission(nil, existingPermission)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
			}
		}

		toDelete := []int64{}
		resourcePermissions, err := s.database.GetPermissionsByResourceId(nil, resource.Id)
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
				toDelete = append(toDelete, permission.Id)
			}
		}

		for _, permissionId := range toDelete {
			err = s.database.DeletePermission(nil, permissionId)
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

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedResourcePermissions, map[string]interface{}{
			"resourceId":   resource.Id,
			"loggedInUser": s.getLoggedInSubject(r),
		})

		result.Success = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAdminResourceValidatePermissionPost(identifierValidator identifierValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	type validatePermissionResult struct {
		Valid bool
		Error string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := validatePermissionResult{}

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

		err = identifierValidator.ValidateIdentifier(permissionIdentifier, true)
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
