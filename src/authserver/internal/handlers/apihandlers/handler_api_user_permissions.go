package apihandlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/models"
)

func HandleAPIUserPermissionsGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to get user by ID"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		err = database.UserLoadPermissions(nil, user)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to load user permissions"), "user_id", user.Id)
			return
		}

		// Load resource information for each permission
		for i := range user.Permissions {
			resource, err := database.GetResourceById(nil, user.Permissions[i].ResourceId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to load resource information"), "user_id", user.Id, "resource_id", user.Permissions[i].ResourceId)
				return
			}
			if resource != nil {
				user.Permissions[i].Resource = *resource
			}
		}

		response := api.GetUserPermissionsResponse{
			User:        *api.ToUserResponse(user),
			Permissions: api.ToPermissionResponses(user.Permissions),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIUserPermissionsPut(
	database data.Database,
	authHelper *handlerhelpers.AuthHelper,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to get user by ID"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var request api.UpdateUserPermissionsRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeJSONError(w, "Invalid request body", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Load current user permissions
		err = database.UserLoadPermissions(nil, user)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to load current user permissions"), "user_id", user.Id)
			return
		}

		// Validate that all requested permissions exist
		for _, permissionId := range request.PermissionIds {
			permission, err := database.GetPermissionById(nil, permissionId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to get permission by ID during validation"), "user_id", user.Id, "permission_id", permissionId)
				return
			}
			if permission == nil {
				writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
		}

		// Add new permissions that don't already exist
		for _, permissionId := range request.PermissionIds {
			found := false
			for _, permission := range user.Permissions {
				if permission.Id == permissionId {
					found = true
					break
				}
			}

			if !found {
				permission, err := database.GetPermissionById(nil, permissionId)
				if err != nil {
					writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to retrieve permission for user permission creation"), "user_id", user.Id, "permission_id", permissionId)
					return
				}

				err = database.CreateUserPermission(nil, &models.UserPermission{
					UserId:       user.Id,
					PermissionId: permission.Id,
				})
				if err != nil {
					writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to create user permission"), "user_id", user.Id, "permission_id", permission.Id)
					return
				}

				auditLogger.Log(r.Context(), constants.AuditAddedUserPermission, map[string]interface{}{
					"userId":       user.Id,
					"permissionId": permission.Id,
					"loggedInUser": authHelper.GetLoggedInSubject(r),
				})
			}
		}

		// Remove permissions that are not in the request
		toDelete := []int64{}
		for _, permission := range user.Permissions {
			found := false
			for _, permissionId := range request.PermissionIds {
				if permission.Id == permissionId {
					found = true
					break
				}
			}

			if !found {
				toDelete = append(toDelete, permission.Id)
			}
		}

		for _, permissionId := range toDelete {
			userPermission, err := database.GetUserPermissionByUserIdAndPermissionId(nil, user.Id, permissionId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to find user permission for deletion"), "user_id", user.Id, "permission_id", permissionId)
				return
			}

			err = database.DeleteUserPermission(nil, userPermission.Id)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to delete user permission"), "user_id", user.Id, "permission_id", permissionId)
				return
			}

			auditLogger.Log(r.Context(), constants.AuditDeletedUserPermission, map[string]interface{}{
				"userId":       user.Id,
				"permissionId": permissionId,
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})
		}

		// Return success response
		response := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, response)
	}
}
