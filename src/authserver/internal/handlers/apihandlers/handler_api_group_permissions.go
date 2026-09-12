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
	"github.com/leodip/goiabada/core/models"
)

func HandleAPIGroupPermissionsGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		group, err := database.GetGroupById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID for permissions"), "group_id", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		err = database.GroupLoadPermissions(nil, group)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error loading group permissions"), "group_id", group.Id)
			return
		}

		// Load resource information for each permission
		for i := range group.Permissions {
			resource, err := database.GetResourceById(nil, group.Permissions[i].ResourceId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting resource by ID for permission"), "resource_id", group.Permissions[i].ResourceId, "group_id", group.Id)
				return
			}
			if resource != nil {
				group.Permissions[i].Resource = *resource
			}
		}

		// Get member count for the group response
		memberCount, err := database.CountGroupMembers(nil, group.Id)
		if err != nil {
			memberCount = 0 // Continue with 0 count on error
		}

		response := api.GetGroupPermissionsResponse{
			Group:       *api.ToGroupResponse(group, memberCount),
			Permissions: api.ToPermissionResponses(group.Permissions),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupPermissionsPut(
	database data.Database,
	authHelper handlers.AuthHelper,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		group, err := database.GetGroupById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID for permissions update"), "group_id", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var request api.UpdateGroupPermissionsRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeJSONError(w, "Invalid request body", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Deduplicate permission IDs to avoid creating duplicate records
		uniquePermissionIds := make([]int64, 0)
		seenIds := make(map[int64]bool)
		for _, permissionId := range request.PermissionIds {
			if !seenIds[permissionId] {
				uniquePermissionIds = append(uniquePermissionIds, permissionId)
				seenIds[permissionId] = true
			}
		}
		request.PermissionIds = uniquePermissionIds

		// Load current group permissions
		err = database.GroupLoadPermissions(nil, group)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error loading current group permissions for update"), "group_id", group.Id)
			return
		}

		// Validate that all requested permissions exist
		for _, permissionId := range request.PermissionIds {
			permission, err := database.GetPermissionById(nil, permissionId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting permission by ID for validation"), "permission_id", permissionId, "group_id", group.Id)
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
			for _, permission := range group.Permissions {
				if permission.Id == permissionId {
					found = true
					break
				}
			}

			if !found {
				permission, err := database.GetPermissionById(nil, permissionId)
				if err != nil {
					writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error retrieving permission for group assignment"), "permission_id", permissionId, "group_id", group.Id)
					return
				}

				err = database.CreateGroupPermission(nil, &models.GroupPermission{
					GroupId:      group.Id,
					PermissionId: permission.Id,
				})
				if err != nil {
					writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error creating group permission"), "group_id", group.Id, "permission_id", permission.Id)
					return
				}

				auditLogger.Log(constants.AuditAddedGroupPermission, map[string]interface{}{
					"groupId":      group.Id,
					"permissionId": permission.Id,
					"loggedInUser": authHelper.GetLoggedInSubject(r),
				})
			}
		}

		// Remove permissions that are not in the request
		toDelete := []int64{}
		for _, permission := range group.Permissions {
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
			groupPermission, err := database.GetGroupPermissionByGroupIdAndPermissionId(nil, group.Id, permissionId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group permission for deletion"), "group_id", group.Id, "permission_id", permissionId)
				return
			}

			err = database.DeleteGroupPermission(nil, groupPermission.Id)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error deleting group permission"), "group_permission_id", groupPermission.Id, "group_id", group.Id, "permission_id", permissionId)
				return
			}

			auditLogger.Log(constants.AuditDeletedGroupPermission, map[string]interface{}{
				"groupId":      group.Id,
				"permissionId": permissionId,
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})
		}

		// Return success response
		response := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, response)
	}
}
