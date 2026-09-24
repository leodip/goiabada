package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// groupPermissionsDatabase is what the group permission endpoints need: the group's grants and
// the catalogue they are granted from.
type groupPermissionsDatabase interface {
	CountGroupMembers(ctx context.Context, tx *sql.Tx, groupId int64) (int, error)
	CreateGroupPermission(ctx context.Context, tx *sql.Tx, groupPermission *models.GroupPermission) error
	DeleteGroupPermission(ctx context.Context, tx *sql.Tx, groupPermissionId int64) error
	GetGroupById(ctx context.Context, tx *sql.Tx, groupId int64) (*models.Group, error)
	GetGroupPermissionByGroupIdAndPermissionId(ctx context.Context, tx *sql.Tx, groupId, permissionId int64) (*models.GroupPermission, error)
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*models.Permission, error)
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*models.Resource, error)
	GroupLoadPermissions(ctx context.Context, tx *sql.Tx, group *models.Group) error
}

func HandleAPIGroupPermissionsGet(
	database groupPermissionsDatabase,
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

		group, err := database.GetGroupById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group by ID for permissions"), "group_id", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		err = database.GroupLoadPermissions(r.Context(), nil, group)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading group permissions"), "group_id", group.Id)
			return
		}

		// Load resource information for each permission
		for i := range group.Permissions {
			resource, getResourceErr := database.GetResourceById(r.Context(), nil, group.Permissions[i].ResourceId)
			if getResourceErr != nil {
				writeInternalServerError(w, r, errs.Wrap(getResourceErr, "database error getting resource by ID for permission"), "resource_id", group.Permissions[i].ResourceId, "group_id", group.Id)
				return
			}
			if resource != nil {
				group.Permissions[i].Resource = *resource
			}
		}

		memberCounts, err := countGroupMembers(r.Context(), database, []models.Group{*group})
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		response := api.GetGroupPermissionsResponse{
			Group:       *apimapping.ToGroupResponse(group, memberCounts[group.Id]),
			Permissions: apimapping.ToPermissionResponses(group.Permissions),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupPermissionsPut(
	database groupPermissionsDatabase,
	auditLogger AuditLogger,
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

		group, err := database.GetGroupById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group by ID for permissions update"), "group_id", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var request api.UpdateGroupPermissionsRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&request); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
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
		err = database.GroupLoadPermissions(r.Context(), nil, group)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading current group permissions for update"), "group_id", group.Id)
			return
		}

		// Validate that all requested permissions exist
		for _, permissionId := range request.PermissionIds {
			permission, err := database.GetPermissionById(r.Context(), nil, permissionId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error getting permission by ID for validation"), "permission_id", permissionId, "group_id", group.Id)
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
				permission, err := database.GetPermissionById(r.Context(), nil, permissionId)
				if err != nil {
					writeInternalServerError(w, r, errs.Wrap(err, "database error retrieving permission for group assignment"), "permission_id", permissionId, "group_id", group.Id)
					return
				}
				// Deleted since the validation above read it: the answer that read would give
				// now, rather than a dereference of nil (#425).
				if permission == nil {
					writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
					return
				}

				err = database.CreateGroupPermission(r.Context(), nil, &models.GroupPermission{
					GroupId:      group.Id,
					PermissionId: permission.Id,
				})
				if err != nil {
					writeInternalServerError(w, r, errs.Wrap(err, "database error creating group permission"), "group_id", group.Id, "permission_id", permission.Id)
					return
				}

				auditLogger.Log(r.Context(), audit.AuditAddedGroupPermission, map[string]interface{}{
					"groupId":      group.Id,
					"permissionId": permission.Id,
					"loggedInUser": callerSubject(r),
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
			groupPermission, err := database.GetGroupPermissionByGroupIdAndPermissionId(r.Context(), nil, group.Id, permissionId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error getting group permission for deletion"), "group_id", group.Id, "permission_id", permissionId)
				return
			}
			// Removed by a concurrent request since the load above: the grant is gone, which is
			// what this request asked for, and this request removed nothing to audit (#425).
			if groupPermission == nil {
				continue
			}

			err = database.DeleteGroupPermission(r.Context(), nil, groupPermission.Id)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error deleting group permission"), "group_permission_id", groupPermission.Id, "group_id", group.Id, "permission_id", permissionId)
				return
			}

			auditLogger.Log(r.Context(), audit.AuditDeletedGroupPermission, map[string]interface{}{
				"groupId":      group.Id,
				"permissionId": permissionId,
				"loggedInUser": callerSubject(r),
			})
		}

		// Return success response
		response := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, response)
	}
}
