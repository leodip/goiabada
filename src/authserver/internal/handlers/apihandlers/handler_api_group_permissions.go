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
	GetGroupPermissionsByGroupId(ctx context.Context, tx *sql.Tx, groupId int64) ([]models.GroupPermission, error)
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*models.Permission, error)
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*models.Resource, error)
	GroupLoadPermissions(ctx context.Context, tx *sql.Tx, group *models.Group) error
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
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

		// The set as the caller loaded it, required as it is on every list save: absent or null
		// decodes to nil and is refused, [] means the caller read no grants (#428).
		if request.ExpectedPermissionIds == nil {
			writeJSONError(w, "expectedPermissionIds is required: send the permission ids as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Deduplicate permission IDs, so each is validated once and audited once.
		wanted := firstOccurrences(request.PermissionIds)

		// Validate that all requested permissions exist
		for _, permissionId := range wanted {
			permission, getErr := database.GetPermissionById(r.Context(), nil, permissionId)
			if getErr != nil {
				writeInternalServerError(w, r, errs.Wrap(getErr, "database error getting permission by ID for validation"), "permission_id", permissionId, "group_id", group.Id)
				return
			}
			if permission == nil {
				writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
		}

		grantKey := func(gp models.GroupPermission) int64 { return gp.PermissionId }
		grantId := func(gp models.GroupPermission) int64 { return gp.Id }

		// One transaction, as the user permission save: a failure part way through commits
		// nothing, overlapping saves merge item by item with no row lock (group_permissions has no
		// unique key, so a grant both add is stored twice and collapsed by the next save), and a
		// deadlock victim is rerun whole with the plan recomputed from the rows read on the
		// transaction (#301, #406, #428).
		//
		// The rows are read once, on the transaction, and deleted by the ids that read returned,
		// so neither of the two nil results #425 guarded is left to arrive: the second "get one"
		// lookup a revocation made, and the second GetPermissionById a grant made, are both gone.
		// A permission deleted after the validation above read it fails the insert's foreign key,
		// which undoes the whole save as one 500 (#406).
		var granted, revoked []int64
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			stored, loadErr := database.GetGroupPermissionsByGroupId(r.Context(), tx, group.Id)
			if loadErr != nil {
				return errs.Wrap(loadErr, "database error loading group permissions before update")
			}
			if !sameSet(stored, grantKey, request.ExpectedPermissionIds) {
				return errListChanged
			}

			insert, remove := replaceSet(stored, grantKey, grantId, wanted)
			for _, rowId := range remove {
				if deleteErr := database.DeleteGroupPermission(r.Context(), tx, rowId); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting group permission %d", rowId)
				}
			}
			for _, permissionId := range insert {
				if createErr := database.CreateGroupPermission(r.Context(), tx, &models.GroupPermission{
					GroupId:      group.Id,
					PermissionId: permissionId,
				}); createErr != nil {
					return errs.Wrapf(createErr, "database error granting permission %d", permissionId)
				}
			}
			granted, revoked = insert, revokedKeys(stored, grantKey, wanted)
			return nil
		})
		if err != nil {
			writeListSaveFailure(w, r, err, "group_id", group.Id)
			return
		}

		// Audit, once the save has committed: one event per grant made and per grant withdrawn,
		// from the plan of the attempt that committed (#428).
		for _, permissionId := range granted {
			auditLogger.Log(r.Context(), audit.AuditAddedGroupPermission, map[string]interface{}{
				"groupId":      group.Id,
				"permissionId": permissionId,
				"loggedInUser": callerSubject(r),
			})
		}
		for _, permissionId := range revoked {
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
