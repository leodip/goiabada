package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// permissionUsersDatabase is what the permission holders endpoint needs: the permission, and one
// page of the users holding it.
type permissionUsersDatabase interface {
	GetPermissionByID(ctx context.Context, tx *sql.Tx, permissionID int64) (*record.Permission, error)
	GetUsersByPermissionIDPaginated(ctx context.Context, tx *sql.Tx, permissionID int64, page int, pageSize int) ([]record.User, int, error)
}

// HandlePermissionUsersGet
// GET /api/v1/admin/permissions/{permissionId}/users?page={page}&size={size}
// Returns paginated users who have the specified permission.
func HandlePermissionUsersGet(
	database permissionUsersDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		permStr := r.PathValue("permissionId")
		if permStr == "" {
			writeJSONError(w, "Permission ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		permissionID, err := strconv.ParseInt(permStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid permission ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		perm, err := database.GetPermissionByID(r.Context(), nil, permissionID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "error getting permission by ID for users listing"), "permission_id", permissionID)
			return
		}
		if perm == nil {
			writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Pagination params
		page := 1
		size := 10
		if v := r.URL.Query().Get("page"); v != "" {
			if p, parseErr := strconv.Atoi(v); parseErr == nil && p > 0 {
				page = p
			}
		}
		if v := r.URL.Query().Get("size"); v != "" {
			if s, parseErr := strconv.Atoi(v); parseErr == nil && s > 0 && s <= 200 {
				size = s
			}
		}

		users, total, err := database.GetUsersByPermissionIDPaginated(r.Context(), nil, permissionID, page, size)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "error getting users by permission paginated"), "permission_id", permissionID, "page", page, "size", size)
			return
		}

		resp := api.GetUsersByPermissionResponse{
			Users: apimapping.ToUserResponses(users),
			Total: total,
			Page:  page,
			Size:  size,
		}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
