package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// permissionUsersDatabase is what the permission holders endpoint needs: the permission, and one
// page of the users holding it.
type permissionUsersDatabase interface {
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*record.Permission, error)
	GetUsersByPermissionIdPaginated(ctx context.Context, tx *sql.Tx, permissionId int64, page int, pageSize int) ([]record.User, int, error)
}

// HandlePermissionUsersGet
// GET /api/v1/admin/permissions/{permissionId}/users?page={page}&size={size}
// Returns paginated users who have the specified permission.
func HandlePermissionUsersGet(
	database permissionUsersDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		permStr := chi.URLParam(r, "permissionId")
		if permStr == "" {
			writeJSONError(w, "Permission ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		permissionId, err := strconv.ParseInt(permStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid permission ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		perm, err := database.GetPermissionById(r.Context(), nil, permissionId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "error getting permission by ID for users listing"), "permission_id", permissionId)
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

		users, total, err := database.GetUsersByPermissionIdPaginated(r.Context(), nil, permissionId, page, size)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "error getting users by permission paginated"), "permission_id", permissionId, "page", page, "size", size)
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
