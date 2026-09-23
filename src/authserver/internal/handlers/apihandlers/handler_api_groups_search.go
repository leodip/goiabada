package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// groupsSearchDatabase is what the group search endpoint needs: one page of groups and the
// permissions they carry.
type groupsSearchDatabase interface {
	GetAllGroupsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int) ([]models.Group, int, error)
	GetGroupPermissionsByGroupIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]models.GroupPermission, error)
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*models.Permission, error)
}

// HandleAPIGroupsSearchGet
// GET /api/v1/admin/groups/search?annotatePermissionId={permissionId}&page={page}&size={size}
// Returns paginated groups annotated with whether they have the specified permission.
func HandleAPIGroupsSearchGet(
	database groupsSearchDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse and validate annotatePermissionId
		permStr := r.URL.Query().Get("annotatePermissionId")
		if permStr == "" {
			writeJSONError(w, "annotatePermissionId is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		permId, err := strconv.ParseInt(permStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid annotatePermissionId", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Ensure permission exists
		perm, err := database.GetPermissionById(r.Context(), nil, permId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting permission by ID for annotation"), "permission_id", permId)
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

		// Fetch groups with server-side pagination
		groups, total, err := database.GetAllGroupsPaginated(r.Context(), nil, page, size)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting groups paginated"), "page", page, "size", size)
			return
		}

		annotated := make([]api.GroupWithPermissionResponse, 0, len(groups))

		if len(groups) > 0 {
			// Build list of group IDs
			groupIds := make([]int64, len(groups))
			for i := range groups {
				groupIds[i] = groups[i].Id
			}

			// Load permissions for all groups in batch
			gp, err := database.GetGroupPermissionsByGroupIds(r.Context(), nil, groupIds)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error getting group permissions by group IDs"), "group_count", len(groupIds))
				return
			}

			// Map groupId -> has permId
			hasPerm := make(map[int64]bool, len(groupIds))
			for _, g := range gp {
				if g.PermissionId == permId {
					hasPerm[g.GroupId] = true
				}
			}

			// Build annotated responses (MemberCount omitted as not needed here)
			for i := range groups {
				gr := apimapping.ToGroupResponse(&groups[i], 0)
				if gr == nil {
					continue
				}
				annotated = append(annotated, api.GroupWithPermissionResponse{
					GroupResponse: *gr,
					HasPermission: hasPerm[groups[i].Id],
				})
			}
		}

		resp := api.SearchGroupsWithPermissionAnnotationResponse{
			Groups: annotated,
			Total:  total,
			Page:   page,
			Size:   size,
		}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
