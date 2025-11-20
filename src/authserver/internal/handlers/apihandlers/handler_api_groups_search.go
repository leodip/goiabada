package apihandlers

import (
    "encoding/json"
    "log/slog"
    "net/http"
    "strconv"

    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/data"
)

// HandleAPIGroupsSearchGet
// GET /api/v1/admin/groups/search?annotatePermissionId={permissionId}&page={page}&size={size}
// Returns paginated groups annotated with whether they have the specified permission.
func HandleAPIGroupsSearchGet(
    database data.Database,
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
        perm, err := database.GetPermissionById(nil, permId)
        if err != nil {
            slog.Error("AuthServer API: Database error getting permission by ID for annotation", "error", err, "permissionId", permId)
            writeJSONError(w, "Failed to validate permission", "INTERNAL_ERROR", http.StatusInternalServerError)
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
            if p, err := strconv.Atoi(v); err == nil && p > 0 {
                page = p
            }
        }
        if v := r.URL.Query().Get("size"); v != "" {
            if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
                size = s
            }
        }

        // Fetch groups with server-side pagination
        groups, total, err := database.GetAllGroupsPaginated(nil, page, size)
        if err != nil {
            slog.Error("AuthServer API: Database error getting groups paginated", "error", err, "page", page, "size", size)
            writeJSONError(w, "Failed to get groups", "INTERNAL_ERROR", http.StatusInternalServerError)
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
            gp, err := database.GetGroupPermissionsByGroupIds(nil, groupIds)
            if err != nil {
                slog.Error("AuthServer API: Database error getting group permissions by group IDs", "error", err, "groupCount", len(groupIds))
                writeJSONError(w, "Failed to load group permissions", "INTERNAL_ERROR", http.StatusInternalServerError)
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
                gr := api.ToGroupResponse(&groups[i], 0)
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
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(resp)
    }
}

