package apihandlers

import (
    "encoding/json"
    "log/slog"
    "net/http"
    "strconv"

    "github.com/go-chi/chi/v5"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/handlerhelpers"
)

// HandleAPIPermissionUsersGet
// GET /api/v1/admin/permissions/{permissionId}/users?page={page}&size={size}
// Returns paginated users who have the specified permission.
func HandleAPIPermissionUsersGet(
    httpHelper *handlerhelpers.HttpHelper,
    database data.Database,
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

        // Validate permission exists and enforce special rules
        perm, err := database.GetPermissionById(nil, permissionId)
        if err != nil {
            slog.Error("AuthServer API: error getting permission by ID for users listing", "error", err, "permissionId", permissionId)
            writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if perm == nil {
            writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        // Load its resource to check for authserver:userinfo special case
        resource, err := database.GetResourceById(nil, perm.ResourceId)
        if err != nil {
            slog.Error("AuthServer API: error getting resource for permission users listing", "error", err, "permissionId", permissionId)
            writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if resource != nil && resource.ResourceIdentifier == constants.AuthServerResourceIdentifier && perm.PermissionIdentifier == constants.UserinfoPermissionIdentifier {
            writeJSONError(w, "Operation not allowed for userinfo permission", "VALIDATION_ERROR", http.StatusBadRequest)
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

        users, total, err := database.GetUsersByPermissionIdPaginated(nil, permissionId, page, size)
        if err != nil {
            slog.Error("AuthServer API: error getting users by permission paginated", "error", err, "permissionId", permissionId, "page", page, "size", size)
            writeJSONError(w, "Failed to list users", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        resp := api.GetUsersByPermissionResponse{
            Users: api.ToUserResponses(users),
            Total: total,
            Page:  page,
            Size:  size,
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(resp)
    }
}

