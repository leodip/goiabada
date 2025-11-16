package apihandlers

import (
    "encoding/json"
    "log/slog"
    "net/http"
    "strconv"

    "github.com/go-chi/chi/v5"
    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/models"
)

// HandleAPIClientPermissionsGet - GET /api/v1/admin/clients/{id}/permissions
func HandleAPIClientPermissionsGet(
    database data.Database,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        idStr := chi.URLParam(r, "id")
        if len(idStr) == 0 {
            writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        id, err := strconv.ParseInt(idStr, 10, 64)
        if err != nil {
            writeJSONError(w, "Invalid client ID format", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        client, err := database.GetClientById(nil, id)
        if err != nil {
            slog.Error("AuthServer API: Database error getting client by ID for permissions", "error", err, "clientId", id)
            writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if err := database.ClientLoadPermissions(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client permissions", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client permissions", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        if client.Permissions != nil {
            if err := database.PermissionsLoadResources(nil, client.Permissions); err != nil {
                slog.Error("AuthServer API: Database error loading permission resources", "error", err, "clientId", client.Id)
                writeJSONError(w, "Failed to load client permissions", "INTERNAL_ERROR", http.StatusInternalServerError)
                return
            }
        }

        resp := api.GetClientPermissionsResponse{
            Client:      *api.ToClientResponse(client),
            Permissions: api.ToPermissionResponses(client.Permissions),
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(resp)
    }
}

// HandleAPIClientPermissionsPut - PUT /api/v1/admin/clients/{id}/permissions
// Replaces the full set of permissions assigned to a client. Validation,
// security, and audit logging are done here to support non-admin-console clients.
func HandleAPIClientPermissionsPut(
    database data.Database,
    authHelper handlers.AuthHelper,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        idStr := chi.URLParam(r, "id")
        if len(idStr) == 0 {
            writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        id, err := strconv.ParseInt(idStr, 10, 64)
        if err != nil {
            writeJSONError(w, "Invalid client ID format", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        client, err := database.GetClientById(nil, id)
        if err != nil {
            slog.Error("AuthServer API: Database error getting client by ID for permissions update", "error", err, "clientId", id)
            writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if client.IsSystemLevelClient() {
            writeJSONError(w, "Trying to edit a system level client", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var request api.UpdateClientPermissionsRequest
        if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
            writeJSONError(w, "Invalid request body", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Deduplicate permission IDs
        uniquePermissionIds := make([]int64, 0)
        seen := make(map[int64]bool)
        for _, pid := range request.PermissionIds {
            if !seen[pid] {
                uniquePermissionIds = append(uniquePermissionIds, pid)
                seen[pid] = true
            }
        }
        request.PermissionIds = uniquePermissionIds

        // Enforce that client credentials flow must be enabled
        if !client.ClientCredentialsEnabled {
            writeJSONError(w, "Client permissions can only be configured when client credentials flow is enabled", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Load current permissions
        if err := database.ClientLoadPermissions(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading current client permissions", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load current permissions", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Validate that all requested permissions exist
        for _, permissionId := range request.PermissionIds {
            permission, err := database.GetPermissionById(nil, permissionId)
            if err != nil {
                slog.Error("AuthServer API: Database error getting permission by ID for validation", "error", err, "permissionId", permissionId, "clientId", client.Id)
                writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
                return
            }
            if permission == nil {
                writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
                return
            }
        }

        // Add new permissions
        for _, permissionId := range request.PermissionIds {
            found := false
            for _, permission := range client.Permissions {
                if permission.Id == permissionId {
                    found = true
                    break
                }
            }
            if !found {
                permission, err := database.GetPermissionById(nil, permissionId)
                if err != nil {
                    slog.Error("AuthServer API: Database error retrieving permission for client assignment", "error", err, "permissionId", permissionId, "clientId", client.Id)
                    writeJSONError(w, "Failed to retrieve permission", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }

                if err := database.CreateClientPermission(nil, &models.ClientPermission{
                    ClientId:     client.Id,
                    PermissionId: permission.Id,
                }); err != nil {
                    slog.Error("AuthServer API: Database error creating client permission", "error", err, "clientId", client.Id, "permissionId", permission.Id)
                    writeJSONError(w, "Failed to create client permission", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }
            }
        }

        // Remove permissions not in request
        toDelete := []int64{}
        for _, permission := range client.Permissions {
            keep := false
            for _, pid := range request.PermissionIds {
                if permission.Id == pid {
                    keep = true
                    break
                }
            }
            if !keep {
                toDelete = append(toDelete, permission.Id)
            }
        }

        for _, permissionId := range toDelete {
            clientPermission, err := database.GetClientPermissionByClientIdAndPermissionId(nil, client.Id, permissionId)
            if err != nil {
                slog.Error("AuthServer API: Database error getting client permission for deletion", "error", err, "clientId", client.Id, "permissionId", permissionId)
                writeJSONError(w, "Failed to find client permission", "INTERNAL_ERROR", http.StatusInternalServerError)
                return
            }
            if clientPermission == nil {
                writeJSONError(w, "Client permission not found", "NOT_FOUND", http.StatusNotFound)
                return
            }

            if err := database.DeleteClientPermission(nil, clientPermission.Id); err != nil {
                slog.Error("AuthServer API: Database error deleting client permission", "error", err, "clientPermissionId", clientPermission.Id, "clientId", client.Id, "permissionId", permissionId)
                writeJSONError(w, "Failed to delete client permission", "INTERNAL_ERROR", http.StatusInternalServerError)
                return
            }
        }

        // Audit consolidated update
        auditLogger.Log(constants.AuditUpdatedClientPermissions, map[string]interface{}{
            "clientId":     client.Id,
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        // Respond success
        resp := api.SuccessResponse{Success: true}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(resp)
    }
}
