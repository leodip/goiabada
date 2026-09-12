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
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting client by ID for permissions"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if err := database.ClientLoadPermissions(nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error loading client permissions"), "client_id", client.Id)
			return
		}

		if client.Permissions != nil {
			if err := database.PermissionsLoadResources(nil, client.Permissions); err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error loading permission resources"), "client_id", client.Id)
				return
			}
		}

		resp := api.GetClientPermissionsResponse{
			Client:      *api.ToClientResponse(client),
			Permissions: api.ToPermissionResponses(client.Permissions),
		}

		writeJSON(w, r, http.StatusOK, resp)
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
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting client by ID for permissions update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
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
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error loading current client permissions"), "client_id", client.Id)
			return
		}

		// Validate that all requested permissions exist
		for _, permissionId := range request.PermissionIds {
			permission, err := database.GetPermissionById(nil, permissionId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting permission by ID for validation"), "permission_id", permissionId, "client_id", client.Id)
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
					writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error retrieving permission for client assignment"), "permission_id", permissionId, "client_id", client.Id)
					return
				}

				if err := database.CreateClientPermission(nil, &models.ClientPermission{
					ClientId:     client.Id,
					PermissionId: permission.Id,
				}); err != nil {
					writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error creating client permission"), "client_id", client.Id, "permission_id", permission.Id)
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
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting client permission for deletion"), "client_id", client.Id, "permission_id", permissionId)
				return
			}
			if clientPermission == nil {
				writeJSONError(w, "Client permission not found", "NOT_FOUND", http.StatusNotFound)
				return
			}

			if err := database.DeleteClientPermission(nil, clientPermission.Id); err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error deleting client permission"), "client_permission_id", clientPermission.Id, "client_id", client.Id, "permission_id", permissionId)
				return
			}
		}

		// Audit consolidated update
		auditLogger.Log(r.Context(), constants.AuditUpdatedClientPermissions, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		// Respond success
		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
