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

// clientPermissionsDatabase is what the client permission endpoints need: the client's grants and
// the catalogue they are granted from.
type clientPermissionsDatabase interface {
	ClientLoadPermissions(ctx context.Context, tx *sql.Tx, client *models.Client) error
	CreateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *models.ClientPermission) error
	DeleteClientPermission(ctx context.Context, tx *sql.Tx, clientPermissionId int64) error
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*models.Client, error)
	GetClientPermissionByClientIdAndPermissionId(ctx context.Context, tx *sql.Tx, clientId, permissionId int64) (*models.ClientPermission, error)
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*models.Permission, error)
	PermissionsLoadResources(ctx context.Context, tx *sql.Tx, permissions []models.Permission) error
}

// HandleAPIClientPermissionsGet - GET /api/v1/admin/clients/{id}/permissions
func HandleAPIClientPermissionsGet(
	database clientPermissionsDatabase,
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

		client, err := database.GetClientById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting client by ID for permissions"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if err := database.ClientLoadPermissions(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error loading client permissions"), "client_id", client.Id)
			return
		}

		if client.Permissions != nil {
			if err := database.PermissionsLoadResources(r.Context(), nil, client.Permissions); err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error loading permission resources"), "client_id", client.Id)
				return
			}
		}

		resp := api.GetClientPermissionsResponse{
			Client:      *apimapping.ToClientResponse(client),
			Permissions: apimapping.ToPermissionResponses(client.Permissions),
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleAPIClientPermissionsPut - PUT /api/v1/admin/clients/{id}/permissions
// Replaces the full set of permissions assigned to a client. Validation,
// security, and audit logging are done here to support non-admin-console clients.
func HandleAPIClientPermissionsPut(
	database clientPermissionsDatabase,
	auditLogger AuditLogger,
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

		client, err := database.GetClientById(r.Context(), nil, id)
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
		if err := database.ClientLoadPermissions(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error loading current client permissions"), "client_id", client.Id)
			return
		}

		// Validate that all requested permissions exist
		for _, permissionId := range request.PermissionIds {
			permission, err := database.GetPermissionById(r.Context(), nil, permissionId)
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
				permission, err := database.GetPermissionById(r.Context(), nil, permissionId)
				if err != nil {
					writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error retrieving permission for client assignment"), "permission_id", permissionId, "client_id", client.Id)
					return
				}

				if err := database.CreateClientPermission(r.Context(), nil, &models.ClientPermission{
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
			clientPermission, err := database.GetClientPermissionByClientIdAndPermissionId(r.Context(), nil, client.Id, permissionId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting client permission for deletion"), "client_id", client.Id, "permission_id", permissionId)
				return
			}
			if clientPermission == nil {
				writeJSONError(w, "Client permission not found", "NOT_FOUND", http.StatusNotFound)
				return
			}

			if err := database.DeleteClientPermission(r.Context(), nil, clientPermission.Id); err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error deleting client permission"), "client_permission_id", clientPermission.Id, "client_id", client.Id, "permission_id", permissionId)
				return
			}
		}

		// Audit consolidated update
		auditLogger.Log(r.Context(), audit.AuditUpdatedClientPermissions, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": callerSubject(r),
		})

		// Respond success
		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
