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
	GetClientPermissionsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]models.ClientPermission, error)
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*models.Permission, error)
	PermissionsLoadResources(ctx context.Context, tx *sql.Tx, permissions []models.Permission) error
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
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
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for permissions"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if err := database.ClientLoadPermissions(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client permissions"), "client_id", client.Id)
			return
		}

		if client.Permissions != nil {
			if err := database.PermissionsLoadResources(r.Context(), nil, client.Permissions); err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error loading permission resources"), "client_id", client.Id)
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
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for permissions update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var request api.UpdateClientPermissionsRequest
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

		wanted := firstOccurrences(request.PermissionIds)

		// Enforce that client credentials flow must be enabled
		if !client.ClientCredentialsEnabled {
			writeJSONError(w, "Client permissions can only be configured when client credentials flow is enabled", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate that all requested permissions exist
		for _, permissionId := range wanted {
			permission, getErr := database.GetPermissionById(r.Context(), nil, permissionId)
			if getErr != nil {
				writeInternalServerError(w, r, errs.Wrap(getErr, "database error getting permission by ID for validation"), "permission_id", permissionId, "client_id", client.Id)
				return
			}
			if permission == nil {
				writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
		}

		grantKey := func(cp models.ClientPermission) int64 { return cp.PermissionId }
		grantId := func(cp models.ClientPermission) int64 { return cp.Id }

		// One transaction, so a failure part way through commits nothing and the 500 is true, where
		// the autocommitted writes this replaced could leave a grant made or a revocation done under
		// a 500 (#406). No row lock, as for every list save: two overlapping saves of one client's
		// grants merge item by item, and client_permissions has no unique key, so a grant the two
		// both add is stored twice, which is harmless and collapsed by the next save's replaceSet.
		// Opened through RunInTransaction, so a deadlock victim is rerun whole (#301). The body is
		// safe to rerun: the plan is recomputed from the rows read on the transaction on every
		// attempt, and nothing is written to the response inside it (#428).
		//
		// A permission deleted after the validation above read it fails the insert's foreign key,
		// which undoes the whole save as one 500; the second lookup the add loop made went with the
		// loop, and so did the "get one, then delete it" lookup, whose nil answer this save
		// reported as a 404 after the grants before it were already written (#406).
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			stored, loadErr := database.GetClientPermissionsByClientId(r.Context(), tx, client.Id)
			if loadErr != nil {
				return errs.Wrap(loadErr, "database error loading client permissions before update")
			}
			if !sameSet(stored, grantKey, request.ExpectedPermissionIds) {
				return errListChanged
			}

			insert, remove := replaceSet(stored, grantKey, grantId, wanted)
			for _, rowId := range remove {
				if deleteErr := database.DeleteClientPermission(r.Context(), tx, rowId); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting client permission %d", rowId)
				}
			}
			for _, permissionId := range insert {
				if createErr := database.CreateClientPermission(r.Context(), tx, &models.ClientPermission{
					ClientId:     client.Id,
					PermissionId: permissionId,
				}); createErr != nil {
					return errs.Wrapf(createErr, "database error granting permission %d", permissionId)
				}
			}
			return nil
		})
		if err != nil {
			writeListSaveFailure(w, r, err, "client_id", client.Id)
			return
		}

		// Audit consolidated update, once the save has committed (#428).
		auditLogger.Log(r.Context(), audit.AuditUpdatedClientPermissions, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": callerSubject(r),
		})

		// Respond success
		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
