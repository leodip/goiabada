package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/imageupload"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// clientLogoDatabase is what the client logo endpoints need: the client and the logo row they
// read, write and delete.
type clientLogoDatabase interface {
	ClientHasLogo(ctx context.Context, tx *sql.Tx, clientId int64) (bool, error)
	CreateClientLogo(ctx context.Context, tx *sql.Tx, clientLogo *models.ClientLogo) error
	DeleteClientLogo(ctx context.Context, tx *sql.Tx, clientId int64) error
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*models.Client, error)
	GetClientLogoByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (*models.ClientLogo, error)
	UpdateClientLogo(ctx context.Context, tx *sql.Tx, clientLogo *models.ClientLogo) error
}

// HandleAPIClientLogoPost - POST /api/v1/admin/clients/{id}/logo
func HandleAPIClientLogoPost(
	database clientLogoDatabase,
	auditLogger AuditLogger,
	baseURL string,
	maxUploadBytes int64,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse client ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		clientId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get client from database
		client, err := database.GetClientById(r.Context(), nil, clientId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		fileData, ok := readUploadedImage(w, r, maxUploadBytes)
		if !ok {
			return
		}

		result, err := imageupload.Validate(fileData, maxUploadBytes)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Check if client already has a logo
		existingLogo, err := database.GetClientLogoByClientId(r.Context(), nil, clientId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if existingLogo != nil {
			// Update existing logo
			existingLogo.Logo = fileData
			existingLogo.ContentType = result.ContentType
			err = database.UpdateClientLogo(r.Context(), nil, existingLogo)
		} else {
			// Create new logo
			clientLogo := &models.ClientLogo{
				ClientId:    clientId,
				Logo:        fileData,
				ContentType: result.ContentType,
			}
			err = database.CreateClientLogo(r.Context(), nil, clientLogo)
		}

		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.EventUpdatedClientLogo, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": loggedInUser,
		})

		response := api.ClientLogoUploadResponse{
			Success:    true,
			PictureUrl: baseURL + "/client/logo/" + client.ClientIdentifier,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIClientLogoDelete - DELETE /api/v1/admin/clients/{id}/logo
func HandleAPIClientLogoDelete(
	database clientLogoDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse client ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		clientId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get client from database
		client, err := database.GetClientById(r.Context(), nil, clientId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the logo
		err = database.DeleteClientLogo(r.Context(), nil, clientId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.EventDeletedClientLogo, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": loggedInUser,
		})

		response := api.SuccessResponse{Success: true}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIClientLogoGet - GET /api/v1/admin/clients/{id}/logo
func HandleAPIClientLogoGet(
	database clientLogoDatabase,
	baseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse client ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		clientId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get client from database
		client, err := database.GetClientById(r.Context(), nil, clientId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if client has a logo
		hasLogo, err := database.ClientHasLogo(r.Context(), nil, clientId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		response := api.ClientLogoInfoResponse{HasLogo: hasLogo}
		if hasLogo {
			response.LogoUrl = baseURL + "/client/logo/" + client.ClientIdentifier
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
