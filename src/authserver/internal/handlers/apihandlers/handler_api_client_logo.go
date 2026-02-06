package apihandlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/imaging"
	"github.com/leodip/goiabada/core/models"
)

// HandleAPIClientLogoPost - POST /api/v1/admin/clients/{id}/logo
func HandleAPIClientLogoPost(
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse client ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Client ID is required", "CLIENT_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		clientId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "INVALID_CLIENT_ID", http.StatusBadRequest)
			return
		}

		// Get client from database
		client, err := database.GetClientById(nil, clientId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if client == nil {
			writeJSONError(w, "Client not found", "CLIENT_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get max file size from config
		maxFileSize := config.GetAuthServer().ProfilePictureMaxSizeBytes
		if maxFileSize <= 0 {
			maxFileSize = imaging.DefaultMaxFileSize
		}

		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, maxFileSize+1024) // extra for multipart overhead

		// Parse multipart form
		err = r.ParseMultipartForm(maxFileSize)
		if err != nil {
			writeJSONError(w, "File too large or invalid form data", "FILE_TOO_LARGE", http.StatusBadRequest)
			return
		}

		// Get the file from the form
		file, _, err := r.FormFile("picture")
		if err != nil {
			writeJSONError(w, "No picture file provided", "NO_FILE", http.StatusBadRequest)
			return
		}
		defer func() { _ = file.Close() }()

		// Read file data
		fileData, err := io.ReadAll(file)
		if err != nil {
			writeJSONError(w, "Failed to read file", "READ_ERROR", http.StatusInternalServerError)
			return
		}

		// Validate the image
		result := imaging.ValidateProfilePicture(fileData, maxFileSize)
		if !result.Valid {
			writeJSONError(w, result.Error, "INVALID_IMAGE", http.StatusBadRequest)
			return
		}

		// Check if client already has a logo
		existingLogo, err := database.GetClientLogoByClientId(nil, clientId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if existingLogo != nil {
			// Update existing logo
			existingLogo.Logo = fileData
			existingLogo.ContentType = result.ContentType
			err = database.UpdateClientLogo(nil, existingLogo)
		} else {
			// Create new logo
			clientLogo := &models.ClientLogo{
				ClientId:    clientId,
				Logo:        fileData,
				ContentType: result.ContentType,
			}
			err = database.CreateClientLogo(nil, clientLogo)
		}

		if err != nil {
			writeJSONError(w, "Failed to save client logo", "SAVE_ERROR", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditUpdatedClientLogo, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": loggedInUser,
		})

		// Return success response
		response := map[string]interface{}{
			"success":    true,
			"pictureUrl": config.GetAuthServer().BaseURL + "/client/logo/" + client.ClientIdentifier,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

// HandleAPIClientLogoDelete - DELETE /api/v1/admin/clients/{id}/logo
func HandleAPIClientLogoDelete(
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse client ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Client ID is required", "CLIENT_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		clientId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "INVALID_CLIENT_ID", http.StatusBadRequest)
			return
		}

		// Get client from database
		client, err := database.GetClientById(nil, clientId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if client == nil {
			writeJSONError(w, "Client not found", "CLIENT_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the logo
		err = database.DeleteClientLogo(nil, clientId)
		if err != nil {
			writeJSONError(w, "Failed to delete client logo", "DELETE_ERROR", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditDeletedClientLogo, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": loggedInUser,
		})

		// Return success response
		response := map[string]interface{}{
			"success": true,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

// HandleAPIClientLogoGet - GET /api/v1/admin/clients/{id}/logo
func HandleAPIClientLogoGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse client ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Client ID is required", "CLIENT_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		clientId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "INVALID_CLIENT_ID", http.StatusBadRequest)
			return
		}

		// Get client from database
		client, err := database.GetClientById(nil, clientId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if client == nil {
			writeJSONError(w, "Client not found", "CLIENT_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if client has a logo
		hasLogo, err := database.ClientHasLogo(nil, clientId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"hasLogo": hasLogo,
		}

		if hasLogo {
			response["logoUrl"] = config.GetAuthServer().BaseURL + "/client/logo/" + client.ClientIdentifier
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}
