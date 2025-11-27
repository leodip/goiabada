package apihandlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/imaging"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

// HandleAPIAccountProfilePicturePost - POST /api/v1/account/profile-picture
func HandleAPIAccountProfilePicturePost(
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			writeJSONError(w, "Unauthorized", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		sub := jwtToken.GetStringClaim("sub")
		if len(sub) == 0 {
			writeJSONError(w, "Invalid token", "INVALID_TOKEN", http.StatusUnauthorized)
			return
		}

		// Get user from database
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
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
		pictureData, err := io.ReadAll(file)
		if err != nil {
			writeJSONError(w, "Failed to read file", "READ_ERROR", http.StatusInternalServerError)
			return
		}

		// Validate the image
		result := imaging.ValidateProfilePicture(pictureData, maxFileSize)
		if !result.Valid {
			writeJSONError(w, result.Error, "INVALID_IMAGE", http.StatusBadRequest)
			return
		}

		// Check if user already has a profile picture
		existingPicture, err := database.GetUserProfilePictureByUserId(nil, user.Id)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if existingPicture != nil {
			// Update existing picture
			existingPicture.Picture = pictureData
			existingPicture.ContentType = result.ContentType
			err = database.UpdateUserProfilePicture(nil, existingPicture)
		} else {
			// Create new picture
			profilePicture := &models.UserProfilePicture{
				UserId:      user.Id,
				Picture:     pictureData,
				ContentType: result.ContentType,
			}
			err = database.CreateUserProfilePicture(nil, profilePicture)
		}

		if err != nil {
			writeJSONError(w, "Failed to save profile picture", "SAVE_ERROR", http.StatusInternalServerError)
			return
		}

		// Log audit event
		auditLogger.Log(constants.AuditUpdatedOwnProfilePicture, map[string]interface{}{
			"userId": user.Id,
		})

		// Return success response
		response := map[string]interface{}{
			"success":    true,
			"pictureUrl": config.GetAuthServer().BaseURL + "/userinfo/picture/" + user.Subject.String(),
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

// HandleAPIAccountProfilePictureDelete - DELETE /api/v1/account/profile-picture
func HandleAPIAccountProfilePictureDelete(
	httpHelper handlers.HttpHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			writeJSONError(w, "Unauthorized", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		sub := jwtToken.GetStringClaim("sub")
		if len(sub) == 0 {
			writeJSONError(w, "Invalid token", "INVALID_TOKEN", http.StatusUnauthorized)
			return
		}

		// Get user from database
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.Wrap(err, "failed to get user"))
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the profile picture
		err = database.DeleteUserProfilePicture(nil, user.Id)
		if err != nil {
			writeJSONError(w, "Failed to delete profile picture", "DELETE_ERROR", http.StatusInternalServerError)
			return
		}

		// Log audit event
		auditLogger.Log(constants.AuditDeletedOwnProfilePicture, map[string]interface{}{
			"userId": user.Id,
		})

		// Return success response
		response := map[string]interface{}{
			"success": true,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

// HandleAPIAccountProfilePictureGet - GET /api/v1/account/profile-picture
func HandleAPIAccountProfilePictureGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			writeJSONError(w, "Unauthorized", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		sub := jwtToken.GetStringClaim("sub")
		if len(sub) == 0 {
			writeJSONError(w, "Invalid token", "INVALID_TOKEN", http.StatusUnauthorized)
			return
		}

		// Get user from database
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user has profile picture
		hasPicture, err := database.UserHasProfilePicture(nil, user.Id)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"hasPicture": hasPicture,
		}

		if hasPicture {
			response["pictureUrl"] = config.GetAuthServer().BaseURL + "/userinfo/picture/" + user.Subject.String()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}
