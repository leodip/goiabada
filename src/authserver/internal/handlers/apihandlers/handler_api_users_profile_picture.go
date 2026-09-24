package apihandlers

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/imaging"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// usersProfilePictureDatabase is what the administrator's user picture endpoints need: the user
// row and the picture attached to it.
type usersProfilePictureDatabase interface {
	CreateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *models.UserProfilePicture) error
	DeleteUserProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) error
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUserProfilePictureByUserId(ctx context.Context, tx *sql.Tx, userId int64) (*models.UserProfilePicture, error)
	UpdateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *models.UserProfilePicture) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)
}

// HandleAPIUserProfilePicturePost - POST /api/v1/admin/users/{id}/profile-picture
func HandleAPIUserProfilePicturePost(
	database usersProfilePictureDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse user ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get max file size from config
		maxFileSize := imaging.MaxFileSize(config.GetAuthServer().ProfilePictureMaxSizeBytes)

		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, maxFileSize+1024) // extra for multipart overhead

		// Parse multipart form
		//nolint:gosec // G120: bounded by the MaxBytesReader above and the server's request-body table; G120 flags every multipart parse
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
		data, err := io.ReadAll(file)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Validate the image
		result := imaging.ValidateProfilePicture(data, maxFileSize)
		if !result.Valid {
			writeJSONError(w, result.Error, "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if user already has a profile picture
		existingPicture, err := database.GetUserProfilePictureByUserId(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if existingPicture != nil {
			// Update existing picture
			existingPicture.Picture = data
			existingPicture.ContentType = result.ContentType
			err = database.UpdateUserProfilePicture(r.Context(), nil, existingPicture)
		} else {
			// Create new picture
			profilePicture := &models.UserProfilePicture{
				UserId:      userId,
				Picture:     data,
				ContentType: result.ContentType,
			}
			err = database.CreateUserProfilePicture(r.Context(), nil, profilePicture)
		}

		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditUpdatedUserProfilePicture, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		// Return success response
		response := map[string]interface{}{
			"success":    true,
			"pictureUrl": config.GetAuthServer().BaseURL + "/userinfo/picture/" + user.Subject,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIUserProfilePictureDelete - DELETE /api/v1/admin/users/{id}/profile-picture
func HandleAPIUserProfilePictureDelete(
	database usersProfilePictureDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse user ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the profile picture
		err = database.DeleteUserProfilePicture(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditDeletedUserProfilePicture, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		// Return success response
		response := map[string]interface{}{
			"success": true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIUserProfilePictureGet - GET /api/v1/admin/users/{id}/profile-picture (check if exists)
func HandleAPIUserProfilePictureGet(
	database usersProfilePictureDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse user ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user has profile picture
		hasPicture, err := database.UserHasProfilePicture(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		response := map[string]interface{}{
			"hasPicture": hasPicture,
		}

		if hasPicture {
			response["pictureUrl"] = config.GetAuthServer().BaseURL + "/userinfo/picture/" + user.Subject
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
