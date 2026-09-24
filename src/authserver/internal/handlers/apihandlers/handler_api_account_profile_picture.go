package apihandlers

import (
	"context"
	"database/sql"
	"io"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/imaging"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

// accountProfilePictureDatabase is what the account profile picture endpoints need: the caller's
// user row and the picture attached to it.
type accountProfilePictureDatabase interface {
	CreateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *models.UserProfilePicture) error
	DeleteUserProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) error
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	GetUserProfilePictureByUserId(ctx context.Context, tx *sql.Tx, userId int64) (*models.UserProfilePicture, error)
	UpdateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *models.UserProfilePicture) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)
}

// HandleAPIAccountProfilePicturePost - POST /api/v1/account/profile-picture
func HandleAPIAccountProfilePicturePost(
	database accountProfilePictureDatabase,
	auditLogger AuditLogger,
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
		user, err := database.GetUserBySubject(r.Context(), nil, sub)
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
			writeInternalServerError(w, r, err)
			return
		}

		// Validate the image
		result := imaging.ValidateProfilePicture(pictureData, maxFileSize)
		if !result.Valid {
			writeJSONError(w, result.Error, "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if user already has a profile picture
		existingPicture, err := database.GetUserProfilePictureByUserId(r.Context(), nil, user.Id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if existingPicture != nil {
			// Update existing picture
			existingPicture.Picture = pictureData
			existingPicture.ContentType = result.ContentType
			err = database.UpdateUserProfilePicture(r.Context(), nil, existingPicture)
		} else {
			// Create new picture
			profilePicture := &models.UserProfilePicture{
				UserId:      user.Id,
				Picture:     pictureData,
				ContentType: result.ContentType,
			}
			err = database.CreateUserProfilePicture(r.Context(), nil, profilePicture)
		}

		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditUpdatedOwnProfilePicture, map[string]interface{}{
			"userId": user.Id,
		})

		// Return success response
		response := map[string]interface{}{
			"success":    true,
			"pictureUrl": config.GetAuthServer().BaseURL + "/userinfo/picture/" + user.Subject,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIAccountProfilePictureDelete - DELETE /api/v1/account/profile-picture
func HandleAPIAccountProfilePictureDelete(
	database accountProfilePictureDatabase,
	auditLogger AuditLogger,
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
		user, err := database.GetUserBySubject(r.Context(), nil, sub)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "failed to get user"))
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the profile picture
		err = database.DeleteUserProfilePicture(r.Context(), nil, user.Id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditDeletedOwnProfilePicture, map[string]interface{}{
			"userId": user.Id,
		})

		// Return success response
		response := map[string]interface{}{
			"success": true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIAccountProfilePictureGet - GET /api/v1/account/profile-picture
func HandleAPIAccountProfilePictureGet(
	database accountProfilePictureDatabase,
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
		user, err := database.GetUserBySubject(r.Context(), nil, sub)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user has profile picture
		hasPicture, err := database.UserHasProfilePicture(r.Context(), nil, user.Id)
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
