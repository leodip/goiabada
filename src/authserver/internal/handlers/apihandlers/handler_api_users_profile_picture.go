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
	baseURL string,
	maxUploadBytes int64,
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

		data, ok := readUploadedImage(w, r, maxUploadBytes)
		if !ok {
			return
		}

		result, err := imageupload.Validate(data, maxUploadBytes)
		if err != nil {
			writeValidationError(w, r, err)
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
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditUpdatedUserProfilePicture, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		response := api.ProfilePictureUploadResponse{
			Success:    true,
			PictureUrl: baseURL + "/userinfo/picture/" + user.Subject,
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
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditDeletedUserProfilePicture, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		response := api.SuccessResponse{Success: true}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIUserProfilePictureGet - GET /api/v1/admin/users/{id}/profile-picture (check if exists)
func HandleAPIUserProfilePictureGet(
	database usersProfilePictureDatabase,
	baseURL string,
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

		response := api.ProfilePictureInfoResponse{HasPicture: hasPicture}
		if hasPicture {
			response.PictureUrl = baseURL + "/userinfo/picture/" + user.Subject
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
