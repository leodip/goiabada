package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
)

// HandleAPIUserEmailVerificationCodePost - POST /api/v1/admin/users/{id}/email/verification-code
func HandleAPIUserEmailVerificationCodePost(
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "USER_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_USER_ID", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		verificationCode := strings.ToUpper(stringutil.GenerateRandomLetterString(3)) + stringutil.GenerateRandomNumberString(3)
		encrypted, err := encryption.EncryptText(verificationCode, settings.AESEncryptionKey)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		issuedAt := time.Now().UTC()
		user.EmailVerified = false
		user.EmailVerificationCodeEncrypted = encrypted
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: issuedAt, Valid: true}
		if err := database.UpdateUser(nil, user); err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		auditLogger.Log(constants.AuditGeneratedEmailVerificationCode, map[string]interface{}{
			"userId":       user.Id,
			"email":        user.Email,
			"loggedInUser": loggedInUser,
		})

		expiresAt := issuedAt.Add(5 * time.Minute)
		response := api.GenerateUserEmailVerificationCodeResponse{
			VerificationCode:          verificationCode,
			VerificationCodeExpiresAt: &expiresAt,
			UserId:                    user.Id,
			Email:                     user.Email,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}
