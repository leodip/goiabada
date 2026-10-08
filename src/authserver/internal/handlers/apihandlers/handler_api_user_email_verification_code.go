package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// userEmailVerificationCodeDatabase is what the user email verification code endpoint needs: the
// user row, and the conditional write that stamps the code on it.
// It embeds what the administrative policy reads to judge whether the user is an administrator.
type userEmailVerificationCodeDatabase interface {
	userTargetPolicyDatabase
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	TryIssueEmailVerificationCode(ctx context.Context, tx *sql.Tx, userId int64, email string, codeEncrypted []byte,
		issuedAt time.Time) (bool, error)
}

// HandleUserEmailVerificationCodePost - POST /api/v1/admin/users/{id}/email/verification-code
func HandleUserEmailVerificationCodePost(
	database userEmailVerificationCodeDatabase,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Only authserver:manage writes to an administrator (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		verificationCode := generateEmailVerificationCode()
		encrypted, err := dataCipher.Encrypt(verificationCode)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// The response and the audit record name the address the code was issued for, so the code is
		// stored only while the account still holds the address read above. Writing back the row as
		// read also undid a disable, a password change or an OTP change made in between (#471).
		issuedAt := time.Now().UTC()
		stored, err := database.TryIssueEmailVerificationCode(r.Context(), nil, user.Id, user.Email, encrypted, issuedAt)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if !stored {
			writeJSONError(w, "The account was changed by another request while the code was being sent. Nothing was sent: try again.", "CONCURRENT_UPDATE", http.StatusConflict)
			return
		}

		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		auditLogger.Log(r.Context(), audit.EventGeneratedEmailVerificationCode, map[string]interface{}{
			"user_id":        user.Id,
			"email":          user.Email,
			"logged_in_user": loggedInUser,
		})

		expiresAt := issuedAt.Add(emailVerificationCodeLifetime)
		response := api.GenerateUserEmailVerificationCodeResponse{
			VerificationCode:          verificationCode,
			VerificationCodeExpiresAt: &expiresAt,
			UserId:                    user.Id,
			Email:                     user.Email,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
