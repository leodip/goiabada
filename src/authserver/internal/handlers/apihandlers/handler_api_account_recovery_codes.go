package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// accountRecoveryCodesDatabase is what the account API's two recovery-code endpoints need: the
// caller's user row, the count of their unused codes, and the replacement of their set.
type accountRecoveryCodesDatabase interface {
	otpcredential.ReplaceRecoveryCodesDatabase

	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	CountUnusedUserRecoveryCodes(ctx context.Context, tx *sql.Tx, userId int64) (int, error)
}

// HandleAccountRecoveryCodesGet - GET /api/v1/account/otp/recovery-codes
//
// Answers how many of the caller's recovery codes are unused, never the codes, which no page shows
// again after their set was first shown (#257 decision 9). A user without an authenticator has no
// codes, since removing one deletes them, so the answer for them is 0.
func HandleAccountRecoveryCodesGet(database accountRecoveryCodesDatabase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		remaining, err := database.CountUnusedUserRecoveryCodes(r.Context(), nil, user.Id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		writeJSON(w, r, http.StatusOK, api.AccountRecoveryCodesResponse{Remaining: remaining})
	}
}

// HandleAccountRecoveryCodesPost - POST /api/v1/account/otp/recovery-codes
//
// Replaces the caller's set of recovery codes with a new one, given their password, and answers it:
// this response is the one time the new set is shown (#257 decision 8). The old codes stop working
// at once. No session ends and no generation moves, since the authenticator did not change.
//
// Mounted behind the account_password limiter, and a wrong password is the one refusal that spends
// it, as at the password, two-factor and email changes: the same password is guessed at all four,
// so separate budgets would hand an attacker more guesses by alternating.
func HandleAccountRecoveryCodesPost(
	database accountRecoveryCodesDatabase,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		var req api.CreateAccountRecoveryCodesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// A blank password compares nothing, so it is refused without spending the budget (#219).
		if strings.TrimSpace(req.Password) == "" {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountPasswordIncorrect, nil), "AUTHENTICATION_FAILED", http.StatusBadRequest)
			return
		}
		if !passwordhash.Verify(user.PasswordHash, req.Password) {
			credentialFailures.RecordCredentialFailure(r)
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountPasswordIncorrect, nil), "AUTHENTICATION_FAILED", http.StatusBadRequest)
			return
		}

		notEnabled := i18n.NewLocalizedError(i18n.ErrCodeUserOTPNotEnabled, nil)
		if !user.OTPEnabled {
			writeLocalizedError(w, r, notEnabled, "OTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		codes, replaced, err := otpcredential.ReplaceRecoveryCodes(r.Context(), database, user)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if !replaced {
			// The authenticator was removed after the read above, from another tab or client:
			// the answer a request arriving a moment later would have got, and nothing stored.
			writeLocalizedError(w, r, notEnabled, "OTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		// After the commit, naming nothing of the codes (#257 decision 10).
		auditLogger.Log(r.Context(), audit.EventRecoveryCodesCreated, map[string]interface{}{
			"user_id":        user.Id,
			"logged_in_user": subject,
		})

		writeJSON(w, r, http.StatusOK, api.CreateAccountRecoveryCodesResponse{RecoveryCodes: codes})
	}
}
