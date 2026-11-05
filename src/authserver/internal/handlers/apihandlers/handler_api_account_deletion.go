package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// accountDeletionDatabase is what POST /api/v1/account/deletion needs: the caller's row, what the
// last-administrator guard reads, the stored authenticator's verification, the recovery code's
// claim, and the deletion.
type accountDeletionDatabase interface {
	userRemovalDatabase
	otpcredential.Database

	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	TryUseUserRecoveryCode(ctx context.Context, tx *sql.Tx, userId int64, codeHash string) (bool, error)
	UserRecoveryCodeExists(ctx context.Context, tx *sql.Tx, userId int64, codeHash string) (bool, error)
	DeleteUser(ctx context.Context, tx *sql.Tx, userId int64) error
}

// The deletion's transaction returns these to say why it rolled back, so the response is written
// after it rather than inside a body a deadlock can run again.
var (
	// errRecoveryCodeRefused is a recovery code that the user's set does not hold unused.
	errRecoveryCodeRefused = errors.New("the recovery code is wrong or already used")
	// errSecondFactorNowRequired is two-factor authentication turned on after the request read the
	// account without it, so the request carried no second factor that was checked.
	errSecondFactorNowRequired = errors.New("two-factor authentication was turned on after the account was read")
	// errAccountGone is the account deleted by another request after this one read it.
	errAccountGone = errors.New("the account was deleted after it was read")
)

// HandleAccountDeletionPost - POST /api/v1/account/deletion
//
// Deletes the caller's own account, at once, given their password and, while two-factor
// authentication is on, an authenticator code or a recovery code (#783). Mounted behind
// RequireAdminConsoleClient, so only the admin console's own pages reach it, and behind the
// account_password limiter: a wrong password, a wrong authenticator code and a wrong recovery code
// each spend it, as the password guessed here is guessed on every route that checks it (decision 4).
//
// The refusals come in decision 3's order. The setting off is 403 ACCOUNT_DELETION_DISABLED, before
// the body is read. The last enabled user holding authserver:manage is 409 LAST_ADMINISTRATOR,
// checked before any credential, so that user spends no password attempt and no code, and again
// under the administrators' lock. Then the password, AUTHENTICATION_FAILED, and with two-factor on
// the second factor: none is OTP_CODE_REQUIRED, a wrong or replayed authenticator code
// INVALID_OTP_CODE, a code from the next step OTP_CLOCK_AHEAD, and a wrong or used recovery code
// INVALID_RECOVERY_CODE, the sign-in page's sentence for both (decision 2).
//
// The deletion is DeleteUser in a transaction whose first statement takes the administrators' lock,
// rolled back when it would leave no enabled user holding manage. A recovery code is claimed on that
// same transaction, so a deletion refused or rolled back spends none, and one that commits deletes it
// with the rest of the set. After the commit, deleted_own_account is written and the user is sent
// "Your account was deleted", addressed to their row as the deletion read it under the row's lock.
func HandleAccountDeletionPost(
	database accountDeletionDatabase,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
	dataCipher *encryption.DataCipher,
	notifier AccountNotifier,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		// The endpoint checks the setting itself on every request: the console reads it from its
		// cached public settings, which decide only what it shows (decision 6).
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.AccountDeletionEnabled {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountDeletionDisabled, nil),
				"ACCOUNT_DELETION_DISABLED", http.StatusForbidden)
			return
		}

		var req api.DeleteAccountRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		otpCode := strings.TrimSpace(req.OtpCode)
		recoveryCodeSent := !otpcredential.IsBlankRecoveryCode(req.RecoveryCode)
		// The shape of the request rather than a credential, so it is refused before anything is
		// read or checked, and spends nothing.
		if otpCode != "" && recoveryCodeSent {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountDeletionOneSecondFactor, nil),
				"VALIDATION_ERROR", http.StatusBadRequest)
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

		// Before any credential: only a holder of manage can meet this, so the early answer tells
		// them nothing they don't know, and it spares them a password attempt and a code (decision
		// 3). The deletion's transaction asks again under the lock, which is what decides.
		sole, err := soleAdministrator(r.Context(), database, user)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		// 409 LAST_ADMINISTRATOR, as every guarded write is answered, with a sentence of its own:
		// the one the other writes use is worded for an administrator acting on another user
		// (decision 9). The deletion's transaction answers its own refusal the same way.
		lastAdministrator := i18n.NewLocalizedError(i18n.ErrCodeAccountDeletionLastAdministrator, nil)
		if sole {
			writeLocalizedError(w, r, lastAdministrator, "LAST_ADMINISTRATOR", http.StatusConflict)
			return
		}

		// A blank password compares nothing, so it is refused without spending the budget (#219).
		if strings.TrimSpace(req.Password) == "" {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountPasswordIncorrect, nil),
				"AUTHENTICATION_FAILED", http.StatusBadRequest)
			return
		}
		if !passwordhash.Verify(user.PasswordHash, req.Password) {
			credentialFailures.RecordCredentialFailure(r)
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountPasswordIncorrect, nil),
				"AUTHENTICATION_FAILED", http.StatusBadRequest)
			return
		}

		// The second factor while two-factor authentication is on. A recovery code is checked inside
		// the deletion's transaction below; an authenticator code is checked here, against the
		// stored authenticator, as at sign-in.
		useRecoveryCode := false
		if user.OTPEnabled {
			switch {
			case otpCode != "":
				if !verifyDeletionOTPCode(w, r, database, auditLogger, credentialFailures, dataCipher, notifier,
					user, subject, otpCode) {
					return
				}
			case recoveryCodeSent:
				useRecoveryCode = true
			default:
				writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountOTPCodeRequired, nil),
					"OTP_CODE_REQUIRED", http.StatusBadRequest)
				return
			}
		}

		codeHash := otpcredential.HashRecoveryCode(req.RecoveryCode)
		// Safe to rerun: current is the committing attempt's.
		var current *record.User
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			current = nil
			administrators, lockErr := lockAdministrators(r.Context(), database, tx)
			if lockErr != nil {
				return lockErr
			}
			locked, readErr := database.GetUserByIdForUpdate(r.Context(), tx, user.Id)
			if readErr != nil {
				return errs.Wrap(readErr, "unable to read the account under its lock")
			}
			if locked == nil {
				return errAccountGone
			}
			if locked.OTPEnabled && !user.OTPEnabled {
				return errSecondFactorNowRequired
			}
			if useRecoveryCode {
				used, claimErr := database.TryUseUserRecoveryCode(r.Context(), tx, user.Id, codeHash)
				if claimErr != nil {
					return errs.Wrap(claimErr, "unable to claim the recovery code")
				}
				if !used {
					return errRecoveryCodeRefused
				}
			}
			holdsManage, guardErr := administrators.userHoldsManage(r.Context(), database, user.Id)
			if guardErr != nil {
				return guardErr
			}
			if decideErr := administrators.decide(r.Context(), holdsManage); decideErr != nil {
				return decideErr
			}
			if deleteErr := database.DeleteUser(r.Context(), tx, user.Id); deleteErr != nil {
				return errs.Wrap(deleteErr, "unable to delete the account")
			}
			if leaveErr := administrators.leavesAnAdministrator(r.Context()); leaveErr != nil {
				return leaveErr
			}
			current = locked
			return nil
		})
		switch {
		case errors.Is(err, errLastAdministrator):
			writeLocalizedError(w, r, lastAdministrator, "LAST_ADMINISTRATOR", http.StatusConflict)
			return
		case errors.Is(err, errRecoveryCodeRefused):
			refuseDeletionRecoveryCode(w, r, database, auditLogger, credentialFailures, user.Id, subject, codeHash)
			return
		case errors.Is(err, errSecondFactorNowRequired):
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountOTPCodeRequired, nil),
				"OTP_CODE_REQUIRED", http.StatusBadRequest)
			return
		case errors.Is(err, errAccountGone):
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		case err != nil:
			writeInternalServerError(w, r, err)
			return
		}

		// The account is gone: from here every session it had has ended and its access tokens are
		// refused at the next call, since the user no longer resolves (decision 8). The notice is
		// captured now, from the row the deletion read, so the job needs nothing of the account.
		defer notifier.Send(r, accountnotice.AccountDeleted, accountnotice.To(current))

		auditLogger.Log(r.Context(), audit.EventDeletedOwnAccount, map[string]interface{}{
			"user_id":        user.Id,
			"logged_in_user": subject,
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}

// soleAdministrator reports whether deleting user would leave no enabled user holding
// authserver:manage: user holds it, directly or through a group, is enabled, and is the only enabled
// holder. It reads in a transaction of its own that writes nothing, under the administrators' lock
// the guard's reads are made under, and only the deletion's own transaction decides.
func soleAdministrator(ctx context.Context, database accountDeletionDatabase, user *record.User) (bool, error) {
	// Safe to rerun: sole is the committing attempt's.
	var sole bool
	err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		sole = false
		administrators, err := lockAdministrators(ctx, database, tx)
		if err != nil {
			return err
		}
		holdsManage, err := administrators.userHoldsManage(ctx, database, user.Id)
		if err != nil || !holdsManage || !user.Enabled {
			return err
		}
		holders, err := database.CountEnabledUsersHoldingPermission(ctx, tx, administrators.manageId)
		if err != nil {
			return errs.Wrap(err, "unable to count the administrators")
		}
		sole = holders == 1
		return nil
	})
	return sole, err
}

// verifyDeletionOTPCode checks code against the user's stored authenticator, claiming its step, and
// answers the refusal when it is not accepted, reporting whether the deletion may go on. A wrong or
// replayed code spends the budget and advances the authenticator's consecutive-failure count, as
// everywhere a stored authenticator's code is checked (NIST SP 800-63B section 3.2.2, #489); the
// refusal that disables the authenticator is audited and told, as at sign-in (#724 decision 7). A
// code from the next step is no guess, so it spends nothing (#142).
func verifyDeletionOTPCode(w http.ResponseWriter, r *http.Request, database accountDeletionDatabase,
	auditLogger AuditLogger, credentialFailures CredentialFailureRecorder, dataCipher *encryption.DataCipher,
	notifier AccountNotifier, user *record.User, subject string, code string) bool {

	verified, err := otpcredential.VerifyStored(r.Context(), database, dataCipher, user, code, time.Now().UTC())
	if err != nil {
		writeInternalServerError(w, r, err)
		return false
	}

	// A replayed code is answered as a wrong one, so the caller cannot tell them apart (#111).
	incorrectOtpCode := i18n.NewLocalizedError(i18n.ErrCodeOtpIncorrectCode, nil)
	switch verified.Outcome {
	case otpcredential.OutcomeMatched:
		return true
	case otpcredential.OutcomeReplayed:
		credentialFailures.RecordCredentialFailure(r)
		auditLogger.Log(r.Context(), audit.EventOTPCodeReplayDetected, map[string]interface{}{
			"user_id":        user.Id,
			"step":           verified.Step,
			"logged_in_user": subject,
		})
	case otpcredential.OutcomeClockAhead:
		auditLogger.Log(r.Context(), audit.EventAuthFailedOtp, map[string]interface{}{
			"user_id":        user.Id,
			"logged_in_user": subject,
			"reason":         audit.AuthFailedOtpClockAhead,
		})
		writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeOtpClockAhead, nil),
			"OTP_CLOCK_AHEAD", http.StatusBadRequest)
		return false
	default:
		credentialFailures.RecordCredentialFailure(r)
	}

	if verified.Disabled {
		auditLogger.Log(r.Context(), audit.EventOTPAuthenticatorDisabled, map[string]interface{}{
			"user_id":        user.Id,
			"logged_in_user": subject,
		})
		defer notifier.Send(r, accountnotice.OTPLockout, accountnotice.To(verified.Current))
	}
	writeLocalizedError(w, r, incorrectOtpCode, "INVALID_OTP_CODE", http.StatusBadRequest)
	return false
}

// refuseDeletionRecoveryCode answers a recovery code the deletion's transaction could not claim:
// the budget spent, a used code of the current set audited as a replay, and the sign-in page's one
// answer for a wrong code and a used one (#257 decisions 6 and 10). The transaction rolled back, so
// nothing was deleted and no code was spent.
func refuseDeletionRecoveryCode(w http.ResponseWriter, r *http.Request, database accountDeletionDatabase,
	auditLogger AuditLogger, credentialFailures CredentialFailureRecorder, userId int64, subject string, codeHash string) {

	exists, err := database.UserRecoveryCodeExists(r.Context(), nil, userId, codeHash)
	if err != nil {
		writeInternalServerError(w, r, err)
		return
	}
	credentialFailures.RecordCredentialFailure(r)
	if exists {
		auditLogger.Log(r.Context(), audit.EventRecoveryCodeReplayDetected, map[string]interface{}{
			"user_id":        userId,
			"logged_in_user": subject,
		})
	}
	writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeOtpIncorrectRecoveryCode, nil),
		"INVALID_RECOVERY_CODE", http.StatusBadRequest)
}
