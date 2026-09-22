package handlers

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/models"
)

// OTPEnrolmentDatabase is what installing an authenticator needs: the user row, the generation
// counter, and the pending enrolment it clears, in one transaction.
//
// Exported, unlike most ports here, because EnableUserOTPTx is called from apihandlers, whose own
// port has to name this capability to hand it on (#386 decision 8).
type OTPEnrolmentDatabase interface {
	ClearPendingOTPEnrollment(ctx context.Context, tx *sql.Tx, userId int64) error
	IncrementUserOtpConfigGeneration(ctx context.Context, tx *sql.Tx, userId int64) (int64, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UpdateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
}

// EnableUserOTPTx establishes a user's authenticator: it writes the user, whose OTPEnabled
// and encrypted secret the caller has already set, and advances the OTP configuration
// generation, returning the value that landed.
//
// **The two writes commit together, and that is the point of this function**, exactly as
// for disableUserOTP in the apihandlers package and for the reason #242 decision 2 gives.
// A separate increment whose error is merely surfaced leaves the authenticator on with the
// counter unmoved, so every existing session's snapshot still matches and they keep
// asserting acr: urn:goiabada:level2_optional with amr: ["pwd"] for a user who now has an
// authenticator. The caller cannot recover from it either: a retry is refused with
// OTP_ALREADY_ENABLED and the only way out is to disable and enroll again. With the
// transaction the enrollment rolls back and the retry is clean.
//
// The TOTP code is spent either way, which is not new: #111 claims the time step before the
// enable write precisely so a failed enable cannot leave OTP switched on, so a rolled back
// transaction behaves exactly as a failed UpdateUser does today and the user types the next
// code.
//
// Shared by the two enable sites decision 2 names, HandleAuthOtpPost's enrollment branch
// and HandleAPIAccountOTPPut's enable branch. There is no third. It lives here rather than
// beside disableUserOTP because the browser handler cannot reach an unexported function in
// apihandlers. TerminateUserSessionTx used to sit in this package for the same reason and no
// longer does: #387 moved it to internal/revocation, which both callers reach, and this
// function follows it to internal/otpcredential.
//
// The browser caller needs the returned value: it captured the pre-enrollment generation at
// /auth/level2, and promoting that at /auth/completed would leave a session that just
// enrolled and verified owing another second-factor prompt at once.
func EnableUserOTPTx(ctx context.Context, database OTPEnrolmentDatabase, user *models.User) (int64, error) {
	// Opened through RunInTransaction, so a deadlock reruns the three writes together (#301).
	// Safe to rerun: the user model was set by the caller before this opened and is written
	// unchanged on every attempt, and generation is the committing attempt's.
	var generation int64
	err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := database.UpdateUser(ctx, tx, user); err != nil {
			return err
		}
		var err error
		generation, err = database.IncrementUserOtpConfigGeneration(ctx, tx, user.Id)
		if err != nil {
			return err
		}
		// The pending enrollment this user may have staged is discarded in the same transaction that
		// establishes the authenticator, so no committed state has OTP enabled with a live seed still
		// installed. Its error is returned rather than surfaced and ignored, for decision 2's reason
		// above: a commit that leaves the pending seed alive leaves a credential the server issued
		// standing on an account that no longer needs one, waiting for the authenticator to be removed.
		//
		// Unconditional, so it also covers the browser ceremony, which never installs a pending
		// enrollment and whose clear is therefore a no-op. Putting it here rather than at the account
		// API's own enable branch is what makes "an enabled authenticator has no pending seed behind
		// it" a property of the transaction rather than of one caller (#247).
		if err := database.ClearPendingOTPEnrollment(ctx, tx, user.Id); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return generation, nil
}
