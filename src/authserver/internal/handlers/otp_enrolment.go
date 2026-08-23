package handlers

import (
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

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
// apihandlers, which is why TerminateUserSessionTx sits in this package too.
//
// The browser caller needs the returned value: it captured the pre-enrollment generation at
// /auth/level2, and promoting that at /auth/completed would leave a session that just
// enrolled and verified owing another second-factor prompt at once.
func EnableUserOTPTx(database data.Database, user *models.User) (int64, error) {
	tx, err := database.BeginTransaction()
	if err != nil {
		return 0, err
	}
	defer database.RollbackTransaction(tx) //nolint:errcheck

	if err := database.UpdateUser(tx, user); err != nil {
		return 0, err
	}
	generation, err := database.IncrementUserOtpConfigGeneration(tx, user.Id)
	if err != nil {
		return 0, err
	}
	if err := database.CommitTransaction(tx); err != nil {
		return 0, err
	}
	return generation, nil
}
