// Package otpcredential owns the stored TOTP authenticator: establishing one, removing one,
// verifying a passcode against one, and the seed's encryption at rest. Four operations, the
// ones that are identical on every path a user can enrol or authenticate through -- the browser
// ceremony at /auth/otp, the account API at PUT /api/v1/account/otp, and the admin API at
// PUT /api/v1/admin/users/{id}/otp (#387 decision 4).
//
// It exists because two of those operations used to live in a handler package for no reason but
// reachability: EnableUserOTPTx sat in authserver/internal/handlers with a doc comment saying it
// was there because "the browser handler cannot reach an unexported function in apihandlers",
// where disableUserOTP was, and the seed's cipher sat on models.User, which is a persistence
// record. Nothing here takes an http.ResponseWriter, a *http.Request, template data or a status
// code, and nothing here imports a handler package.
//
// **The audit call stays at the caller**, as revocation requires of its own callers and for the
// same reason: the three verification sites raise deliberately different event sets. The browser
// raises AuditAuthFailedOtp on a wrong code and AuditAuthSuccessOtp on a good one; the account
// API raises neither, because enabling an authenticator is not an authentication ceremony; all
// three raise AuditOTPCodeReplayDetected. That is what VerifyResult reports an outcome for
// instead of deciding anything itself.
//
// Deliberately outside it, both from decision 4. The account API's pending-enrolment mint, its
// compare-and-set install and its expiry read stay in apihandlers: one caller, one storage shape,
// and a capability carrying an operation only one caller can ever reach is not one cohesive
// responsibility. The browser ceremony's seed, which lives on AuthContext rather than on the
// users table, and its regenerate-on-unparseable arm stay in handlers for the same reason.
//
// internal/otp remains the stateless TOTP primitive below this one -- key URL generation,
// SecretFromKeyURL, RenderQRCodeImage, MatchStep. This package sits above it and owns the stored
// credential.
package otpcredential

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/otp"
)

// Database is what the OTP credential lifecycle needs: the user row, the generation counter every
// session compares itself against, the pending enrolment an establish clears, the consumed-step
// marker a verification claims and a removal resets, and the transaction they share.
//
// Exported, unlike the per-file ports #386 left in the handler packages, because it is this
// package's own port and the two consumer ports embed it to hand the capability on (#387).
//
// One port for all four operations rather than one per operation, following revocation.Database:
// the browser's port therefore names ResetUserOTPStep, which only Remove calls and the browser
// ceremony never reaches. Three ports in a package this small would name the same six methods
// between them and leave each consumer choosing which to embed.
type Database interface {
	ClearPendingOTPEnrollment(ctx context.Context, tx *sql.Tx, userId int64) error
	IncrementUserOtpConfigGeneration(ctx context.Context, tx *sql.Tx, userId int64) (int64, error)
	ResetUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64) error
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	TryConsumeUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64, requireOTPEnabled bool) (bool, error)
	UpdateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
}

// VerifyOutcome is what a passcode check concluded. The three values are the three arms every
// verification site already had, and they are distinguished because the audit sets differ: a
// replay raises an event of its own at all three, where a wrong code raises one at the browser
// and nothing at the account API.
type VerifyOutcome int

const (
	// OutcomeWrong is the zero value on purpose: a VerifyResult nobody filled in is a refusal,
	// not an acceptance, so a caller that drops an error and reads the result anyway refuses
	// the passcode rather than authenticating on it.
	OutcomeWrong VerifyOutcome = iota
	// OutcomeMatched means the passcode matched a step inside the acceptance window AND that
	// step was claimed by this call. It is the only outcome a caller may treat as a verified
	// second factor.
	OutcomeMatched
	// OutcomeReplayed means the passcode matched, and the step it matched was already spent.
	// Indistinguishable from a wrong code to the person submitting it, by design (#111), which
	// is why the two arms write the same body at every caller.
	OutcomeReplayed
)

// VerifyResult is the outcome and the time step it was decided on, following RevocationResult's
// shape rather than returning a bare bool the callers would each interpret. Step is the matched
// step, which the replay audit record at all three sites carries; it is zero when nothing
// matched, since there is no step to name.
type VerifyResult struct {
	Outcome VerifyOutcome
	Step    int64
}

// Establish installs a user's authenticator: it encrypts the seed at rest, turns otp_enabled on,
// writes the user, advances the OTP configuration generation and discards any pending enrolment,
// returning the generation that landed.
//
// **The writes commit together, and that is the point of this function**, exactly as for Remove
// below and for the reason #242 decision 2 gives. A separate increment whose error is merely
// surfaced leaves the authenticator on with the counter unmoved, so every existing session's
// snapshot still matches and they keep asserting acr: urn:goiabada:level2_optional with amr:
// ["pwd"] for a user who now has an authenticator. The caller cannot recover from it either: a
// retry is refused with OTP_ALREADY_ENABLED and the only way out is to disable and enrol again.
// With the transaction the enrollment rolls back and the retry is clean.
//
// The TOTP code is spent either way, which is not new: #111 claims the time step before the
// enable write precisely so a failed enable cannot leave OTP switched on, so a rolled back
// transaction behaves exactly as a failed UpdateUser does today and the user types the next code.
//
// Shared by the two enable sites decision 2 names, HandleAuthOtpPost's enrollment branch and
// HandleAPIAccountOTPPut's enable branch. There is no third. The encryption and the two field
// writes were the caller's before #387 and are folded in here, so a site that establishes an
// authenticator cannot store the seed without moving the counter.
//
// The browser caller needs the returned value: it captured the pre-enrollment generation at
// /auth/level2, and promoting that at /auth/completed would leave a session that just enrolled
// and verified owing another second-factor prompt at once.
func Establish(ctx context.Context, db Database, user *models.User, seed string) (int64, error) {
	if err := setSecret(user, seed); err != nil {
		return 0, err
	}
	user.OTPEnabled = true

	// Opened through RunInTransaction, so a deadlock reruns the three writes together (#301).
	// Safe to rerun: the user model was set above, before this opened, and is written
	// unchanged on every attempt, and generation is the committing attempt's.
	var generation int64
	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := db.UpdateUser(ctx, tx, user); err != nil {
			return err
		}
		var err error
		generation, err = db.IncrementUserOtpConfigGeneration(ctx, tx, user.Id)
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
		if err := db.ClearPendingOTPEnrollment(ctx, tx, user.Id); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return generation, nil
}

// Remove removes a user's authenticator: it clears the secret, turns otp_enabled off and returns
// the consumed-step marker to 0. The marker belongs to the authenticator being removed, and
// UpdateUser cannot carry it because the column is dont-update, which is why it takes a second write
// (#111 decision 4). The reset is also the only in-product remedy if a clock jump strands a user's
// marker in the future: without it, disabling OTP and re-enrolling would claim against the same
// poisoned marker and fail too.
//
// **The two writes commit together, and that is the point of this function** (#111 decision 13).
// Committed separately, which is how they were written before that decision, they leave a window in
// which the row reads otp_enabled = false with the old marker still standing. The window is between
// two committed statements, not inside one: no engine this server supports exposes an uncommitted
// write to an outside reader, so a transaction is the remedy rather than the hazard. An enrollment
// landing in that window loads the disabled state, matches a code and
// claims its step successfully, and then this reset erases the claim: the row settles at
// otp_enabled = 1 with last_otp_step = 0 and a code already consumed, so that code is claimable
// again at the browser prompt for the rest of its acceptance window. A concurrent enrollment sees
// either the pre-disable state, where OTP_ALREADY_ENABLED refuses it at the account API and decision
// 10's requireOTPEnabled refuses it at the browser verification branch, or the fully disabled state
// including the reset, where its claim stands. Neither method needed a transaction on its own; the
// pair does.
//
// The order inside the transaction is decision 10's, otp_enabled cleared before the marker. The
// commit boundary is now what closes that window rather than the ordering, since no reader outside
// the transaction observes either write until both have landed, but the order is kept: it costs
// nothing and it is the order the two disable sites have always written in.
//
// Shared by the two sites decision 4 names, HandleAPIAccountOTPPut's disable branch and
// HandleAPIUserOTPPut. There is no third: the browser flow enrolls but never disables.
func Remove(ctx context.Context, db Database, user *models.User) error {
	clearSecret(user)
	user.OTPEnabled = false

	// Opened through RunInTransaction, so a deadlock reruns the three writes together (#301).
	// Safe to rerun: the model was cleared above, before the helper opened, and is written
	// unchanged on every attempt; the reset and the increment carry no state between attempts.
	return db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := db.UpdateUser(ctx, tx, user); err != nil {
			return err
		}
		if err := db.ResetUserOTPStep(ctx, tx, user.Id); err != nil {
			return err
		}
		// The counter that tells every one of this user's sessions they owe a second factor
		// again, advanced inside the same transaction as the removal itself. Being per user is
		// what makes "every session" one statement: the boolean this replaced was per session
		// and written only for the caller's own sid, so a user disabling their authenticator
		// from one device left every other session asserting amr ["pwd","otp"] for an
		// authenticator that no longer existed (#242 decisions 1 and 2).
		//
		// Its error is returned rather than discarded, and that is the other half of decision 2:
		// a removal that commits without the counter moving is precisely the state the re-prompt
		// exists to prevent.
		if _, err := db.IncrementUserOtpConfigGeneration(ctx, tx, user.Id); err != nil {
			return err
		}
		return nil
	})
}

// VerifyStored checks a passcode against the authenticator the user has enrolled, and claims the
// step it matched. This is the assertion of a second factor, so requireOTPEnabled is true: without
// that term a request that loaded the user before a concurrent Remove could still claim a step and
// be issued a token naming amr "otp" for an authenticator that had just been removed (#111
// decision 10).
//
// The stored seed is decrypted here and goes no further: it is the read that used to travel out to
// the browser handler as models.User.GetOTPSecret, which is what #387's rule about a plaintext seed
// not leaving the minimum is about.
//
// One caller today, HandleAuthOtpPost's already-enrolled arm.
func VerifyStored(ctx context.Context, db Database, user *models.User, code string, now time.Time) (VerifyResult, error) {
	secret, err := storedSecret(user)
	if err != nil {
		return VerifyResult{}, err
	}
	return verify(ctx, db, user, secret, code, now, true)
}

// VerifySupplied checks a passcode against a seed the caller holds rather than one the user has
// enrolled, and claims the step it matched. This is enrolment establishing an authenticator rather
// than a verification asserting one, so requireOTPEnabled is false: otp_enabled is still off until
// Establish writes it (#111 decision 10).
//
// The claim comes before the establish deliberately, at both callers: if the write then fails, a
// code is burned and the user retries with the next one, whereas the reverse order would leave OTP
// enabled on a request that was refused.
//
// Two callers, and the seed reaches this function from a different place at each: the browser's
// comes off AuthContext.OTPKeyURL, the account API's off the pending enrolment the server issued
// and recorded. Neither seed is ever one the requester named.
func VerifySupplied(ctx context.Context, db Database, user *models.User, seed string, code string,
	now time.Time) (VerifyResult, error) {
	return verify(ctx, db, user, seed, code, now, false)
}

// verify is the arm both entry points run: match the passcode against a seed inside the acceptance
// window, then claim the step it matched, so a passcode is accepted at most once (#111).
//
// It reports rather than decides. The caller keeps the audit records, the rate-limit accounting and
// the response, because those three genuinely differ between the sites and must keep differing.
func verify(ctx context.Context, db Database, user *models.User, secret string, code string,
	now time.Time, requireOTPEnabled bool) (VerifyResult, error) {
	step, matched := otp.MatchStep(code, secret, now)
	if !matched {
		return VerifyResult{Outcome: OutcomeWrong}, nil
	}

	consumed, err := db.TryConsumeUserOTPStep(ctx, nil, user.Id, step, requireOTPEnabled)
	if err != nil {
		return VerifyResult{}, err
	}
	if !consumed {
		return VerifyResult{Outcome: OutcomeReplayed, Step: step}, nil
	}
	return VerifyResult{Outcome: OutcomeMatched, Step: step}, nil
}

// setSecret encrypts the TOTP seed at rest (AES-256-GCM, via the process data cipher) into
// OTPSecretEncrypted. See issue #82: TOTP secrets must not be stored in plaintext. The data cipher
// must be initialized at startup (encryption.InitDataCipher, issue #83).
//
// Unexported, where this was models.User.SetOTPSecret: the only way to store a seed is to establish
// an authenticator with it, which is what keeps the cipher and the generation advance from coming
// apart (#387).
func setSecret(u *models.User, secret string) error {
	encrypted, err := encryption.EncryptData(secret)
	if err != nil {
		return err
	}
	u.OTPSecretEncrypted = encrypted
	return nil
}

// storedSecret returns the decrypted TOTP seed, or an empty string if the user has no encrypted
// secret. It is the only way a seed is read: the legacy plaintext users.otp_secret column was
// dropped by migration 000048 along with the startup pass that converted it (#98, #262).
//
// Unexported, where this was models.User.GetOTPSecret, and that is decision 4's point: a plaintext
// seed now leaves this package only on the enrolment render path, where the QR code needs it.
func storedSecret(u *models.User) (string, error) {
	if len(u.OTPSecretEncrypted) == 0 {
		return "", nil
	}
	return encryption.DecryptData(u.OTPSecretEncrypted)
}

// clearSecret removes any stored TOTP seed.
func clearSecret(u *models.User) {
	u.OTPSecretEncrypted = nil
}
