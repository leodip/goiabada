// Package otpcredential owns the stored TOTP authenticator: establishing one, removing one,
// verifying a passcode against one, and the seed's encryption at rest. Four operations, the
// ones that are identical on every path a user can enrol or authenticate through -- the browser
// ceremony at /auth/otp, the account API at PUT /api/v1/account/otp, and the admin API at
// PUT /api/v1/admin/users/{id}/otp (#387 decision 4).
//
// Nothing here takes an http.ResponseWriter, a *http.Request, template data or a status code, and
// nothing here imports a handler package: the operations sit below every handler that calls them,
// and the seed's cipher sits here rather than on record.User, which is a persistence record (#387).
//
// **The audit call stays at the caller**, as revocation requires of its own callers and for the
// same reason: the two verification sites raise deliberately different event sets. The browser,
// which verifies a stored authenticator or one being enrolled, raises EventAuthFailedOtp on a
// wrong code and EventAuthSuccessOtp on a good one; the account API raises neither, because
// enabling an authenticator is not an authentication ceremony; both raise
// EventOTPCodeReplayDetected. That is what VerifyResult reports an outcome for instead of deciding
// anything itself.
//
// Deliberately outside it (#387 decision 4), the account API's pending-enrolment mint, its
// compare-and-set install and its expiry read stay in apihandlers: one caller, one storage shape,
// and a capability carrying an operation only one caller can ever reach is not one cohesive
// responsibility. The browser ceremony's seed, which lives on AuthContext rather than on the
// users table, and its regenerate-on-unparseable arm stay in handlers for the same reason.
//
// internal/otp is the stateless TOTP primitive below this one -- key URL generation,
// SecretFromKeyURL, RenderQRCodeImage, MatchStep. This package sits above it and owns the stored
// credential.
package otpcredential

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// Database is what the OTP credential lifecycle needs: the authenticator's two compare-and-sets on
// the user row, the generation counter every session compares itself against, the pending enrolment an establish clears, the consumed-step
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
	TryConsumeEnrolledUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64,
		expectedGeneration int64) (bool, error)
	TryConsumeUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64) (bool, error)
	TryEstablishUserOTP(ctx context.Context, tx *sql.Tx, userId int64, expectedGeneration int64,
		secretEncrypted []byte) (bool, error)
	TryRemoveUserOTP(ctx context.Context, tx *sql.Tx, userId int64, expectedGeneration int64) (bool, error)
}

// VerifyOutcome is what a passcode check concluded. The three values are the three arms every
// verification site already had, and they are distinguished because the audit sets differ: a
// replay raises an event of its own at both sites, where a wrong code raises one at the browser
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

// VerifyResult is the outcome and the time step it was decided on, following
// revocation.UserAuthStateResult's shape rather than returning a bare bool the callers would each
// interpret. Step is the matched step, which the replay audit record at both sites carries;
// it is zero when nothing matched, since there is no step to name.
type VerifyResult struct {
	Outcome VerifyOutcome
	Step    int64
}

// Establish installs a user's authenticator: it encrypts the seed at rest and, only while OTP is
// still off at the otp_config_generation user was read with, stores it and turns otp_enabled on,
// advances the generation and discards any pending enrolment. It reports whether it did and, when
// it did, the generation that landed.
//
// **A compare-and-set on the authenticator, not on the flag** (#471 decision 2). The write names
// only the seed and otp_enabled, so it cannot undo a disable or a password change made since the
// read, and it lands only while the row still holds the authenticator state the request read: of two
// overlapping enrolments the second is refused rather than replacing the first's secret, and an
// enable and a disable landing entirely between the read and the write, which leave otp_enabled
// where it was, still move the generation and refuse it (#144). When it matches nothing, nothing
// else runs either: the generation does not advance and the pending enrolment stays, and the caller
// gets false with no error and answers from what the row now shows.
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
// enable write precisely so a failed enable cannot leave OTP switched on, so a rolled back or lost
// establish behaves exactly as a failed write always has and the user types the next code.
//
// Shared by the two enable sites decision 2 names, HandleAuthOtpPost's enrollment branch and
// HandleAccountOTPPut's enable branch. There is no third. The encryption and the two field
// writes were the caller's before #387 and are folded in here, so a site that establishes an
// authenticator cannot store the seed without moving the counter.
//
// The browser caller needs the returned value: it captured the pre-enrollment generation at
// /auth/level2, and promoting that at /auth/completed would leave a session that just enrolled
// and verified owing another second-factor prompt at once.
func Establish(ctx context.Context, db Database, dataCipher *encryption.DataCipher, user *record.User,
	seed string) (generation int64, established bool, err error) {

	encrypted, err := encryptSecret(dataCipher, seed)
	if err != nil {
		return 0, false, err
	}

	// Opened through RunInTransaction, so a deadlock reruns the three writes together (#301).
	// Safe to rerun: the ciphertext and the generation compared are fixed above, before this
	// opened, and established and generation are the committing attempt's.
	err = db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		generation = 0
		var writeErr error
		established, writeErr = db.TryEstablishUserOTP(ctx, tx, user.Id, user.OtpConfigGeneration, encrypted)
		if writeErr != nil {
			return writeErr
		}
		if !established {
			return nil
		}
		generation, writeErr = db.IncrementUserOtpConfigGeneration(ctx, tx, user.Id)
		if writeErr != nil {
			return writeErr
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
		return db.ClearPendingOTPEnrollment(ctx, tx, user.Id)
	})
	if err != nil {
		return 0, false, err
	}
	if !established {
		return 0, false, nil
	}

	user.OTPSecretEncrypted = encrypted
	user.OTPEnabled = true
	user.OtpConfigGeneration = generation
	return generation, true, nil
}

// Remove removes a user's authenticator: only while OTP is still on at the otp_config_generation
// user was read with, it clears the secret, turns otp_enabled off, returns the consumed-step marker
// to 0 and advances the generation. It reports whether it did.
//
// A compare-and-set on the authenticator, for Establish's reason (#471 decision 2): the write names
// only the seed and otp_enabled, so it cannot undo a disable or a password change made since the
// read, and a removal read before the authenticator was removed and another established in its
// place does not remove the replacement. When it matches nothing, nothing else runs: the marker and
// the generation stay as they are, and the caller gets false with no error.
//
// The marker belongs to the authenticator being removed, and the column is dont-update, which is
// why it takes a second write (#111 decision 4). The reset is also the only in-product remedy if a
// clock jump strands a user's marker in the future: without it, disabling OTP and re-enrolling
// would claim against the same poisoned marker and fail too.
//
// **The writes commit together, and that is the point of this function** (#111 decision 13).
// Committed separately, which is how they were written before that decision, they leave a window in
// which the row reads otp_enabled = false with the old marker still standing. The window is between
// two committed statements, not inside one: no engine this server supports exposes an uncommitted
// write to an outside reader, so a transaction is the remedy rather than the hazard. An enrollment
// landing in that window loads the disabled state, matches a code and
// claims its step successfully, and then this reset erases the claim: the row settles at
// otp_enabled = 1 with last_otp_step = 0 and a code already consumed, so that code is claimable
// again at the browser prompt for the rest of its acceptance window. A concurrent enrollment sees
// either the pre-disable state, where OTP_ALREADY_ENABLED refuses it at the account API and decision
// 10's otp_enabled term refuses it at the browser verification branch, or the fully disabled state
// including the reset, where its claim stands. Neither method needed a transaction on its own; the
// pair does.
//
// The order inside the transaction is decision 10's, otp_enabled cleared before the marker. The
// commit boundary is now what closes that window rather than the ordering, since no reader outside
// the transaction observes either write until both have landed, but the order is kept: it costs
// nothing and it is the order the two disable sites have always written in.
//
// Shared by the two sites decision 4 names, HandleAccountOTPPut's disable branch and
// HandleUserOTPPut. There is no third: the browser flow enrolls but never disables.
func Remove(ctx context.Context, db Database, user *record.User) (removed bool, err error) {
	// Opened through RunInTransaction, so a deadlock reruns the three writes together (#301).
	// Safe to rerun: the generation compared is the request's read, and removed is the committing
	// attempt's; the reset and the increment carry no state between attempts.
	err = db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var writeErr error
		removed, writeErr = db.TryRemoveUserOTP(ctx, tx, user.Id, user.OtpConfigGeneration)
		if writeErr != nil {
			return writeErr
		}
		if !removed {
			return nil
		}
		if writeErr = db.ResetUserOTPStep(ctx, tx, user.Id); writeErr != nil {
			return writeErr
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
		_, writeErr = db.IncrementUserOtpConfigGeneration(ctx, tx, user.Id)
		return writeErr
	})
	if err != nil {
		return false, err
	}
	if !removed {
		return false, nil
	}

	user.OTPSecretEncrypted = nil
	user.OTPEnabled = false
	return true, nil
}

// VerifyStored checks a passcode against the authenticator the user has enrolled, and claims the
// step it matched. This is the assertion of a second factor, so the claim is bound to the
// authenticator the passcode was checked against: it matches only while otp_enabled is on at the
// otp_config_generation user was read with, the one read with the secret. Without the first term a
// request that loaded the user before a concurrent Remove could still claim a step and be issued a
// token naming amr "otp" for an authenticator that had just been removed (#111 decision 10);
// without the second, one that loaded the user before a Remove and an Establish replaced the
// authenticator could, since the row reads enabled again with the marker reset (#144, #471
// decision 3). A claim refused this way is OutcomeReplayed, answered as every refused claim is.
//
// The stored seed is decrypted here and goes no further: it is the read that used to travel out to
// the browser handler as record.User.GetOTPSecret, which is what #387's rule about a plaintext seed
// not leaving the minimum is about.
//
// One caller today, HandleAuthOtpPost's already-enrolled arm.
func VerifyStored(ctx context.Context, db Database, dataCipher *encryption.DataCipher, user *record.User, code string, now time.Time) (VerifyResult, error) {
	secret, err := storedSecret(dataCipher, user)
	if err != nil {
		return VerifyResult{}, err
	}
	return verify(secret, code, now, func(step int64) (bool, error) {
		return db.TryConsumeEnrolledUserOTPStep(ctx, nil, user.Id, step, user.OtpConfigGeneration)
	})
}

// VerifySupplied checks a passcode against a seed the caller holds rather than one the user has
// enrolled, and claims the step it matched. This is enrolment establishing an authenticator rather
// than a verification asserting one, so the claim names no authenticator state: otp_enabled is
// still off until Establish writes it, and Establish is itself the compare-and-set on the
// authenticator the request read (#111 decision 10, #471 decision 2).
//
// The claim comes before the establish deliberately, at both callers: if the write then fails, a
// code is burned and the user retries with the next one, whereas the reverse order would leave OTP
// enabled on a request that was refused.
//
// Two callers, and the seed reaches this function from a different place at each: the browser's
// comes off AuthContext.OTPKeyURL, the account API's off the pending enrolment the server issued
// and recorded. Neither seed is ever one the requester named.
func VerifySupplied(ctx context.Context, db Database, user *record.User, seed string, code string,
	now time.Time) (VerifyResult, error) {
	return verify(seed, code, now, func(step int64) (bool, error) {
		return db.TryConsumeUserOTPStep(ctx, nil, user.Id, step)
	})
}

// verify is the arm both entry points run: match the passcode against a seed inside the acceptance
// window, then claim the step it matched through the entry point's claim, so a passcode is
// accepted at most once (#111).
//
// It reports rather than decides. The caller keeps the audit records, the rate-limit accounting and
// the response, because those three genuinely differ between the sites and must keep differing.
func verify(secret string, code string, now time.Time, claim func(step int64) (bool, error)) (VerifyResult, error) {
	step, matched := otp.MatchStep(code, secret, now)
	if !matched {
		return VerifyResult{Outcome: OutcomeWrong}, nil
	}

	consumed, err := claim(step)
	if err != nil {
		return VerifyResult{}, err
	}
	if !consumed {
		return VerifyResult{Outcome: OutcomeReplayed, Step: step}, nil
	}
	return VerifyResult{Outcome: OutcomeMatched, Step: step}, nil
}

// encryptSecret encrypts the TOTP seed at rest (AES-256-GCM, under the data cipher it is given),
// which is the form OTPSecretEncrypted stores. See issue #82: TOTP secrets must not be stored in
// plaintext.
//
// Unexported, where this was record.User.SetOTPSecret: the only way to store a seed is to establish
// an authenticator with it, which is what keeps the cipher and the generation advance from coming
// apart (#387).
func encryptSecret(dataCipher *encryption.DataCipher, secret string) ([]byte, error) {
	return dataCipher.Encrypt(secret)
}

// storedSecret returns the decrypted TOTP seed, or an empty string if the user has no encrypted
// secret. It is the only way a seed is read: the legacy plaintext users.otp_secret column was
// dropped by migration 000048 along with the startup pass that converted it (#98, #262).
//
// Unexported, where this was record.User.GetOTPSecret, and that is decision 4's point: a plaintext
// seed now leaves this package only on the enrolment render path, where the QR code needs it.
func storedSecret(dataCipher *encryption.DataCipher, u *record.User) (string, error) {
	if len(u.OTPSecretEncrypted) == 0 {
		return "", nil
	}
	return dataCipher.Decrypt(u.OTPSecretEncrypted)
}
