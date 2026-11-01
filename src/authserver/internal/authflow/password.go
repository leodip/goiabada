package authflow

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
)

// PasswordPrompt is the client block of the password form, which GET /auth/pwd renders and POST
// /auth/pwd renders again beside a refusal, and only then: an accepted submission redirects. The
// route table builds one.
//
// No user session is read: the form prefills no address, because an ended session's address is
// what a shared machine should not show (#248, #436).
type PasswordPrompt struct {
	database ceremonyClientDisplayDatabase
}

// NewPasswordPrompt builds the operation over the database it reads.
func NewPasswordPrompt(database ceremonyClientDisplayDatabase) *PasswordPrompt {
	return &PasswordPrompt{database: database}
}

// Run loads the ceremony's client and returns its block (loadClientDisplay). A failed read, or a
// client not found, is returned as an error. It writes nothing.
func (o *PasswordPrompt) Run(ctx context.Context, authContext *ceremony.AuthContext) (*ClientDisplayInfo, error) {
	return loadClientDisplay(ctx, o.database, authContext)
}

// passwordSubmissionDatabase is what PasswordSubmission reads: the account the address names.
// data.Database satisfies it.
type passwordSubmissionDatabase interface {
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error)
}

// passwordSubmissionBrowser is what PasswordSubmission does through the handler's per-request
// adapter: charge a refused guess to the rate limiter, rotate the browser session's identifier, and
// save the ceremony.
type passwordSubmissionBrowser interface {
	stepSaver
	sessionRotator
	credentialFailureRecorder
}

// PasswordSubmission is POST /auth/pwd, the password form submitted in level1_password: it checks
// the password and, when it is right and the account enabled, records level 1 as performed by this
// ceremony. The route table builds one.
type PasswordSubmission struct {
	database    passwordSubmissionDatabase
	auditLogger auditLogger
	// proof records an accepted password on the ceremony, as registration and activation record
	// theirs (#622 decision 9).
	proof *PasswordProof
	// verifyPassword is the password comparison the form makes, a field so a test can see which
	// hash each refusal compared against (#681).
	verifyPassword func(hashedPassword string, password string) bool
}

// NewPasswordSubmission builds the operation over the database it reads and the audit log.
func NewPasswordSubmission(database passwordSubmissionDatabase, auditLogger auditLogger) *PasswordSubmission {
	return &PasswordSubmission{database: database, auditLogger: auditLogger, proof: NewPasswordProof(auditLogger),
		verifyPassword: passwordhash.Verify}
}

// PasswordAnswer is how PasswordSubmission answered a submission.
type PasswordAnswer int

const (
	// PasswordRefused is an address naming no account, a password that is not the account's, or any
	// password for an account that has none yet. The form is shown again with one message for all
	// three, in the request's locale, so neither the wording nor the language says whether the
	// account exists.
	PasswordRefused PasswordAnswer = iota + 1
	// PasswordAccountDisabled is the right password for a disabled account. The form is shown again
	// with the disabled message, in the user's page language. Nothing was written to the browser session.
	PasswordAccountDisabled
	// PasswordAccepted is the right password for an enabled account: the ceremony recorded it, the
	// browser session's identifier was rotated, and the ceremony saved in level1_password_completed.
	PasswordAccepted
)

// PasswordSubmissionResult is what PasswordSubmission.Run did.
type PasswordSubmissionResult struct {
	Answer PasswordAnswer
	// UserPageLanguage is the verified user's page language, set on PasswordAccountDisabled and
	// PasswordAccepted. From the verified password on, the handler answers in it
	// (i18n.WithPageLanguage), over the request's ui_locales and the browser; on Automatic it answers
	// in the request's language, never the user's Language and region (#631 decisions 2 and 5).
	UserPageLanguage string

	// NextStep is /auth/level1completed, set on PasswordAccepted.
	NextStep string
	// SaveErr is the rotation's failure, or the save's, on PasswordAccepted:
	// ceremony.ErrCeremonyReplaced when the browser session no longer holds the ceremony. A failed
	// rotation is never followed by the save. The handler redirects to NextStep only when it is nil.
	SaveErr error
}

// Run checks the password typed for email, which the handler has already normalized to the spelling
// the rate limiter keys on and every write stores (#219). In order:
//
//  1. Loads the account email names; a failed read is returned as an error, and nothing is audited.
//  2. No account: compares the password against a dummy hash, so the answer takes as long as for a
//     wrong password, charges the guess to the rate limiter, audits EventAuthFailedPwd with the
//     address's digest, and answers PasswordRefused.
//  3. A wrong password, or an account with no password yet, whose password is compared against
//     the dummy hash for the same reason and refused whatever that comparison says: charges the
//     guess, audits EventAuthFailedPwd with the digest and the account, and answers PasswordRefused.
//  4. A disabled account: audits EventUserDisabled and answers PasswordAccountDisabled. Not charged
//     to the rate limiter: the password was right, so there is no guess to bound (#219).
//  5. Accepted: records the proven password on the ceremony through PasswordProof, which audits
//     EventAuthSuccessPwd, rotates the browser session's identifier, and only then saves the
//     ceremony in level1_password_completed.
//
// The address is audited only as its digest: the form collects whatever anyone types, and the audit
// table would otherwise keep every mistyped address and pasted password in plain text (#522
// decision 10).
func (o *PasswordSubmission) Run(ctx context.Context, browser passwordSubmissionBrowser,
	authContext *ceremony.AuthContext, email string, password string) (PasswordSubmissionResult, error) {

	user, err := o.database.GetUserByEmail(ctx, nil, email)
	if err != nil {
		return PasswordSubmissionResult{}, err
	}

	emailDigest := hashutil.HashString(email)

	if user == nil {
		o.verifyPassword(passwordhash.DummyHash(), password)
		browser.RecordCredentialFailure()
		o.auditLogger.Log(ctx, audit.EventAuthFailedPwd, map[string]interface{}{
			"email_digest": emailDigest,
		})
		return PasswordSubmissionResult{Answer: PasswordRefused}, nil
	}

	// An account with no password yet (one an administrator created with the setup email keeps an
	// empty hash until its user sets one, and bcrypt refuses an empty hash without doing any work)
	// is compared against the dummy hash, so it takes as long to refuse as a wrong password and the
	// response time does not say whether its user has set a password. The comparison's result is
	// ignored: the dummy hash's plaintext signs no one in (#681).
	passwordMatches := false
	if user.PasswordHash == "" {
		o.verifyPassword(passwordhash.DummyHash(), password)
	} else {
		passwordMatches = o.verifyPassword(user.PasswordHash, password)
	}
	if !passwordMatches {
		browser.RecordCredentialFailure()
		o.auditLogger.Log(ctx, audit.EventAuthFailedPwd, map[string]interface{}{
			"email_digest": emailDigest,
			"user_id":      user.Id,
		})
		return PasswordSubmissionResult{Answer: PasswordRefused}, nil
	}

	if !user.Enabled {
		o.auditLogger.Log(ctx, audit.EventUserDisabled, map[string]interface{}{
			"user_id": user.Id,
		})
		return PasswordSubmissionResult{Answer: PasswordAccountDisabled, UserPageLanguage: user.PageLanguage}, nil
	}

	proven := o.proof.Record(ctx, browser, authContext, user)
	return PasswordSubmissionResult{
		Answer:           PasswordAccepted,
		UserPageLanguage: user.PageLanguage,
		NextStep:         proven.NextStep,
		SaveErr:          proven.SaveErr,
	}, nil
}

// passwordProofBrowser is what PasswordProof does through the handler's per-request adapter: rotate
// the browser session's identifier, and save the ceremony.
type passwordProofBrowser interface {
	stepSaver
	sessionRotator
}

// PasswordProof records on a sign-in that its user has just proven a password: the password page's
// accepted submission, and registration and activation carrying on the sign-in that started them,
// where the user has just chosen it (#622 decision 9). The rotation and the state change are
// security-critical, so they live here alone, and every page that proves a password makes them in
// the same order. Built by the route table, or by a handler over its audit log.
type PasswordProof struct {
	auditLogger auditLogger
}

// NewPasswordProof builds the operation over the audit log.
func NewPasswordProof(auditLogger auditLogger) *PasswordProof {
	return &PasswordProof{auditLogger: auditLogger}
}

// PasswordProofResult is what PasswordProof.Record did.
type PasswordProofResult struct {
	// NextStep is /auth/level1completed, where the ceremony goes on once the save landed.
	NextStep string
	// SaveErr is the rotation's failure, or the save's: ceremony.ErrCeremonyReplaced when the
	// browser session no longer holds the ceremony. A failed rotation is never followed by the save.
	// The caller sends the browser to NextStep only when it is nil.
	SaveErr error
}

// Record audits EventAuthSuccessPwd, records the verified password on the ceremony
// (RecordPasswordVerified), rotates the browser session's identifier, and only then saves the
// ceremony in level1_password_completed. The caller has established that user proved the password,
// that the account is enabled, and that the ceremony is at the password step.
//
// The rotation comes the instant the password is accepted, and before the save. The steps between
// here and /auth/completed are GETs gated on the ceremony's state alone, so an attacker who planted
// the browser session's identifier and polls them could otherwise be handed the session minted for
// this user. Rotating before the save leaves a failure between the two on a fresh identifier whose
// ceremony is not yet password-completed, the harmless direction; saving first would leave the
// planted identifier naming a password-completed ceremony (#266). Both land only while the browser
// session still holds this ceremony (#579).
func (o *PasswordProof) Record(ctx context.Context, browser passwordProofBrowser, authContext *ceremony.AuthContext,
	user *record.User) PasswordProofResult {

	o.auditLogger.Log(ctx, audit.EventAuthSuccessPwd, map[string]interface{}{
		"user_id": user.Id,
	})

	authContext.RecordPasswordVerified(user, time.Now())

	result := PasswordProofResult{NextStep: "/auth/level1completed"}
	if result.SaveErr = browser.RegenerateSession(authContext.CeremonyId, authContext.UserId); result.SaveErr != nil {
		return result
	}
	result.SaveErr = browser.SaveAuthContext(authContext)
	return result
}
