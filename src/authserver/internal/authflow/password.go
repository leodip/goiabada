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
}

// NewPasswordSubmission builds the operation over the database it reads and the audit log.
func NewPasswordSubmission(database passwordSubmissionDatabase, auditLogger auditLogger) *PasswordSubmission {
	return &PasswordSubmission{database: database, auditLogger: auditLogger}
}

// PasswordAnswer is how PasswordSubmission answered a submission.
type PasswordAnswer int

const (
	// PasswordRefused is an address naming no account, or a password that is not the account's. The
	// form is shown again with one message for both, in the request's locale, so neither the wording
	// nor the language says whether the account exists.
	PasswordRefused PasswordAnswer = iota + 1
	// PasswordAccountDisabled is the right password for a disabled account. The form is shown again
	// with the disabled message, in the user's locale. Nothing was written to the browser session.
	PasswordAccountDisabled
	// PasswordAccepted is the right password for an enabled account: the ceremony recorded it, the
	// browser session's identifier was rotated, and the ceremony saved in level1_password_completed.
	PasswordAccepted
)

// PasswordSubmissionResult is what PasswordSubmission.Run did.
type PasswordSubmissionResult struct {
	Answer PasswordAnswer
	// UserLocale is the verified user's stored locale, set on PasswordAccountDisabled and
	// PasswordAccepted. From the verified password on, the handler answers in it, unless the request
	// named a locale of its own (i18n.WithLocale, non-explicit).
	UserLocale string

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
//  3. A wrong password: charges the guess, audits EventAuthFailedPwd with the digest and the
//     account, and answers PasswordRefused.
//  4. A disabled account: audits EventUserDisabled and answers PasswordAccountDisabled. Not charged
//     to the rate limiter: the password was right, so there is no guess to bound (#219).
//  5. Accepted: audits EventAuthSuccessPwd, records the verified password on the ceremony
//     (RecordPasswordVerified), rotates the browser session's identifier, and only then saves the
//     ceremony in level1_password_completed.
//
// The address is audited only as its digest: the form collects whatever anyone types, and the audit
// table would otherwise keep every mistyped address and pasted password in plain text (#522
// decision 10).
//
// The rotation comes the instant the password is accepted, and before the save. The steps between
// here and /auth/completed are GETs gated on the ceremony's state alone, so an attacker who planted
// the browser session's identifier and polls them could otherwise be handed the session minted for
// this user. Rotating before the save leaves a failure between the two on a fresh identifier whose
// ceremony is not yet password-completed, the harmless direction; saving first would leave the
// planted identifier naming a password-completed ceremony (#266). Both land only while the browser
// session still holds this ceremony (#579).
func (o *PasswordSubmission) Run(ctx context.Context, browser passwordSubmissionBrowser,
	authContext *ceremony.AuthContext, email string, password string) (PasswordSubmissionResult, error) {

	user, err := o.database.GetUserByEmail(ctx, nil, email)
	if err != nil {
		return PasswordSubmissionResult{}, err
	}

	emailDigest := hashutil.HashString(email)

	if user == nil {
		passwordhash.Verify(passwordhash.DummyHash, password)
		browser.RecordCredentialFailure()
		o.auditLogger.Log(ctx, audit.EventAuthFailedPwd, map[string]interface{}{
			"email_digest": emailDigest,
		})
		return PasswordSubmissionResult{Answer: PasswordRefused}, nil
	}

	if !passwordhash.Verify(user.PasswordHash, password) {
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
		return PasswordSubmissionResult{Answer: PasswordAccountDisabled, UserLocale: user.Locale}, nil
	}

	o.auditLogger.Log(ctx, audit.EventAuthSuccessPwd, map[string]interface{}{
		"user_id": user.Id,
	})

	authContext.RecordPasswordVerified(user, time.Now())

	result := PasswordSubmissionResult{
		Answer:     PasswordAccepted,
		UserLocale: user.Locale,
		NextStep:   "/auth/level1completed",
	}
	if result.SaveErr = browser.RegenerateSession(authContext.CeremonyId); result.SaveErr != nil {
		return result, nil
	}
	result.SaveErr = browser.SaveAuthContext(authContext)
	return result, nil
}
