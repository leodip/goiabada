package authflow

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// otpStepDatabase is what both OTP operations read: the ceremony's user, and the client and whether
// it has a logo for the form. data.Database satisfies it.
type otpStepDatabase interface {
	ceremonyClientDisplayDatabase

	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// loadOTPUser reads the ceremony's user, whom either OTP form is for. A failed read, or a user not
// found, is returned as an error.
func loadOTPUser(ctx context.Context, database otpStepDatabase, authContext *ceremony.AuthContext) (*record.User, error) {
	user, err := database.GetUserById(ctx, nil, authContext.UserId)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errs.New("user not found")
	}
	return user, nil
}

// otpKeyGenerator mints the otpauth:// URL of a new TOTP key for an enrolling user, under the
// application name the authenticator app shows. otp.KeyGenerator satisfies it.
type otpKeyGenerator interface {
	GenerateKeyURL(email string, appName string) (string, error)
}

// OTPForm is which of the two OTP forms a step shows.
type OTPForm int

const (
	// OTPCodeForm asks a user who has an authenticator for its code (auth_otp.html).
	OTPCodeForm OTPForm = iota + 1
	// OTPEnrolmentForm shows a user with no authenticator the key to set one up with, as a QR code
	// and as its base32 secret, and asks for the first code (auth_otp_enrollment.html).
	OTPEnrolmentForm
)

// OTPPrompt is GET /auth/otp in level2_otp: it decides which form the user sees and prepares the
// ceremony for it. The route table builds one.
type OTPPrompt struct {
	database     otpStepDatabase
	keyGenerator otpKeyGenerator
}

// NewOTPPrompt builds the operation over the database it reads and the generator of enrolment keys.
func NewOTPPrompt(database otpStepDatabase, keyGenerator otpKeyGenerator) *OTPPrompt {
	return &OTPPrompt{database: database, keyGenerator: keyGenerator}
}

// OTPPromptResult is what OTPPrompt.Run prepared.
type OTPPromptResult struct {
	Form    OTPForm
	Display *ClientDisplayInfo
	// EnrolmentSecret and QRCodeImage, on OTPEnrolmentForm, are the base32 secret and the base64
	// PNG of the ceremony's enrolment key, both drawn from the one URL the ceremony holds, so the
	// image cannot disagree with the secret a code is checked against (#247).
	EnrolmentSecret string
	QRCodeImage     string

	// SaveErr is the save's failure: ceremony.ErrCeremonyReplaced when the browser session no
	// longer holds the ceremony. The handler renders the form only when it is nil.
	SaveErr error
}

// Run prepares the OTP form for the ceremony. appName is the settings' application name, under
// which a new key is minted. In order:
//
//  1. Loads the user (loadOTPUser), then the client block (loadClientDisplay); a failure is returned
//     as an error.
//  2. A user with an authenticator: clears the ceremony's enrolment key and saves the ceremony, for
//     OTPCodeForm. A key generated before the user enrolled elsewhere is dead, and the POST picks
//     the form it shows again by whether one is present (#242).
//  3. A user with none: keeps the ceremony's enrolment key, so a reload shows the QR code the user
//     has already scanned (#242 part 3). A ceremony with no key, or one that does not parse, gets a
//     new one: refusing an unusable key would wedge the ceremony on a 500 every reload repeats
//     (#247). Draws the QR code and only then saves the ceremony, for OTPEnrolmentForm. A key that
//     cannot be generated, parsed or drawn is returned as an error, and nothing is saved.
func (o *OTPPrompt) Run(ctx context.Context, browser stepSaver, authContext *ceremony.AuthContext,
	appName string) (OTPPromptResult, error) {

	user, err := loadOTPUser(ctx, o.database, authContext)
	if err != nil {
		return OTPPromptResult{}, err
	}
	display, err := loadClientDisplay(ctx, o.database, authContext)
	if err != nil {
		return OTPPromptResult{}, err
	}

	if user.OTPEnabled {
		authContext.OTPKeyURL = ""
		return OTPPromptResult{
			Form:    OTPCodeForm,
			Display: display,
			SaveErr: browser.SaveAuthContext(authContext),
		}, nil
	}

	secret, err := otp.SecretFromKeyURL(authContext.OTPKeyURL)
	if err != nil {
		keyURL, genErr := o.keyGenerator.GenerateKeyURL(user.Email, appName)
		if genErr != nil {
			return OTPPromptResult{}, genErr
		}
		authContext.OTPKeyURL = keyURL

		secret, err = otp.SecretFromKeyURL(keyURL)
		if err != nil {
			return OTPPromptResult{}, err
		}
	}

	image, err := otp.RenderQRCodeImage(authContext.OTPKeyURL)
	if err != nil {
		return OTPPromptResult{}, err
	}

	return OTPPromptResult{
		Form:            OTPEnrolmentForm,
		Display:         display,
		EnrolmentSecret: secret,
		QRCodeImage:     image,
		SaveErr:         browser.SaveAuthContext(authContext),
	}, nil
}

// otpSubmissionDatabase is what OTPSubmission reads and writes: the user and the client, and the
// stored authenticator a code is verified against or established on (otpcredential, which owns the
// single-use step claim as well as the write, #387). data.Database satisfies it.
type otpSubmissionDatabase interface {
	otpStepDatabase
	otpcredential.Database
}

// otpSubmissionBrowser is what OTPSubmission does through the handler's per-request adapter: charge
// a refused code to the rate limiter, end a ceremony whose enrolment was lost, and rotate the browser
// session's identifier and save the ceremony once a code is accepted.
type otpSubmissionBrowser interface {
	stepSaver
	sessionRotator
	ceremonyClearer
	credentialFailureRecorder
}

// OTPSubmission is POST /auth/otp, the OTP form submitted in level2_otp: it checks the code against
// the user's authenticator, or against the ceremony's enrolment key and then stores that key as the
// user's authenticator, and records level 2 as performed by this ceremony. The route table builds one.
type OTPSubmission struct {
	database    otpSubmissionDatabase
	auditLogger auditLogger
	dataCipher  *encryption.DataCipher
}

// NewOTPSubmission builds the operation over the database it reads and writes, the audit log, and the
// cipher a stored authenticator's seed is encrypted under.
func NewOTPSubmission(database otpSubmissionDatabase, auditLogger auditLogger,
	dataCipher *encryption.DataCipher) *OTPSubmission {

	return &OTPSubmission{database: database, auditLogger: auditLogger, dataCipher: dataCipher}
}

// OTPAnswer is how OTPSubmission answered a submission.
type OTPAnswer int

const (
	// OTPAccountDisabled is a disabled account. The form is shown again with the disabled message.
	OTPAccountDisabled OTPAnswer = iota + 1
	// OTPEnrolmentLost is an enrolment that can never be stored, because the account's authenticator
	// changed after the form was shown: the ceremony was cleared, and the sign-in ends on a page of
	// its own (#471 decision 2).
	OTPEnrolmentLost
	// OTPCodeMissing is a submission with no code. The form is shown again asking for one.
	OTPCodeMissing
	// OTPRefused is a wrong code, or a replayed one. The form is shown again with one message for
	// both: a code already spent proves nothing about who is submitting it.
	OTPRefused
	// OTPAccepted is a code accepted, and for an enrolling user the authenticator stored: the ceremony
	// recorded it, the browser session's identifier was rotated, and the ceremony saved in
	// authentication_completed.
	OTPAccepted
)

// OTPSubmissionResult is what OTPSubmission.Run did.
type OTPSubmissionResult struct {
	Answer OTPAnswer
	// Display is the client block, for the form shown again beside a refusal: set on
	// OTPAccountDisabled, OTPCodeMissing and OTPRefused, and nil on the two answers that show no form.
	Display *ClientDisplayInfo
	// EnrolmentSecret is the base32 secret of the ceremony's enrolment key, "" for a user with no key
	// on the ceremony. The form shown again beside a refusal is the enrolment form when it is set.
	EnrolmentSecret string

	// NextStep is /auth/completed, set on OTPAccepted.
	NextStep string
	// SaveErr is the rotation's failure, or the save's, on OTPAccepted, and the clear's on
	// OTPEnrolmentLost: ceremony.ErrCeremonyReplaced when the browser session no longer holds the
	// ceremony. A failed rotation is never followed by the save.
	SaveErr error
}

// Run checks code, which the handler read from the submitted body, against the ceremony's user. In
// order:
//
//  1. Parses the ceremony's enrolment key, when it holds one; a key that does not parse is returned
//     as an error, before anything is read.
//  2. Loads the user (loadOTPUser); a failure is returned as an error.
//  3. A disabled account: audits EventUserDisabled and answers OTPAccountDisabled.
//  4. An enrolment key on the ceremony for a user who has an authenticator now, set up in another tab
//     or on the account page since the form was shown: ends the lost enrolment (below), before the
//     code is looked at, since the code was minted from a seed that can never be stored.
//  5. No code: OTPCodeMissing.
//  6. Verifies the code: an enrolled user's against the stored authenticator
//     (otpcredential.VerifyStored), an enrolling user's against the enrolment key
//     (otpcredential.VerifySupplied). Either claims the code's time step, so a code is accepted once
//     (#111). A failed verification is returned as an error.
//  7. A replayed code: charges it to the rate limiter, audits EventOTPCodeReplayDetected and
//     EventAuthFailedOtp, and answers OTPRefused. A wrong code: charges it, audits
//     EventAuthFailedOtp, and answers OTPRefused. Every wrong code is a guess the OTP budget bounds
//     (#219). The refusal that disabled the authenticator also audits EventOTPAuthenticatorDisabled,
//     after the others (#489).
//  8. An enrolling user: stores the key as the user's authenticator (otpcredential.Establish), which
//     lands only while the user's OTP configuration generation is still the one read in step 2. A
//     failed write is returned as an error; a write that did not land ends the lost enrolment
//     (below). Audits EventEnabledOTP.
//  9. Accepted: audits EventAuthSuccessOtp, records the code on the ceremony (RecordOTPVerified) with
//     the generation of the authenticator it was checked against, rotates the browser session's
//     identifier, and only then saves the ceremony in authentication_completed.
//
// An answer that shows the form again, OTPAccountDisabled, OTPCodeMissing or OTPRefused, loads the
// client block for it last (refuse), after everything else that answer does; a failed read, or a
// client not found, is returned as an error. An accepted code redirects and a lost enrolment ends on
// a page of its own, so neither reads the client.
//
// A lost enrolment (#471 decision 2, #144) logs a warn record and clears the ceremony, answering
// OTPEnrolmentLost: nothing was stored, so the ceremony has no second factor to claim. Nothing is
// audited, and the code's step stays spent, as #111 already accepts for a failed enable.
//
// The rotation comes the instant the code is accepted, before the save, for the reason
// PasswordSubmission.Run gives (#266): a ceremony that reached level 2 by reusing a session has not
// rotated at all, and its identifier names the session about to be raised.
func (o *OTPSubmission) Run(ctx context.Context, browser otpSubmissionBrowser,
	authContext *ceremony.AuthContext, code string) (OTPSubmissionResult, error) {

	keyURL := authContext.OTPKeyURL
	var secret string
	if keyURL != "" {
		var err error
		secret, err = otp.SecretFromKeyURL(keyURL)
		if err != nil {
			return OTPSubmissionResult{}, err
		}
	}

	user, err := loadOTPUser(ctx, o.database, authContext)
	if err != nil {
		return OTPSubmissionResult{}, err
	}

	result := OTPSubmissionResult{EnrolmentSecret: secret}

	if !user.Enabled {
		o.auditLogger.Log(ctx, audit.EventUserDisabled, map[string]interface{}{
			"user_id": user.Id,
		})
		return o.refuse(ctx, authContext, result, OTPAccountDisabled)
	}

	if keyURL != "" && user.OTPEnabled {
		return o.endLostEnrolment(ctx, browser, result, user.Id, authContext.CeremonyId), nil
	}

	if len(code) == 0 {
		return o.refuse(ctx, authContext, result, OTPCodeMissing)
	}

	var verified otpcredential.VerifyResult
	if user.OTPEnabled {
		verified, err = otpcredential.VerifyStored(ctx, o.database, o.dataCipher, user, code, time.Now().UTC())
	} else {
		verified, err = otpcredential.VerifySupplied(ctx, o.database, user, secret, code, time.Now().UTC())
	}
	if err != nil {
		return OTPSubmissionResult{}, err
	}

	switch verified.Outcome {
	case otpcredential.OutcomeReplayed:
		browser.RecordCredentialFailure()
		o.auditLogger.Log(ctx, audit.EventOTPCodeReplayDetected, map[string]interface{}{
			"user_id": user.Id,
			"step":    verified.Step,
		})
		o.auditLogger.Log(ctx, audit.EventAuthFailedOtp, map[string]interface{}{
			"user_id": user.Id,
		})
		o.auditDisabled(ctx, verified, user.Id)
		return o.refuse(ctx, authContext, result, OTPRefused)
	case otpcredential.OutcomeWrong:
		browser.RecordCredentialFailure()
		o.auditLogger.Log(ctx, audit.EventAuthFailedOtp, map[string]interface{}{
			"user_id": user.Id,
		})
		o.auditDisabled(ctx, verified, user.Id)
		return o.refuse(ctx, authContext, result, OTPRefused)
	}

	verifiedGeneration := user.OtpConfigGeneration
	enrolled := false
	if !user.OTPEnabled {
		generation, established, establishErr := otpcredential.Establish(ctx, o.database, o.dataCipher, user, secret)
		if establishErr != nil {
			return OTPSubmissionResult{}, establishErr
		}
		if !established {
			return o.endLostEnrolment(ctx, browser, result, user.Id, authContext.CeremonyId), nil
		}
		verifiedGeneration = generation
		enrolled = true

		o.auditLogger.Log(ctx, audit.EventEnabledOTP, map[string]interface{}{
			"user_id": user.Id,
		})
	}

	o.auditLogger.Log(ctx, audit.EventAuthSuccessOtp, map[string]interface{}{
		"user_id": user.Id,
	})

	authContext.RecordOTPVerified(time.Now(), verifiedGeneration, enrolled)

	result.Answer = OTPAccepted
	result.NextStep = "/auth/completed"
	if result.SaveErr = browser.RegenerateSession(authContext.CeremonyId, authContext.UserId); result.SaveErr != nil {
		return result, nil
	}
	result.SaveErr = browser.SaveAuthContext(authContext)
	return result, nil
}

// refuse answers a submission whose form is shown again, with the client block for it, loaded now
// (loadClientDisplay): a failed read, or a client not found, is returned as an error.
func (o *OTPSubmission) refuse(ctx context.Context, authContext *ceremony.AuthContext, result OTPSubmissionResult,
	answer OTPAnswer) (OTPSubmissionResult, error) {

	display, err := loadClientDisplay(ctx, o.database, authContext)
	if err != nil {
		return OTPSubmissionResult{}, err
	}
	result.Answer = answer
	result.Display = display
	return result, nil
}

// auditDisabled audits EventOTPAuthenticatorDisabled when the refusal is the one that disabled the
// authenticator. Only the call whose count reached the limit reports it, so it is audited once; the
// submitter is answered as for any other refused code (#489).
func (o *OTPSubmission) auditDisabled(ctx context.Context, verified otpcredential.VerifyResult, userId int64) {
	if !verified.Disabled {
		return
	}
	o.auditLogger.Log(ctx, audit.EventOTPAuthenticatorDisabled, map[string]interface{}{
		"user_id": userId,
	})
}

// endLostEnrolment logs the lost enrolment and clears the ceremony, answering OTPEnrolmentLost with
// the clear's failure in SaveErr.
func (o *OTPSubmission) endLostEnrolment(ctx context.Context, browser otpSubmissionBrowser,
	result OTPSubmissionResult, userId int64, ceremonyId string) OTPSubmissionResult {

	slog.WarnContext(ctx, "the account's authenticator changed during the enrolment, so nothing was stored and the sign-in ends",
		"user_id", userId)

	result.Answer = OTPEnrolmentLost
	result.SaveErr = browser.ClearAuthContext(ceremonyId)
	return result
}
