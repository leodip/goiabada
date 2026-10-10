package accounthandlers

import (
	"context"
	"database/sql"
	"errors"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/core/inputvalidation"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/securerandom"
)

// refuseSelfRegistrationDisabled answers a self-registration page, or an activation link, while
// the setting is off: one Warn record and the not-found page.
//
// 404 is RFC 9110 section 15.5.5's status for a resource the server "is not willing to disclose
// that one exists", which is what a feature switched off is. It used to be the 500 page with an
// error-level stack, which alerted an operator for every visitor following an old link to a page
// the operator had turned off on purpose (#425 decision 5).
func refuseSelfRegistrationDisabled(pageRenderer PageRenderer, w http.ResponseWriter, r *http.Request) {
	slog.WarnContext(r.Context(), "self-registration request refused because self-registration is disabled")
	pageRenderer.NotFound(w, r)
}

// registrationCeremonyId is the sign-in the visitor came to this page from, when the password page's
// "Register" link said so: the id that link carried, if it has the shape of one. The page puts it back
// into its own "Sign in" link, so a visitor who registers nothing and goes back lands on the same
// sign-in's password form, where without it the link would load a step that names no ceremony and get
// the "no longer active" page (#246 decision 22).
//
// It is only ever echoed into a link, and never checked against a stored ceremony here, so a value
// that is not an id is dropped and not repeated into the page, whatever the visitor put in the query:
// a length and an alphabet that need no escaping and leave no room to smuggle a URL through. Empty
// means the page was reached from anywhere else, an emailed link or a bookmark, and its "Sign in" link
// stays bare.
func registrationCeremonyId(r *http.Request) string {
	id := r.URL.Query().Get(ceremony.QueryParameter)
	if !ceremony.IsWellFormedId(id) {
		return ""
	}
	return id
}

// registrationRequiresEmailVerification is the mode in which an account comes from the emailed
// link: SMTP on and "requires email verification" on. In it the register form asks for the
// address alone, and the password is chosen on the form the link leads to (#207 decision 1). In
// every other mode the form creates a usable account at once, and asks for the password.
func registrationRequiresEmailVerification(settings *record.Settings) bool {
	return settings.SMTPEnabled && settings.SelfRegistrationRequiresEmailVerification
}

func HandleRegisterGet(
	pageRenderer PageRenderer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SelfRegistrationEnabled {
			refuseSelfRegistrationDisabled(pageRenderer, w, r)
			return
		}

		bind := map[string]interface{}{
			"ceremonyId":                registrationCeremonyId(r),
			"requiresEmailVerification": registrationRequiresEmailVerification(settings),
		}

		err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
	}
}

// accountRegisterDatabase is what the self-registration page needs: the account and the pending
// registration an address may already have, the pending registration it writes for a new one, and
// the fresh code it gives a dead one.
type accountRegisterDatabase interface {
	CreatePreRegistration(ctx context.Context, tx *sql.Tx, preRegistration *record.PreRegistration) error
	GetPreRegistrationByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.PreRegistration, error)
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error)
	TryReplacePreRegistrationCode(ctx context.Context, tx *sql.Tx, preRegistrationId int64, deadCodeHash string,
		codeEncrypted []byte, codeHash string, issuedAt time.Time) (bool, error)
}

// livePreRegistration is the pending registration a lookup found, or nil when it found none or a
// dead one: every reader treats a registration that can no longer complete as absent (#207
// decision 6).
func livePreRegistration(preRegistration *record.PreRegistration, now time.Time) *record.PreRegistration {
	if preRegistration == nil || emaillinks.IsPreRegistrationDead(preRegistration.VerificationCodeIssuedAt.Time, now) {
		return nil
	}
	return preRegistration
}

// The outcomes a registration with verification is recorded with, one per request, in the
// requested_registration entry (#207 decision 8). Every well-formed request is answered with the
// same "check your email" page whichever of these it was, so the entry is the only place the
// difference is visible.
const (
	// registrationOutcomeLinkIssued is a new pending registration written, or a dead one given
	// a fresh code, and its link issued. It says the row was written, not that the mail went
	// out: the entry is written before the send, and a send failure is an Error log line on the
	// same request id.
	registrationOutcomeLinkIssued = "link_issued"
	// registrationOutcomeLinkPending is an address whose pending registration can still
	// complete, for which nothing is sent.
	registrationOutcomeLinkPending = "link_pending"
	// registrationOutcomeNoticeIssued is a verified, enabled account, mailed the notice that it
	// already exists. Written before the send, as link_issued is.
	registrationOutcomeNoticeIssued = "notice_issued"
	// registrationOutcomeUnverifiedAddress is an enabled account whose address was never
	// verified, to which nothing is sent, as forgot-password sends it nothing.
	registrationOutcomeUnverifiedAddress = "unverified_address"
	// registrationOutcomeAccountDisabled is a disabled account, verified or not.
	registrationOutcomeAccountDisabled = "account_disabled"
	// registrationOutcomeReplacementLost is a dead pending registration whose replacement the
	// conditional write declined, because a concurrent repeat replaced it first or it was
	// consumed or swept meanwhile, for which nothing is sent (#207 decision 6).
	registrationOutcomeReplacementLost = "replacement_lost"
	// registrationOutcomeInvalidAddress is a submission the format or length check refused,
	// answered with the form redrawn and looking nothing up.
	registrationOutcomeInvalidAddress = "invalid_address"
	// registrationOutcomeServerError is a request the server failed before deciding it: a
	// lookup, or the code's encryption or the pending registration's write or replacement. The
	// cause is the Error log line on the same request id.
	registrationOutcomeServerError = "server_error"
)

// auditRequestedRegistration writes the one requested_registration entry a registration with
// verification leaves.
//
// The address is digested rather than recorded, as requested_password_reset digests it, so the
// table does not collect every address typed into an unauthenticated form. user_id is absent, not
// zero, when no account matched, and pre_registration_id when no pending registration was written
// or found (#207 decision 8).
//
// It takes the context rather than the request because a well-formed request's entry is written
// by the job after its response, under the job's context, which keeps the request's id.
func auditRequestedRegistration(ctx context.Context, auditLogger AuditLogger, clientIP string, email string,
	userId int64, preRegistrationId int64, outcome string) {
	details := map[string]interface{}{
		"ip":           clientIP,
		"email_digest": hashutil.HashString(email),
		"outcome":      outcome,
	}
	if userId != 0 {
		details["user_id"] = userId
	}
	if preRegistrationId != 0 {
		details["pre_registration_id"] = preRegistrationId
	}
	auditLogger.Log(ctx, audit.EventRequestedRegistration, details)
}

// HandleRegisterPost registers an address.
//
// With email verification (registrationRequiresEmailVerification) it answers every well-formed
// address alike: the format and length checks, then both lookups, every time and whatever the
// first one found, then the one "check your email" page. Everything that depends on what the
// lookups found, the decision, the pending registration's write, the audit entry, the render and
// the send, runs in a job after the response, so a new address costs the response nothing an
// address with an account does not, and a mail that fails to send is an Error record on the
// request's id rather than a 500 only a new address could get (#207 decision 4). A malformed
// address is answered, and audited, at once, since its redrawn form is visibly different anyway,
// and so is a lookup that failed, whose 500 says nothing about the address.
//
// Without it the form creates a usable account at once, so whether an address has one cannot be
// hidden, and a taken address is told so (#207 decision 3).
func HandleRegisterPost(
	pageRenderer PageRenderer,
	database accountRegisterDatabase,
	userCreator UserCreator,
	emailValidator EmailValidator,
	passwordValidator PasswordValidator,
	emailSender EmailSender,
	auditLogger AuditLogger,
	afterResponse AfterResponse,
	dataCipher *encryption.DataCipher,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SelfRegistrationEnabled {
			refuseSelfRegistrationDisabled(pageRenderer, w, r)
			return
		}

		requiresEmailVerification := registrationRequiresEmailVerification(settings)

		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		clientIP := auditedClientIP(r)

		// recordRequest writes this request's requested_registration entry, which only registration
		// with verification leaves. Without it the request is recorded as created_user, or not at all.
		recordRequest := func(userId int64, outcome string) {
			if requiresEmailVerification {
				auditRequestedRegistration(r.Context(), auditLogger, clientIP, email, userId, 0, outcome)
			}
		}

		renderError := func(message string) {
			// The form posts to action="", so the URL the visitor arrived at, ceremony parameter
			// included, is the one this request has, and the re-render carries the id on.
			bind := map[string]interface{}{
				"email":                     email,
				"error":                     message,
				"ceremonyId":                registrationCeremonyId(r),
				"requiresEmailVerification": requiresEmailVerification,
			}

			err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
		}

		// refuseAddress redraws the form for an address the format or length check refused.
		refuseAddress := func(message string) {
			recordRequest(0, registrationOutcomeInvalidAddress)
			renderError(message)
		}

		if len(email) == 0 {
			// i18n surface: A — browser-flow form rerender.
			refuseAddress(i18n.NewLocalizedError(i18n.ErrCodeHandlerEmailRequired, nil).Localize(r.Context()))
			return
		}

		err := emailValidator.ValidateEmailAddress(email)
		if err != nil {
			// i18n surface: A — browser-flow form rerender.
			// errors.As in the switch's own order, not a type switch: both read the dynamic type,
			// so anything that wrapped the validator's result on the way here would fall through
			// to default and answer a 500 page rather than redrawing the form with the reason
			// (#279 decision 6).
			var localizedErr *i18n.LocalizedError
			var errorDetail *oauth.ErrorDetail
			switch {
			case errors.As(err, &localizedErr):
				refuseAddress(localizedErr.Localize(r.Context()))
			case errors.As(err, &errorDetail):
				refuseAddress(errorDetail.Description())
			default:
				recordRequest(0, registrationOutcomeServerError)
				pageRenderer.InternalServerError(w, r, err)
			}
			return
		}

		// The limit the administrator's and the self-service email change apply, checked with the
		// shape and before either lookup. Without it an address the columns cannot hold answered
		// the 500 page on MySQL, PostgreSQL and SQL Server and registered on SQLite (#207 decision
		// 11). The shape admits ASCII alone, so the byte length is the character count.
		if inputvalidation.TextLength(email) > accountvalidation.MaxEmailLength {
			// i18n surface: A — browser-flow form rerender.
			refuseAddress(i18n.NewLocalizedError(i18n.ErrCodeEmailTooLong,
				map[string]any{"max": accountvalidation.MaxEmailLength}).Localize(r.Context()))
			return
		}

		if requiresEmailVerification {
			registerWithVerification(w, r, pageRenderer, database, emailSender, auditLogger, afterResponse,
				dataCipher, baseURL, settings, clientIP, email)
			return
		}

		alreadyRegisteredMessage := i18n.NewLocalizedError(i18n.ErrCodeEmailAlreadyRegistered, nil).Localize(r.Context())

		user, err := database.GetUserByEmail(r.Context(), nil, email)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if user != nil {
			renderError(alreadyRegisteredMessage)
			return
		}

		// A pending registration keeps the address taken only while it can still complete: a dead
		// one is treated as absent, as every reader treats it (#207 decision 6).
		preRegistration, err := database.GetPreRegistrationByEmail(r.Context(), nil, email)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if livePreRegistration(preRegistration, time.Now().UTC()) != nil {
			renderError(alreadyRegisteredMessage)
			return
		}

		// r.PostFormValue rather than r.FormValue: r.Form merges the URL query behind the
		// body, so /account/register?password=... would register an account with a password
		// taken from a request target, where it reaches the browser's history, the Referer of
		// anything the page loads, and the access log of every proxy in front of the
		// deployment. Only the submitted body is a submission (#202). The email read above
		// keeps the merged accessor: it is not a credential, and the rate limiter derives its
		// per-account key from the same accessor, so the two must not diverge (#219).
		password := r.PostFormValue("password")
		passwordConfirmation := r.PostFormValue("passwordConfirmation")

		// i18n surface: A — browser-flow form rerender.
		if len(password) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordRequired, nil).Localize(r.Context()))
			return
		}

		if len(password) > 0 && len(passwordConfirmation) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordConfirmationRequired, nil).Localize(r.Context()))
			return
		}

		if password != passwordConfirmation {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordConfirmationMismatch, nil).Localize(r.Context()))
			return
		}

		err = passwordValidator.ValidatePassword(settings.PasswordPolicy, password)
		if err != nil {
			// i18n surface: A — browser-flow form rerender.
			var locErr *i18n.LocalizedError
			if errors.As(err, &locErr) {
				renderError(locErr.Localize(r.Context()))
			} else {
				renderError(err.Error())
			}
			return
		}

		passwordHash, err := passwordhash.Hash(password)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		_, err = userCreator.CreateUser(r.Context(), &usercreation.Input{
			Email:         email,
			EmailVerified: false,
			PasswordHash:  passwordHash,
		})
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.EventCreatedUser, map[string]interface{}{
			"email": email,
		})

		if settings.SMTPEnabled {
			bind := map[string]interface{}{
				"link": adminConsoleBaseURL + "/account/profile",
			}
			// Recipient is the freshly-created user; no stored Locale yet,
			// so the welcome email uses the locale they registered in.
			emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, i18n.LocaleTag(r.Context())))
			buf, emailErr := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_register_confirmation.html", bind)
			if emailErr != nil {
				pageRenderer.InternalServerError(w, r, emailErr)
				return
			}

			input := &emaildelivery.SendEmailInput{
				To:       email,
				Subject:  i18n.T(emailReq.Context(), "email.register_confirmation.subject"),
				HtmlBody: buf.String(),
			}
			emailErr = emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input)
			if emailErr != nil {
				pageRenderer.InternalServerError(w, r, emailErr)
				return
			}
		}

		bind := map[string]interface{}{
			"adminConsoleBaseUrl": adminConsoleBaseURL,
		}
		err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_success.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}

// registerWithVerification answers a well-formed address in the mode with verification: both
// lookups, every time and whatever the first found, then the one "check your email" page, and the
// rest handed to a job that runs after the response (#207 decision 4). No password is read: the
// person who follows the emailed link chooses it (#207 decision 1).
func registerWithVerification(
	w http.ResponseWriter,
	r *http.Request,
	pageRenderer PageRenderer,
	database accountRegisterDatabase,
	emailSender EmailSender,
	auditLogger AuditLogger,
	afterResponse AfterResponse,
	dataCipher *encryption.DataCipher,
	baseURL string,
	settings *record.Settings,
	clientIP string,
	email string,
) {
	user, err := database.GetUserByEmail(r.Context(), nil, email)
	if err != nil {
		auditRequestedRegistration(r.Context(), auditLogger, clientIP, email, 0, 0, registrationOutcomeServerError)
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	// Looked up whatever the first lookup found, so an address with an account and one without
	// cost the response the same two queries.
	preRegistration, err := database.GetPreRegistrationByEmail(r.Context(), nil, email)
	if err != nil {
		var userId int64
		if user != nil {
			userId = user.Id
		}
		auditRequestedRegistration(r.Context(), auditLogger, clientIP, email, userId, 0, registrationOutcomeServerError)
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	bind := map[string]interface{}{
		"email": email,
	}
	err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_check_email.html", bind)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}

	afterResponse.Go(r.Context(), afterresponse.ClassRegistration, func(ctx context.Context) {
		finishRegistration(ctx, r, database, emailSender, auditLogger, pageRenderer, dataCipher, baseURL,
			settings, clientIP, email, user, preRegistration)
	})
}

// finishRegistration is the work after a well-formed registration's response: it decides what
// becomes of the request, records that, and mails a new address its link or a verified, enabled
// account the notice. ctx is the job's, detached from the request's cancellation and carrying its
// id, so every failure here is an Error record on that id: the registrant has already been
// answered, and is told nothing different (#207 decision 4).
//
// r is the request the job was started from, read for nothing but the renderer's inputs. Its
// context is replaced by ctx before anything reads it, since the request's own is cancelled once
// the response has gone.
func finishRegistration(
	ctx context.Context,
	r *http.Request,
	database accountRegisterDatabase,
	emailSender EmailSender,
	auditLogger AuditLogger,
	pageRenderer PageRenderer,
	dataCipher *encryption.DataCipher,
	baseURL string,
	settings *record.Settings,
	clientIP string,
	email string,
	user *record.User,
	preRegistration *record.PreRegistration,
) {
	var userId, preRegistrationId int64
	if user != nil {
		userId = user.Id
	}
	if preRegistration != nil {
		preRegistrationId = preRegistration.Id
	}

	switch {
	case user != nil && !user.Enabled:
		auditRequestedRegistration(ctx, auditLogger, clientIP, email, userId, preRegistrationId,
			registrationOutcomeAccountDisabled)
	case user != nil && !canRecoverPassword(user):
		// The rule forgot-password applies, so the two flows share one eligibility rule: the
		// notice points at password recovery, which sends an unverified address nothing (#207
		// decision 5).
		auditRequestedRegistration(ctx, auditLogger, clientIP, email, userId, preRegistrationId,
			registrationOutcomeUnverifiedAddress)
	case user != nil:
		auditRequestedRegistration(ctx, auditLogger, clientIP, email, userId, preRegistrationId,
			registrationOutcomeNoticeIssued)
		sendExistingAccountNotice(ctx, r, emailSender, pageRenderer, baseURL, settings, user)
	case livePreRegistration(preRegistration, time.Now().UTC()) != nil:
		// It can still complete, so its link is still the one that completes it, and replacing
		// it would change the code under a form already on screen (#207 decision 6).
		auditRequestedRegistration(ctx, auditLogger, clientIP, email, 0, preRegistrationId,
			registrationOutcomeLinkPending)
	default:
		// No pending registration, or a dead one, which this replaces.
		issueActivationLink(ctx, r, database, emailSender, auditLogger, pageRenderer, dataCipher, baseURL,
			settings, clientIP, email, preRegistration)
	}
}

// issueActivationLink writes a new address's pending registration, or gives a dead one a fresh
// code, and mails its link.
//
// dead is the pending registration the lookup found and judged dead, or nil when it found none.
// Its replacement is conditional on the row still holding the dead code, so of two repeats racing
// for it exactly one sends a link; the other is recorded as replacement_lost and sends nothing
// (#207 decision 6).
func issueActivationLink(
	ctx context.Context,
	r *http.Request,
	database accountRegisterDatabase,
	emailSender EmailSender,
	auditLogger AuditLogger,
	pageRenderer PageRenderer,
	dataCipher *encryption.DataCipher,
	baseURL string,
	settings *record.Settings,
	clientIP string,
	email string,
	dead *record.PreRegistration,
) {
	var deadId int64
	if dead != nil {
		deadId = dead.Id
	}

	verificationCode := securerandom.String(32)
	verificationCodeEncrypted, err := dataCipher.Encrypt(verificationCode)
	if err != nil {
		slog.ErrorContext(ctx, "unable to encrypt the activation code", "error", err)
		auditRequestedRegistration(ctx, auditLogger, clientIP, email, 0, deadId, registrationOutcomeServerError)
		return
	}

	// The hash is how the activation link finds this row again, since the link carries the code
	// and no email address (#112). The encryption above stays: it is what proves a submitted code
	// matches, where the hash only locates the row.
	preRegistration := &record.PreRegistration{
		Email:                     email,
		VerificationCodeEncrypted: verificationCodeEncrypted,
		VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
		VerificationCodeHash:      hashutil.HashString(verificationCode),
	}
	if dead == nil {
		err = database.CreatePreRegistration(ctx, nil, preRegistration)
		if err != nil {
			slog.ErrorContext(ctx, "unable to store the pending registration", "error", err)
			auditRequestedRegistration(ctx, auditLogger, clientIP, email, 0, 0, registrationOutcomeServerError)
			return
		}
	} else {
		var replaced bool
		replaced, err = database.TryReplacePreRegistrationCode(ctx, nil, dead.Id, dead.VerificationCodeHash,
			preRegistration.VerificationCodeEncrypted, preRegistration.VerificationCodeHash,
			preRegistration.VerificationCodeIssuedAt.Time)
		if err != nil {
			slog.ErrorContext(ctx, "unable to replace the dead pending registration", "pre_registration_id", dead.Id,
				"error", err)
			auditRequestedRegistration(ctx, auditLogger, clientIP, email, 0, dead.Id, registrationOutcomeServerError)
			return
		}
		if !replaced {
			auditRequestedRegistration(ctx, auditLogger, clientIP, email, 0, dead.Id, registrationOutcomeReplacementLost)
			return
		}
		preRegistration.Id = dead.Id
	}
	auditRequestedRegistration(ctx, auditLogger, clientIP, email, 0, preRegistration.Id,
		registrationOutcomeLinkIssued)

	bind := map[string]interface{}{
		// The code and nothing else: the address used to travel here too, which broke every '+'
		// and '%xx' address under form-urlencoded query parsing (#112). The helper also owns the
		// path the activation handler redirects back to, so the two cannot drift.
		"link": emaillinks.AccountActivateLink(baseURL, verificationCode),
	}
	// The address has no account and so no stored locale; the mail is rendered in the locale the
	// registration was made in, which ctx carries from the request.
	emailReq := r.WithContext(i18n.WithLocale(ctx, true, i18n.LocaleTag(ctx)))
	buf, err := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_register_activate.html", bind)
	if err != nil {
		slog.ErrorContext(ctx, "unable to render the activation email", "pre_registration_id", preRegistration.Id, "error", err)
		return
	}

	input := &emaildelivery.SendEmailInput{
		To:       email,
		Subject:  i18n.T(emailReq.Context(), "email.register_activate.subject"),
		HtmlBody: buf.String(),
	}
	err = emailSender.SendEmail(ctx, emaildelivery.SMTPConfigFromSettings(settings), input)
	if err != nil {
		slog.ErrorContext(ctx, "unable to send the activation email", "pre_registration_id", preRegistration.Id, "error", err)
	}
}

// sendExistingAccountNotice mails a verified, enabled account that someone tried to register its
// address: nothing was created, and the holder can sign in or reset the password from the
// forgot-password page (#207 decisions 5 and 13). It carries no code and no credential, and is
// rendered in the account's stored locale, falling back to English, as the reset mail is.
func sendExistingAccountNotice(
	ctx context.Context,
	r *http.Request,
	emailSender EmailSender,
	pageRenderer PageRenderer,
	baseURL string,
	settings *record.Settings,
	user *record.User,
) {
	bind := map[string]interface{}{
		"link": baseURL + emaillinks.ForgotPasswordPath,
	}
	emailReq := r.WithContext(i18n.WithLocale(ctx, true, user.Locale, "en"))
	buf, err := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_register_existing_account.html", bind)
	if err != nil {
		slog.ErrorContext(ctx, "unable to render the existing account notice", "user_id", user.Id, "error", err)
		return
	}

	input := &emaildelivery.SendEmailInput{
		To:       user.Email,
		Subject:  i18n.T(emailReq.Context(), "email.register_existing_account.subject"),
		HtmlBody: buf.String(),
	}
	err = emailSender.SendEmail(ctx, emaildelivery.SMTPConfigFromSettings(settings), input)
	if err != nil {
		slog.ErrorContext(ctx, "unable to send the existing account notice", "user_id", user.Id, "error", err)
	}
}
