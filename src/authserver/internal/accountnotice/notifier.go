// Package accountnotice is the one notifier that emails a user about a change to their account:
// the email change's notice to the previous address (#404 decisions 9 and 11), and the security
// notices that tell a user their password was changed, by them or an administrator, or reset, that
// their two-factor authentication was set up or turned off, that their authenticator was disabled
// after too many wrong codes, that a recovery code signed in, that a new set of recovery codes
// was made (#724, #737), and that they or an administrator deleted their account (#783).
//
// Every notice follows the same rules, which is why they live here once rather than beside each
// handler. A handler calls Send after its change has committed, and only for the request whose
// write landed. Send hands the notice to a job that runs after the response, so the change never
// waits for the mail or fails with it. Nothing is sent with SMTP off, or to an address the account
// has not verified: an address is verified only with a code read from its own mailbox, so a notice
// cannot be used to mail an arbitrary address on demand (#404). The notice is written in the
// recipient's language (i18n.WithRecipientLanguage), from its built-in definition in
// internal/emailtemplate (#818), greets a user with no name by the address it is sent to, carries
// no link that acts on the account and no password, code or secret, and says when through the
// email's own Date header. A notice that
// cannot be rendered or sent is one Error record on the request's id, and writes no audit entry.
package accountnotice

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
)

// errUnknownNotice is a Notice that deliver has no email for, which only a new constant added
// without its case can be.
var errUnknownNotice = errors.New("no email for this notice")

// Renderer renders a notice from its built-in definition as the message its recipient receives.
// The request it is handed carries the recipient's language and the job's context; nothing else of
// it is read but the settings and the brand of the page it was sent from.
type Renderer interface {
	RenderEmail(r *http.Request, email *emailtemplate.Email, values emailtemplate.Values) (emailtemplate.Message, error)
}

// Sender delivers one message, under the job's context, which carries the request's id. The SMTP
// dial and conversation are bounded by the sender's own deadlines.
type Sender interface {
	SendEmail(ctx context.Context, smtpConfig emaildelivery.SMTPConfig, input *emaildelivery.SendEmailInput) (emaildelivery.SendResult, error)
}

// Jobs runs a job after the response, under the request's context detached from its cancellation.
// The server's afterresponse.Jobs is the one implementation: past 64 jobs of one class in flight it
// drops the job with a warning and counts it, rather than run it (#485).
type Jobs interface {
	Go(ctx context.Context, class afterresponse.Class, job func(ctx context.Context))
}

// Notice is one kind of notice. Its value names it in a log record, a closed set of literals, and is
// the identifier of its email's definition (#818 decision 6).
type Notice string

const (
	// EmailAddressChanged tells the address an account had that it was changed. It names neither
	// the new address, which whoever reads the old mailbox has no business learning, nor carries a
	// link. It keeps ClassAccountNotice, a budget of its own: once an attacker changes the address,
	// every later notice goes to their own unverified address, so this one is the victim's only
	// warning (#394 review, #724 decision 4).
	EmailAddressChanged Notice = "email_address_changed"
	// PasswordChanged tells a user their password was changed on the Account pages (#724).
	PasswordChanged Notice = "password_changed"
	// PasswordChangedByAdministrator tells a user an administrator replaced their password. A
	// first password, set on an account whose setup link is pending, is not replaced and sends
	// none (#724 decision 6).
	PasswordChangedByAdministrator Notice = "password_changed_by_administrator"
	// PasswordReset tells a user their password was reset through a forgot-password link. The
	// setup link an administrator emails a new user sets a first password and sends none (#724).
	PasswordReset Notice = "password_reset"
	// OTPEnabled tells a user an authenticator was set up for their account, on the Account pages
	// or while signing in, and mentions the set of recovery codes it came with, so that one event
	// sends one email (#724 decision 1). Only the user can set one up.
	OTPEnabled Notice = "otp_enabled"
	// OTPDisabled tells a user they turned two-factor authentication off on the Account pages.
	OTPDisabled Notice = "otp_disabled"
	// OTPDisabledByAdministrator tells a user an administrator turned their two-factor
	// authentication off.
	OTPDisabledByAdministrator Notice = "otp_disabled_by_administrator"
	// OTPLockout tells a user their authenticator was disabled after record.OtpConsecutiveFailureLimit
	// wrong codes in a row, at sign-in or confirming the account's deletion, which only someone holding the password reaches (#489, #724
	// decision 7). The refusal that disabled it sends it, so it goes once per lockout.
	OTPLockout Notice = "otp_lockout"
	// RecoveryCodeUsed tells a user a recovery code signed in, with how many unused codes are left
	// (#737), as {{codes_left}}. SendRecoveryCodeUsed sends it, since it carries the count.
	RecoveryCodeUsed Notice = "recovery_code_used"
	// RecoveryCodesReplaced tells a user a new set of recovery codes was made on the Account pages,
	// which voids the old set (#737). The set an authenticator comes with is OTPEnabled's.
	RecoveryCodesReplaced Notice = "recovery_codes_replaced"
	// AccountDeleted tells a user they deleted their own account on the Account pages (#783
	// decision 9). The recipient is captured from the row the deletion's transaction read, so the
	// job needs nothing of the account, which is gone by the time it runs.
	AccountDeleted Notice = "account_deleted"
	// AccountDeletedByAdministrator tells a user an administrator deleted their account, naming no
	// administrator (#783 decision 10). Like AccountDeleted, the recipient is captured from the row
	// the deletion's transaction read.
	AccountDeletedByAdministrator Notice = "account_deleted_by_administrator"
)

// class is the job class whose budget the notice is admitted against: every notice but the email
// change's is a security notice.
func (notice Notice) class() afterresponse.Class {
	if notice == EmailAddressChanged {
		return afterresponse.ClassAccountNotice
	}
	return afterresponse.ClassSecurityNotice
}

// Recipient is the address a notice goes to and the user it is about. The address and its verified
// flag are what the change's write matched, which for the email change is the address the account
// had, not the one it has now. For every other notice it is the user's row as the transaction that
// committed the change read it under the row's lock, never a read from before it, so an address
// changed, verified or unverified while the request ran is answered as the change found it.
type Recipient struct {
	UserId        int64
	Email         string
	EmailVerified bool
	Name          string
	// PageLanguage and Locale choose the notice's language: the page language, else the locale,
	// else English.
	PageLanguage string
	Locale       string
}

// To is the account's own address, as user holds it.
func To(user *record.User) Recipient {
	return Recipient{
		UserId:        user.Id,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.FullName(),
		PageLanguage:  user.PageLanguage,
		Locale:        user.Locale,
	}
}

// Notifier sends the notices. routes.go builds the one the handlers take.
type Notifier struct {
	renderer Renderer
	sender   Sender
	jobs     Jobs
}

// New builds the notifier over the server's renderer, mail sender and after-response jobs.
func New(renderer Renderer, sender Sender, jobs Jobs) *Notifier {
	return &Notifier{renderer: renderer, sender: sender, jobs: jobs}
}

// Send hands notice to a job that sends it to to after the response, when the request's settings
// have SMTP enabled and the address is verified, and does nothing otherwise. The caller calls it
// once its change has committed.
func (n *Notifier) Send(r *http.Request, notice Notice, to Recipient) {
	n.send(r, notice, to, 0)
}

// SendRecoveryCodeUsed sends RecoveryCodeUsed as Send does, saying that remaining unused recovery
// codes are left. The count is not a secret: the Account pages show it.
func (n *Notifier) SendRecoveryCodeUsed(r *http.Request, to Recipient, remaining int) {
	n.send(r, RecoveryCodeUsed, to, remaining)
}

// send is Send with the codes left, which only RecoveryCodeUsed reads.
func (n *Notifier) send(r *http.Request, notice Notice, to Recipient, codesLeft int) {
	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		slog.ErrorContext(r.Context(), "unable to send an account notice",
			"notice", string(notice), "user_id", to.UserId, "error", reqctx.ErrNoSettings)
		return
	}
	if !settings.SMTPEnabled || !to.EmailVerified {
		return
	}

	smtpConfig := emaildelivery.SMTPConfigFromSettings(settings)
	n.jobs.Go(r.Context(), notice.class(), func(ctx context.Context) {
		n.deliver(ctx, r, notice, to, codesLeft, smtpConfig)
	})
}

// emailOf answers the built-in definition notice is sent from, nil for none.
func emailOf(notice Notice) *emailtemplate.Email {
	switch notice {
	case EmailAddressChanged:
		return emailtemplate.EmailAddressChanged
	case PasswordChanged:
		return emailtemplate.PasswordChanged
	case PasswordChangedByAdministrator:
		return emailtemplate.PasswordChangedByAdministrator
	case PasswordReset:
		return emailtemplate.PasswordReset
	case OTPEnabled:
		return emailtemplate.OTPEnabled
	case OTPDisabled:
		return emailtemplate.OTPDisabled
	case OTPDisabledByAdministrator:
		return emailtemplate.OTPDisabledByAdministrator
	case OTPLockout:
		return emailtemplate.OTPLockout
	case RecoveryCodeUsed:
		return emailtemplate.RecoveryCodeUsed
	case RecoveryCodesReplaced:
		return emailtemplate.RecoveryCodesReplaced
	case AccountDeleted:
		return emailtemplate.AccountDeleted
	case AccountDeletedByAdministrator:
		return emailtemplate.AccountDeletedByAdministrator
	}
	return nil
}

// deliver renders and sends one notice, in the job: its email's built-in text in the recipient's
// language, {{name}} the recipient's name or, for one with none, the address it is sent to, which
// for the email change is the previous address, so the new one is never shown (#818 decision 15).
func (n *Notifier) deliver(ctx context.Context, r *http.Request, notice Notice, to Recipient,
	codesLeft int, smtpConfig emaildelivery.SMTPConfig) {
	email := emailOf(notice)
	if email == nil {
		slog.ErrorContext(ctx, "unable to render an account notice",
			"notice", string(notice), "user_id", to.UserId, "error", errUnknownNotice)
		return
	}

	// The request is read for nothing but the renderer's inputs, under the job's context: the
	// request's own is cancelled once the response has gone.
	emailReq := r.WithContext(i18n.WithRecipientLanguage(ctx, to.PageLanguage, to.Locale))
	message, err := n.renderer.RenderEmail(emailReq, email, emailtemplate.Values{
		Name:      emailtemplate.RecipientName(to.Name, to.Email),
		CodesLeft: codesLeft,
	})
	if err != nil {
		slog.ErrorContext(ctx, "unable to render an account notice",
			"notice", string(notice), "user_id", to.UserId, "error", err)
		return
	}

	input := &emaildelivery.SendEmailInput{
		To:       to.Email,
		Subject:  message.Subject,
		HtmlBody: message.HTML,
	}
	if _, err := n.sender.SendEmail(ctx, smtpConfig, input); err != nil {
		slog.ErrorContext(ctx, "unable to send an account notice",
			"notice", string(notice), "user_id", to.UserId, "error", err)
	}
}
