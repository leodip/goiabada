package apihandlers

import (
	"bytes"
	"context"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
)

// The collaborator ports this package's handlers take, declared here rather than imported from
// the parent handlers package.
//
// This package used to name handlers.AuditLogger, handlers.HttpHelper and five more, which is the
// only reason 37 files here imported a transport package sitting above them. A port belongs to the
// side that calls it (#386), and declaring it here means each one names only the methods this
// package actually calls: PageRenderer is one method here against the parent's four. The concrete
// types the composition root builds satisfy these structurally, so routes.go is unchanged (#387).
// So do the parent's generated mocks, which live beside the parent's ports in
// internal/handlers/mocks, because every generated mock lives beside the interface it doubles;
// UserCreator's is accounthandlers' (#431).
//
// Per-file database ports stay per-file, beside the function taking them: the database is the
// dependency that genuinely varies from handler to handler, and these nine do not.

// AuditLogger records one security event. The context is first because every audit event raised
// while serving a request is correlated to that request: the installed slog handler reads chi's
// request id off it, so the console record joins the request's own log line, and the persisted row
// carries the same id. A call that passed context.Background() here would produce exactly the
// uncorrelated record this exists to prevent, which is why guard.AssertAuditLogContext refuses
// one in a request-path package (#328).
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// PageRenderer is one method wide here, and deliberately so. Every handler in this package answers
// JSON: a 500 is writeInternalServerError and a refusal is writeJSONError (#279 decision 7), so
// the page writers the parent's declaration carries have no caller here and are not named. The two
// sites that remain render an email body to a buffer, which is a template but not a response.
type PageRenderer interface {
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
}

// EmailSender delivers one message. The context is the request's, or the job's that a request
// handed its mail to (AfterResponse); either way it carries the request's id. The SMTP dial and
// conversation are bounded by the sender's own deadlines.
type EmailSender interface {
	SendEmail(ctx context.Context, smtpConfig emaildelivery.SMTPConfig, input *emaildelivery.SendEmailInput) error
}

// EmailValidator is the address check alone, which the settings email endpoints and user creation
// call. The two richer validations this package performs each have one caller, so each is a
// per-file port beside it: accountEmailValidator in handler_api_account_email.go and
// usersEmailValidator in handler_api_users_email.go, both naming ValidateEmailChange. Naming it
// here would widen this port past its callers.
type EmailValidator interface {
	ValidateEmailAddress(emailAddress string) error
}

// PasswordValidator checks a new password against the password policy the caller passes from its
// settings. Three handlers call it: user creation, an administrator setting a user's password, and
// the account's own password change.
type PasswordValidator interface {
	ValidatePassword(policy record.PasswordPolicy, password string) error
}

// UserCreator creates the user row and its default permissions in one transaction.
type UserCreator interface {
	CreateUser(ctx context.Context, input *usercreation.Input) (*record.User, error)
}

// CredentialFailureRecorder marks the credential check this request performed as failed, so
// the rate limiter charges the reservation it is holding instead of dropping it.
//
// A handler names no bucket and no key: the limiter chose those before the handler ran, and
// a handler that derived them again would be free to disagree with the limiter about which
// account the request is, which is exactly how the per-account tiers came to be worth
// nothing (#219). *middleware.RateLimiter satisfies it, and the call is a
// no-op on a request that carries no reservation.
type CredentialFailureRecorder interface {
	RecordCredentialFailure(r *http.Request)
}

// OtpSecretGenerator mints a TOTP key URL for an enrolment about to be offered. The stored
// credential itself belongs to internal/otpcredential; this is the stateless primitive that
// produces the seed (#387).
type OtpSecretGenerator interface {
	GenerateKeyURL(email string, appName string) (string, error)
}

// AfterResponse runs work a handler hands off so that its response does not wait for it. The job
// is given the context passed in, detached from its cancellation but keeping its values, so what it
// logs carries the request's id. The server's afterresponse.Jobs is the one implementation, and
// shutdown waits for the jobs it holds. The email change hands it the notice to the previous
// address, which must never fail or hold up the change it reports (#404 decision 11).
// Past 64 jobs in flight it drops the job with a warning rather than run it, so a flood costs
// some genuine requests their mail and never changes a response (#485).
type AfterResponse interface {
	Go(ctx context.Context, job func(ctx context.Context))
}
