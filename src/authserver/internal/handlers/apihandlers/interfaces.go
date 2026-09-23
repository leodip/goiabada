package apihandlers

import (
	"bytes"
	"context"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
)

// The collaborator ports this package's handlers take, declared here rather than imported from
// the parent handlers package.
//
// This package used to name handlers.AuditLogger, handlers.HttpHelper and five more, which is the
// only reason 37 files here imported a transport package sitting above them. A port belongs to the
// side that calls it (#386), and declaring it here means each one names only the methods this
// package actually calls: HttpHelper is one method here against the parent's eight. The concrete
// types the composition root builds satisfy these structurally, so routes.go is unchanged, and so
// do the generated mocks, which mockery still emits into the packages that own the
// implementations (#387).
//
// Per-file database ports stay per-file, beside the function taking them: the database is the
// dependency that genuinely varies from handler to handler, and these eight do not.

// AuditLogger records one security event. The context is first because every audit event raised
// while serving a request is correlated to that request: the installed slog handler reads chi's
// request id off it, so the console record joins the request's own log line, and the persisted row
// carries the same id. A call that passed context.Background() here would produce exactly the
// uncorrelated record this exists to prevent, which is why testutil.AssertAuditLogContext refuses
// one in a request-path package (#328).
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// HttpHelper is one method wide here, and deliberately so. Every handler in this package answers
// JSON: a 500 is writeInternalServerError and a refusal is writeJSONError (#279 decision 7), so
// the page writers the parent's declaration carries have no caller here and are not named. The two
// sites that remain render an email body to a buffer, which is a template but not a response.
type HttpHelper interface {
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
}

// EmailSender delivers one message. The context is the request's, so the SMTP dial and write are
// bounded by the request that asked for them.
type EmailSender interface {
	SendEmail(ctx context.Context, input *emaildelivery.SendEmailInput) error
}

// EmailValidator is the address check alone, which the settings email endpoints and user creation
// call. The two richer validations this package performs each have one caller, so each is a
// per-file port beside it: accountEmailValidator (ValidateEmailChange) in
// handler_api_account_email.go and usersEmailValidator (ValidateEmailUpdate) in
// handler_api_users_email.go. Naming them here would widen this port past its callers.
type EmailValidator interface {
	ValidateEmailAddress(emailAddress string) error
}

// PasswordValidator checks a new password against the password policy in the request's
// settings. Three handlers call it: user creation, an administrator setting a user's password, and
// the account's own password change.
type PasswordValidator interface {
	ValidatePassword(ctx context.Context, password string) error
}

// UserCreator creates the user row and its default permissions in one transaction.
type UserCreator interface {
	CreateUser(ctx context.Context, input *usercreation.CreateUserInput) (*models.User, error)
}

// CredentialFailureRecorder marks the credential check this request performed as failed, so
// the rate limiter charges the reservation it is holding instead of dropping it.
//
// A handler names no bucket and no key: the limiter chose those before the handler ran, and
// a handler that derived them again would be free to disagree with the limiter about which
// account the request is, which is exactly how the per-account tiers came to be worth
// nothing (#219). *middleware.RateLimiterMiddleware satisfies it, and the call is a
// no-op on a request that carries no reservation.
type CredentialFailureRecorder interface {
	RecordCredentialFailure(r *http.Request)
}

// OtpSecretGenerator mints a TOTP key URL for an enrolment about to be offered. The stored
// credential itself belongs to internal/otpcredential; this is the stateless primitive that
// produces the seed (#387).
type OtpSecretGenerator interface {
	GenerateOTPSecret(email string, appName string) (string, error)
}
