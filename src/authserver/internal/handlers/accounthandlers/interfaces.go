package accounthandlers

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
)

// The collaborator ports this package's handlers take, declared here rather than imported from
// the parent handlers package.
//
// handler_account_activate.go and handler_account_register.go named handlers.HttpHelper,
// handlers.AuditLogger and four more, which is the only reason this package imported a transport
// package sitting above it. A port belongs to the side that calls it (#386), so each of these
// names only what this package's files call: PageRenderer carries the same four page methods as
// the parent's. The concrete types the composition root builds satisfy them structurally, and so
// do the generated mocks (#387). The forgot and reset password handlers moved here in #435 and
// named no port these did not already declare.
//
// Per-file database ports stay per-file, beside the function taking them: the database is the
// dependency that genuinely varies from handler to handler, and these six do not.

// AuditLogger records one security event. The context is first because every audit event raised
// while serving a request is correlated to that request: the installed slog handler reads chi's
// request id off it, so the console record joins the request's own log line, and the persisted row
// carries the same id. A call that passed context.Background() here would produce exactly the
// uncorrelated record this exists to prevent, which is why guard.AssertAuditLogContext refuses
// one in a request-path package (#328).
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// PageRenderer renders this package's pages and its two email bodies. These handlers answer
// HTML, so unlike apihandlers they name every page writer. NotFound answers every
// self-registration page while the feature is off (#425).
type PageRenderer interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	NotFound(w http.ResponseWriter, r *http.Request)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
}

// EmailSender delivers one message. The context is the request's, or the job's that a request
// handed its mail to (AfterResponse); either way it carries the request's id. The SMTP dial and
// conversation are bounded by the sender's own deadlines.
type EmailSender interface {
	SendEmail(ctx context.Context, smtpConfig emaildelivery.SMTPConfig, input *emaildelivery.SendEmailInput) error
}

// EmailValidator is the address check alone, which is the only validation self-registration
// performs through a port.
type EmailValidator interface {
	ValidateEmailAddress(emailAddress string) error
}

// PasswordValidator holds a chosen password to the configured policy.
type PasswordValidator interface {
	ValidatePassword(policy record.PasswordPolicy, password string) error
}

// UserCreator creates the user row and its default permissions in one transaction.
type UserCreator interface {
	CreateUser(ctx context.Context, input *usercreation.Input) (*record.User, error)
}

// TransactionalUserCreator creates the user row and its default permissions on the caller's
// transaction, so activation commits the account and the consumption of its pending registration
// together or neither (#207).
type TransactionalUserCreator interface {
	CreateUserInTransaction(ctx context.Context, tx *sql.Tx, input *usercreation.Input) (*record.User, error)
}

// AfterResponse runs work a handler hands off so that its response does not wait for it. The job
// is given the context passed in, detached from its cancellation but keeping its values, so what it
// records carries the request's id (#404 decision 8). The server's afterresponse.Jobs is the one
// implementation, and shutdown waits for the jobs it holds.
type AfterResponse interface {
	Go(ctx context.Context, job func(ctx context.Context))
}
