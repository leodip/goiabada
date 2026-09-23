package accounthandlers

import (
	"bytes"
	"context"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
)

// The collaborator ports this package's two handlers take, declared here rather than imported
// from the parent handlers package.
//
// handler_account_activate.go and handler_account_register.go named handlers.HttpHelper,
// handlers.AuditLogger and four more, which is the only reason this package imported a transport
// package sitting above it. A port belongs to the side that calls it (#386), so each of these
// names only what these two files call: HttpHelper is four methods here against the parent's
// eight. The concrete types the composition root builds satisfy them structurally, so routes.go is
// unchanged, and so do the generated mocks (#387).
//
// Per-file database ports stay per-file, beside the function taking them: the database is the
// dependency that genuinely varies from handler to handler, and these six do not.

// AuditLogger records one security event. The context is first because every audit event raised
// while serving a request is correlated to that request: the installed slog handler reads chi's
// request id off it, so the console record joins the request's own log line, and the persisted row
// carries the same id. A call that passed context.Background() here would produce exactly the
// uncorrelated record this exists to prevent, which is why testutil.AssertAuditLogContext refuses
// one in a request-path package (#328).
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// HttpHelper renders this package's pages and its one email body. These two handlers answer HTML,
// so unlike apihandlers they do name the page writers. NotFound answers every self-registration
// page while the feature is off (#425); the JSON writers and the two merged-form accessors the
// parent's declaration carries have no caller here and are not named.
type HttpHelper interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	NotFound(w http.ResponseWriter, r *http.Request)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
}

// EmailSender delivers one message. The context is the request's, so the SMTP dial and write are
// bounded by the request that asked for them.
type EmailSender interface {
	SendEmail(ctx context.Context, input *emaildelivery.SendEmailInput) error
}

// EmailValidator is the address check alone, which is the only validation self-registration
// performs through a port.
type EmailValidator interface {
	ValidateEmailAddress(emailAddress string) error
}

// PasswordValidator holds a chosen password to the configured policy.
type PasswordValidator interface {
	ValidatePassword(ctx context.Context, password string) error
}

// UserCreator creates the user row and its default permissions in one transaction.
type UserCreator interface {
	CreateUser(ctx context.Context, input *usercreation.CreateUserInput) (*models.User, error)
}
