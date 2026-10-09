package accountvalidation

import (
	"context"
	"database/sql"
	"regexp"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// emailValidatorDatabase is what the account email validator reads: the rows that decide whether
// an address is already somebody else's.
type emailValidatorDatabase interface {
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error)
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
}

type EmailValidator struct {
	database emailValidatorDatabase
}

func NewEmailValidator(database emailValidatorDatabase) *EmailValidator {
	return &EmailValidator{
		database: database,
	}
}

// MaxEmailLength is the longest address an account may hold, in characters: every place that sets
// one applies it, the administrator's and the self-service change through ValidateEmailChange and
// self-registration in its own handler, so all four engines store the same addresses (#207).
const MaxEmailLength = 60

// emailShape is the basic shape of an address: a local part, one @, and a domain ending in a label
// of two or more letters.
var emailShape = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func (val *EmailValidator) ValidateEmailAddress(emailAddress string) error {
	// i18n surface: A | C — emitted to browser-flow handlers and admin/account API.
	if !emailShape.MatchString(emailAddress) {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil)
	}

	// The shape above guarantees exactly one @ with at least one character before it.
	localPart, _, _ := strings.Cut(emailAddress, "@")

	if strings.Contains(emailAddress, "..") {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil)
	}

	if localPart[0] == '.' || localPart[len(localPart)-1] == '.' {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil)
	}

	return nil
}

// ValidateEmailChange validates an email change for a given subject, which both the account's own
// change and an administrator's update of a user's address call. It checks presence, format, max
// length and uniqueness across users. There is no confirmation field: confirmation is a UI concern,
// and the administrator's endpoint, the one caller that had passed one, passed the address as its
// own confirmation (#433).
func (val *EmailValidator) ValidateEmailChange(ctx context.Context, email string, subject string) error {
	// i18n surface: C — admin/account API.
	if len(email) == 0 {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailRequired, nil)
	}

	if err := val.ValidateEmailAddress(email); err != nil {
		return err
	}

	if len(email) > MaxEmailLength {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTooLong, map[string]any{"max": MaxEmailLength})
	}

	user, err := val.database.GetUserBySubject(ctx, nil, subject)
	if err != nil {
		return err
	}
	// An unresolvable subject is not a validation problem the caller can show to
	// a user: it means the request carried a stale or forged subject. Surface it
	// as an error. Guarding the comparison below with `user != nil` instead would
	// make the whole condition false and so report the change as valid, silently
	// skipping the uniqueness check and letting one account claim an address that
	// belongs to another.
	if user == nil {
		return errs.New("subject not found: " + subject)
	}

	userByEmail, err := val.database.GetUserByEmail(ctx, nil, email)
	if err != nil {
		return err
	}

	if userByEmail != nil && userByEmail.Subject != user.Subject {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailAlreadyRegistered, nil)
	}

	return nil
}
