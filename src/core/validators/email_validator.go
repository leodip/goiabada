package validators

import (
	"regexp"

	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/i18n"
)

type EmailValidator struct {
	database data.Database
}

func NewEmailValidator(database data.Database) *EmailValidator {
	return &EmailValidator{
		database: database,
	}
}

type ValidateEmailInput struct {
	Email             string
	EmailConfirmation string
	Subject           string
}

func (val *EmailValidator) ValidateEmailAddress(emailAddress string) error {
	// Basic regex pattern for email validation.
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	// i18n surface: A | C — emitted to browser-flow handlers and admin/account API.
	if !regex.MatchString(emailAddress) {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil)
	}

	// Split the email address into local and domain parts.
	atIndex := regexp.MustCompile("@").FindStringIndex(emailAddress)
	localPart := emailAddress[:atIndex[0]]

	if regexp.MustCompile(`\.\.`).MatchString(emailAddress) {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil)
	}

	if localPart[0] == '.' || localPart[len(localPart)-1] == '.' {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil)
	}

	return nil
}

func (val *EmailValidator) ValidateEmailUpdate(input *ValidateEmailInput) error {

	// i18n surface: C — admin/account API.
	if len(input.Email) == 0 {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailRequired, nil)
	}

	if err := val.ValidateEmailAddress(input.Email); err != nil {
		return err
	}

	if len(input.Email) > 60 {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTooLong, map[string]any{"max": 60})
	}

	if input.Email != input.EmailConfirmation {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailConfirmationMismatch, nil)
	}

	user, err := val.database.GetUserBySubject(nil, input.Subject)
	if err != nil {
		return err
	}

	userByEmail, err := val.database.GetUserByEmail(nil, input.Email)
	if err != nil {
		return err
	}

	if userByEmail != nil && userByEmail.Subject != user.Subject {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailAlreadyRegistered, nil)
	}

	return nil
}

// ValidateEmailChange validates an email change for a given subject without
// relying on a confirmation field (confirmation is a UI concern).
// It checks presence, format, max length and uniqueness across users.
func (val *EmailValidator) ValidateEmailChange(email string, subject string) error {
	// i18n surface: C — admin/account API.
	if len(email) == 0 {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailRequired, nil)
	}

	if err := val.ValidateEmailAddress(email); err != nil {
		return err
	}

	if len(email) > 60 {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTooLong, map[string]any{"max": 60})
	}

	user, err := val.database.GetUserBySubject(nil, subject)
	if err != nil {
		return err
	}

	userByEmail, err := val.database.GetUserByEmail(nil, email)
	if err != nil {
		return err
	}

	if userByEmail != nil && user != nil && userByEmail.Subject != user.Subject {
		return i18n.NewLocalizedError(i18n.ErrCodeEmailAlreadyRegistered, nil)
	}

	return nil
}
