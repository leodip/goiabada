package validators

import (
	"regexp"

	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
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

	if !regex.MatchString(emailAddress) {
		return customerrors.NewErrorDetail("", "Please enter a valid email address.")
	}

	// Split the email address into local and domain parts.
	atIndex := regexp.MustCompile("@").FindStringIndex(emailAddress)
	localPart := emailAddress[:atIndex[0]]
	// domainPart := emailAddress[atIndex[0]+1:]

	// Check for consecutive dots in the entire email address.
	if regexp.MustCompile(`\.\.`).MatchString(emailAddress) {
		return customerrors.NewErrorDetail("", "Please enter a valid email address.")
	}

	// Check for leading or trailing dots in the local part.
	if localPart[0] == '.' || localPart[len(localPart)-1] == '.' {
		return customerrors.NewErrorDetail("", "Please enter a valid email address.")
	}

	// Additional domain part validations could be added here if necessary.

	return nil
}

func (val *EmailValidator) ValidateEmailUpdate(input *ValidateEmailInput) error {

	if len(input.Email) == 0 {
		return customerrors.NewErrorDetail("", "Please enter an email address.")
	}

	err := val.ValidateEmailAddress(input.Email)
	if err != nil {
		return err
	}

	if len(input.Email) > 60 {
		return customerrors.NewErrorDetail("", "The email address cannot exceed a maximum length of 60 characters.")
	}

	if input.Email != input.EmailConfirmation {
		return customerrors.NewErrorDetail("", "The email and email confirmation entries must be identical.")
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
		return customerrors.NewErrorDetail("", "Apologies, but this email address is already registered.")
	}

	return nil
}

// ValidateEmailChange validates an email change for a given subject without
// relying on a confirmation field (confirmation is a UI concern).
// It checks presence, format, max length and uniqueness across users.
func (val *EmailValidator) ValidateEmailChange(email string, subject string) error {
	if len(email) == 0 {
		return customerrors.NewErrorDetail("", "Please enter an email address.")
	}

	if err := val.ValidateEmailAddress(email); err != nil {
		return err
	}

	if len(email) > 60 {
		return customerrors.NewErrorDetail("", "The email address cannot exceed a maximum length of 60 characters.")
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
		return customerrors.NewErrorDetail("", "Apologies, but this email address is already registered.")
	}

	return nil
}
