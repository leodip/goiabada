package validators

import (
	"regexp"

	"github.com/leodip/goiabada/authserver/internal/customerrors"
	"github.com/leodip/goiabada/authserver/internal/data"
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
