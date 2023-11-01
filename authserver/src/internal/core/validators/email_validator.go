package core

import (
	"context"
	"regexp"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
)

type EmailValidator struct {
	database *data.Database
}

func NewEmailValidator(database *data.Database) *EmailValidator {
	return &EmailValidator{
		database: database,
	}
}

type ValidateEmailInput struct {
	Email             string
	EmailConfirmation string
	Subject           string
}

func (val *EmailValidator) ValidateEmailAddress(ctx context.Context, emailAddress string) error {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if !regex.MatchString(emailAddress) {
		return customerrors.NewValidationError("", "Please enter a valid email address.")
	}
	return nil
}

func (val *EmailValidator) ValidateEmailUpdate(ctx context.Context, input *ValidateEmailInput) error {

	if len(input.Email) == 0 {
		return customerrors.NewValidationError("", "Please enter an email address.")
	}

	err := val.ValidateEmailAddress(ctx, input.Email)
	if err != nil {
		return err
	}

	if len(input.Email) > 60 {
		return customerrors.NewValidationError("", "The email address cannot exceed a maximum length of 60 characters.")
	}

	if input.Email != input.EmailConfirmation {
		return customerrors.NewValidationError("", "The email and email confirmation entries must be identical.")
	}

	user, err := val.database.GetUserBySubject(input.Subject)
	if err != nil {
		return err
	}

	userByEmail, err := val.database.GetUserByEmail(input.Email)
	if err != nil {
		return err
	}

	if userByEmail != nil && userByEmail.Subject != user.Subject {
		return customerrors.NewValidationError("", "Apologies, but this email address is already registered.")
	}

	return nil
}
