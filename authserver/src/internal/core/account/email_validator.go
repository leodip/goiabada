package core

import (
	"context"
	"regexp"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
)

type EmailValidator struct {
	database *data.Database
}

func NewEmailValidator(database *data.Database) *EmailValidator {
	return &EmailValidator{
		database: database,
	}
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

func (val *EmailValidator) ValidateEmailUpdate(ctx context.Context, accountEmail *dtos.AccountEmail) error {

	if len(accountEmail.Email) == 0 {
		return customerrors.NewValidationError("", "Please enter an email address.")
	}

	err := val.ValidateEmailAddress(ctx, accountEmail.Email)
	if err != nil {
		return err
	}

	if len(accountEmail.Email) > 60 {
		return customerrors.NewValidationError("", "The email address cannot exceed a maximum length of 60 characters.")
	}

	if accountEmail.Email != accountEmail.EmailConfirmation {
		return customerrors.NewValidationError("", "The email and email confirmation entries must be identical.")
	}

	user, err := val.database.GetUserBySubject(accountEmail.Subject)
	if err != nil {
		return err
	}

	userByEmail, err := val.database.GetUserByEmail(accountEmail.Email)
	if err != nil {
		return err
	}

	if userByEmail != nil && userByEmail.Subject != user.Subject {
		return customerrors.NewValidationError("", "Apologies, but this email address is already registered.")
	}

	return nil
}
