package core

import (
	"context"
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
)

type EmailValidator struct {
	database core.Database
}

func NewEmailValidator(database core.Database) *EmailValidator {
	return &EmailValidator{
		database: database,
	}
}

func (val *EmailValidator) ValidateEmail(ctx context.Context, accountEmail *dtos.AccountEmail) error {

	if len(accountEmail.Email) == 0 {
		return nil
	}

	requestId := middleware.GetReqID(ctx)

	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	if len(accountEmail.Email) > 0 {
		if !regex.MatchString(accountEmail.Email) {
			return customerrors.NewAppError(nil, "", "Please enter a valid email address.", http.StatusOK)
		}

		if len(accountEmail.Email) > 60 {
			return customerrors.NewAppError(nil, "", "The email address cannot exceed a maximum length of 60 characters.", http.StatusOK)
		}
	}

	if accountEmail.Email != accountEmail.EmailConfirmation {
		return customerrors.NewAppError(nil, "", "The email and email confirmation entries must be identical.", http.StatusOK)
	}

	user, err := val.database.GetUserBySubject(accountEmail.Subject)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	userByEmail, err := val.database.GetUserByEmail(accountEmail.Email)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	if userByEmail != nil && userByEmail.Subject != user.Subject {
		return customerrors.NewAppError(nil, "", "Apologies, but this email address is already registered.", http.StatusOK)
	}

	return nil
}
