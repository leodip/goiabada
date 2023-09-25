package core

import (
	"context"
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

type PhoneValidator struct {
	database core.Database
}

func NewPhoneValidator(database core.Database) *PhoneValidator {
	return &PhoneValidator{
		database: database,
	}
}

func (val *PhoneValidator) ValidatePhone(ctx context.Context, accountPhone *dtos.AccountPhone) error {

	requestId := middleware.GetReqID(ctx)

	if len(accountPhone.PhoneNumberCountry) > 0 {
		phoneCountries := lib.GetPhoneCountries()

		found := false
		for _, c := range phoneCountries {
			if c.Code == accountPhone.PhoneNumberCountry {
				found = true
				break
			}
		}

		if !found {
			return customerrors.NewAppError(nil, "", "Phone country is invalid.", http.StatusOK)
		}

		if len(accountPhone.PhoneNumber) == 0 {
			return customerrors.NewAppError(nil, "", "The phone number field must contain a valid phone number. To remove the phone number information, please select the (blank) option from the dropdown menu for the phone country and leave the phone number field empty.", http.StatusOK)
		}
	}

	if len(accountPhone.PhoneNumber) > 0 {
		pattern := `^[0-9\s]+$`
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return customerrors.NewInternalServerError(err, requestId)
		}
		if !regex.MatchString(accountPhone.PhoneNumber) {
			return customerrors.NewAppError(nil, "", "Please enter a valid phone number. Phone numbers should consist of only digits and spaces.", http.StatusOK)
		}
		if len(accountPhone.PhoneNumber) > 30 {
			return customerrors.NewAppError(nil, "", "The maximum allowed length for a phone number is 30 characters.", http.StatusOK)
		}

		if len(accountPhone.PhoneNumberCountry) == 0 {
			return customerrors.NewAppError(nil, "", "You must select a country for your phone number.", http.StatusOK)
		}
	}

	return nil
}
