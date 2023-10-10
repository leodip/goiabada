package core

import (
	"context"
	"regexp"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

type PhoneValidator struct {
	database *data.Database
}

func NewPhoneValidator(database *data.Database) *PhoneValidator {
	return &PhoneValidator{
		database: database,
	}
}

func (val *PhoneValidator) ValidatePhone(ctx context.Context, accountPhone *dtos.AccountPhone) error {

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
			return customerrors.NewValidationError("", "Phone country is invalid.")
		}

		if len(accountPhone.PhoneNumber) == 0 {
			return customerrors.NewValidationError("", "The phone number field must contain a valid phone number. To remove the phone number information, please select the (blank) option from the dropdown menu for the phone country and leave the phone number field empty.")
		}
	}

	if len(accountPhone.PhoneNumber) > 0 {
		pattern := `^[0-9]+([- ]?[0-9]+)*$`
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		if !regex.MatchString(accountPhone.PhoneNumber) {
			return customerrors.NewValidationError("", "Please enter a valid number. Phone numbers can contain only digits, and may include single spaces or hyphens as separators.")
		}
		if len(accountPhone.PhoneNumber) > 30 {
			return customerrors.NewValidationError("", "The maximum allowed length for a phone number is 30 characters.")
		}

		if len(accountPhone.PhoneNumberCountry) == 0 {
			return customerrors.NewValidationError("", "You must select a country for your phone number.")
		}
	}

	return nil
}
