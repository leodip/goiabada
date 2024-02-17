package core

import (
	"context"
	"regexp"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/datav2"
	"github.com/leodip/goiabada/internal/lib"
)

type PhoneValidator struct {
	database datav2.Database
}

func NewPhoneValidator(database datav2.Database) *PhoneValidator {
	return &PhoneValidator{
		database: database,
	}
}

type ValidatePhoneInput struct {
	PhoneNumberCountry  string
	PhoneNumber         string
	PhoneNumberVerified bool
}

func (val *PhoneValidator) ValidatePhone(ctx context.Context, input *ValidatePhoneInput) error {

	if len(input.PhoneNumberCountry) > 0 {
		phoneCountries := lib.GetPhoneCountries()

		found := false
		for _, c := range phoneCountries {
			if c.Code == input.PhoneNumberCountry {
				found = true
				break
			}
		}

		if !found {
			return customerrors.NewValidationError("", "Phone country is invalid.")
		}

		if len(input.PhoneNumber) == 0 {
			return customerrors.NewValidationError("", "The phone number field must contain a valid phone number. To remove the phone number information, please select the (blank) option from the dropdown menu for the phone country and leave the phone number field empty.")
		}
	}

	if len(input.PhoneNumber) > 0 {
		pattern := `^[0-9]+([- ]?[0-9]+)*$`
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		if !regex.MatchString(input.PhoneNumber) {
			return customerrors.NewValidationError("", "Please enter a valid number. Phone numbers can contain only digits, and may include single spaces or hyphens as separators.")
		}
		if len(input.PhoneNumber) > 30 {
			return customerrors.NewValidationError("", "The maximum allowed length for a phone number is 30 characters.")
		}

		if len(input.PhoneNumberCountry) == 0 {
			return customerrors.NewValidationError("", "You must select a country for your phone number.")
		}
	}

	return nil
}
