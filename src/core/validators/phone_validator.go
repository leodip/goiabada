package validators

import (
	"context"
	"regexp"

	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/phonecountries"
)

type PhoneValidator struct {
	database data.Database
}

func NewPhoneValidator(database data.Database) *PhoneValidator {
	return &PhoneValidator{
		database: database,
	}
}

type ValidatePhoneInput struct {
	PhoneCountryUniqueId string
	PhoneNumber          string
	PhoneNumberVerified  bool
}

func (val *PhoneValidator) ValidatePhone(ctx context.Context, input *ValidatePhoneInput) error {

	if len(input.PhoneCountryUniqueId) > 0 {
		phoneCountries := phonecountries.Get()

		found := false
		for _, c := range phoneCountries {
			if c.UniqueId == input.PhoneCountryUniqueId {
				found = true
				break
			}
		}

		if !found {
			return customerrors.NewErrorDetail("", "Phone country is invalid.")
		}

		if len(input.PhoneNumber) == 0 {
			return customerrors.NewErrorDetail("", "The phone number field must contain a valid phone number. To remove the phone number information, please select the (blank) option from the dropdown menu for the phone country and leave the phone number field empty.")
		}
	}

	if len(input.PhoneNumber) > 0 {
		pattern := `^[0-9]+([- ]?[0-9]+)*$`
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		if !regex.MatchString(input.PhoneNumber) {
			return customerrors.NewErrorDetail("", "Please enter a valid number. Phone numbers can contain only digits, and may include single spaces or hyphens as separators.")
		}
		if len(input.PhoneNumber) > 30 {
			return customerrors.NewErrorDetail("", "The maximum allowed length for a phone number is 30 characters.")
		}

		if len(input.PhoneCountryUniqueId) == 0 {
			return customerrors.NewErrorDetail("", "You must select a country for your phone number.")
		}
	}

	return nil
}
