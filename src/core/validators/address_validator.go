package validators

import (
	"github.com/biter777/countries"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
)

type AddressValidator struct {
	database data.Database
}

func NewAddressValidator(database data.Database) *AddressValidator {
	return &AddressValidator{
		database: database,
	}
}

type ValidateAddressInput struct {
	AddressLine1      string
	AddressLine2      string
	AddressLocality   string
	AddressRegion     string
	AddressPostalCode string
	AddressCountry    string
}

func (val *AddressValidator) ValidateAddress(input *ValidateAddressInput) error {

	if len(input.AddressLine1) > 60 {
		return customerrors.NewErrorDetail("", "Please ensure the address line 1 is no longer than 60 characters.")
	}

	if len(input.AddressLine2) > 60 {
		return customerrors.NewErrorDetail("", "Please ensure the address line 2 is no longer than 60 characters.")
	}

	if len(input.AddressLocality) > 60 {
		return customerrors.NewErrorDetail("", "Please ensure the locality is no longer than 60 characters.")
	}

	if len(input.AddressRegion) > 60 {
		return customerrors.NewErrorDetail("", "Please ensure the region is no longer than 60 characters.")
	}

	if len(input.AddressPostalCode) > 30 {
		errorMsg := "Please ensure the postal code is no longer than 30 characters."
		return customerrors.NewErrorDetail("", errorMsg)
	}

	// The canonical stored country representation is ISO 3166-1 alpha-2
	// (e.g. "US", "BR"). The form posts alpha-2 codes; the stored value
	// is also alpha-2 (a one-time migration converted any pre-existing
	// alpha-3 values).
	if len(input.AddressCountry) > 0 {
		if len(input.AddressCountry) != 2 {
			return customerrors.NewErrorDetail("", "Invalid country.")
		}
		country := countries.ByName(input.AddressCountry)
		if !country.IsValid() || country.Alpha2() != input.AddressCountry {
			return customerrors.NewErrorDetail("", "Invalid country.")
		}
	}

	return nil
}
