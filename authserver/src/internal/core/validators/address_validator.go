package core

import (
	"context"

	"github.com/biter777/countries"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
)

type AddressValidator struct {
	database *data.Database
}

func NewAddressValidator(database *data.Database) *AddressValidator {
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

func (val *AddressValidator) ValidateAddress(ctx context.Context, input *ValidateAddressInput) error {

	if len(input.AddressLine1) > 60 {
		return customerrors.NewValidationError("", "Please ensure the address line 1 is no longer than 60 characters.")
	}

	if len(input.AddressLine2) > 60 {
		return customerrors.NewValidationError("", "Please ensure the address line 2 is no longer than 60 characters.")
	}

	if len(input.AddressLocality) > 60 {
		return customerrors.NewValidationError("", "Please ensure the locality is no longer than 60 characters.")
	}

	if len(input.AddressRegion) > 60 {
		return customerrors.NewValidationError("", "Please ensure the region is no longer than 60 characters.")
	}

	if len(input.AddressPostalCode) > 60 {
		errorMsg := "Please ensure the postal code is no longer than 60 characters."
		return customerrors.NewValidationError("", errorMsg)
	}

	if len(input.AddressCountry) > 0 {
		country := countries.ByName(input.AddressCountry)
		if country.Info().Code == 0 {
			return customerrors.NewValidationError("", "Invalid country.")
		}
	}

	return nil
}
