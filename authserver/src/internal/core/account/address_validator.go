package core

import (
	"context"

	"github.com/biter777/countries"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
)

type AddressValidator struct {
	database *data.Database
}

func NewAddressValidator(database *data.Database) *AddressValidator {
	return &AddressValidator{
		database: database,
	}
}

func (val *AddressValidator) ValidateAddress(ctx context.Context, accountAddress *dtos.AccountAddress) error {

	if len(accountAddress.AddressLine1) > 60 {
		return customerrors.NewValidationError("", "Please ensure the address line 1 is no longer than 60 characters.")
	}

	if len(accountAddress.AddressLine2) > 60 {
		return customerrors.NewValidationError("", "Please ensure the address line 2 is no longer than 60 characters.")
	}

	if len(accountAddress.AddressLocality) > 60 {
		return customerrors.NewValidationError("", "Please ensure the locality is no longer than 60 characters.")
	}

	if len(accountAddress.AddressRegion) > 60 {
		return customerrors.NewValidationError("", "Please ensure the region is no longer than 60 characters.")
	}

	if len(accountAddress.AddressPostalCode) > 60 {
		errorMsg := "Please ensure the postal code is no longer than 60 characters."
		return customerrors.NewValidationError("", errorMsg)
	}

	if len(accountAddress.AddressCountry) > 0 {
		country := countries.ByName(accountAddress.AddressCountry)
		if country.Info().Code == 0 {
			return customerrors.NewValidationError("", "Invalid country.")
		}
	}

	return nil
}
