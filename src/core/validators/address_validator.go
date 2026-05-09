package validators

import (
	"github.com/biter777/countries"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/i18n"
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

	// i18n surface: C — admin/account API.
	if len(input.AddressLine1) > 60 {
		return i18n.NewLocalizedError(i18n.ErrCodeAddressLine1TooLong, map[string]any{"max": 60})
	}

	if len(input.AddressLine2) > 60 {
		return i18n.NewLocalizedError(i18n.ErrCodeAddressLine2TooLong, map[string]any{"max": 60})
	}

	if len(input.AddressLocality) > 60 {
		return i18n.NewLocalizedError(i18n.ErrCodeAddressLocalityTooLong, map[string]any{"max": 60})
	}

	if len(input.AddressRegion) > 60 {
		return i18n.NewLocalizedError(i18n.ErrCodeAddressRegionTooLong, map[string]any{"max": 60})
	}

	if len(input.AddressPostalCode) > 30 {
		return i18n.NewLocalizedError(i18n.ErrCodeAddressPostalCodeTooLong, map[string]any{"max": 30})
	}

	// The canonical stored country representation is ISO 3166-1 alpha-2
	// (e.g. "US", "BR"). The form posts alpha-2 codes; the stored value
	// is also alpha-2 (a one-time migration converted any pre-existing
	// alpha-3 values).
	if len(input.AddressCountry) > 0 {
		if len(input.AddressCountry) != 2 {
			return i18n.NewLocalizedError(i18n.ErrCodeAddressCountryInvalid, nil)
		}
		country := countries.ByName(input.AddressCountry)
		if !country.IsValid() || country.Alpha2() != input.AddressCountry {
			return i18n.NewLocalizedError(i18n.ErrCodeAddressCountryInvalid, nil)
		}
	}

	return nil
}
