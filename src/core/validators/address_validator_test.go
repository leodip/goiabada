package validators

import (
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

func TestValidateAddress(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAddressValidator(mockDB)

	tests := []struct {
		name         string
		input        ValidateAddressInput
		expectedCode string
		expectedArgs map[string]any
	}{
		{
			name: "Valid address (alpha-2 country)",
			input: ValidateAddressInput{
				AddressLine1:      "123 Main St",
				AddressLine2:      "Apt 4B",
				AddressLocality:   "Springfield",
				AddressRegion:     "IL",
				AddressPostalCode: "62701",
				// Country is canonicalized to ISO 3166-1 alpha-2.
				AddressCountry: "US",
			},
		},
		{
			name: "Country name (no longer accepted post-canonicalization)",
			input: ValidateAddressInput{
				AddressCountry: "United States",
			},
			expectedCode: i18n.ErrCodeAddressCountryInvalid,
		},
		{
			name: "Country alpha-3 (no longer accepted post-canonicalization)",
			input: ValidateAddressInput{
				AddressCountry: "USA",
			},
			expectedCode: i18n.ErrCodeAddressCountryInvalid,
		},
		{
			name: "Lowercase alpha-2 is rejected (ByAlpha2 is upper-case only)",
			input: ValidateAddressInput{
				AddressCountry: "us",
			},
			expectedCode: i18n.ErrCodeAddressCountryInvalid,
		},
		{
			name: "Removed country AN is rejected post-migration",
			input: ValidateAddressInput{
				AddressCountry: "AN",
			},
			expectedCode: i18n.ErrCodeAddressCountryInvalid,
		},
		{
			name: "Valid alpha-2 (BR)",
			input: ValidateAddressInput{
				AddressCountry: "BR",
			},
		},
		{
			name: "Address line 1 too long",
			input: ValidateAddressInput{
				AddressLine1: "This address line is way too long and exceeds the maximum allowed length of sixty characters",
			},
			expectedCode: i18n.ErrCodeAddressLine1TooLong,
			expectedArgs: map[string]any{"max": 60},
		},
		{
			name: "Address line 2 too long",
			input: ValidateAddressInput{
				AddressLine2: "This address line 2 is way too long and exceeds the maximum allowed length of sixty characters",
			},
			expectedCode: i18n.ErrCodeAddressLine2TooLong,
			expectedArgs: map[string]any{"max": 60},
		},
		{
			name: "Locality too long",
			input: ValidateAddressInput{
				AddressLocality: "This locality name is way too long and exceeds the maximum allowed length of sixty characters",
			},
			expectedCode: i18n.ErrCodeAddressLocalityTooLong,
			expectedArgs: map[string]any{"max": 60},
		},
		{
			name: "Region too long",
			input: ValidateAddressInput{
				AddressRegion: "This region name is way too long and exceeds the maximum allowed length of sixty characters",
			},
			expectedCode: i18n.ErrCodeAddressRegionTooLong,
			expectedArgs: map[string]any{"max": 60},
		},
		{
			name: "Postal code too long",
			input: ValidateAddressInput{
				AddressPostalCode: "This postal code is way too long and exceeds the maximum allowed length",
			},
			expectedCode: i18n.ErrCodeAddressPostalCodeTooLong,
			expectedArgs: map[string]any{"max": 30},
		},
		{
			name: "Invalid country",
			input: ValidateAddressInput{
				AddressCountry: "Nonexistent Country",
			},
			expectedCode: i18n.ErrCodeAddressCountryInvalid,
		},
		// Decision 3 of #275: the alpha-2 lookup is the only guard against markup
		// in the country code, so one row per character pins it here.
		{
			name: "Pins decision 3 of #275 - country with a less-than",
			input: ValidateAddressInput{
				AddressCountry: "U<",
			},
			expectedCode: i18n.ErrCodeAddressCountryInvalid,
		},
		{
			name: "Pins decision 3 of #275 - country with a greater-than",
			input: ValidateAddressInput{
				AddressCountry: "U>",
			},
			expectedCode: i18n.ErrCodeAddressCountryInvalid,
		},
		// The five text fields are refused by ValidateNoAngleBrackets (#275). These
		// rows prove the wiring, one per field; angle_brackets_validator_test.go
		// owns the table that isolates the two characters.
		{
			name: "Markup in address line 1",
			input: ValidateAddressInput{
				AddressLine1:      "<b>x</b>",
				AddressLine2:      "Apt 4B",
				AddressLocality:   "Springfield",
				AddressRegion:     "IL",
				AddressPostalCode: "62701",
				AddressCountry:    "US",
			},
			expectedCode: i18n.ErrCodeAddressAngleBrackets,
		},
		{
			name: "Markup in address line 2",
			input: ValidateAddressInput{
				AddressLine1:      "123 Main St",
				AddressLine2:      "<b>x</b>",
				AddressLocality:   "Springfield",
				AddressRegion:     "IL",
				AddressPostalCode: "62701",
				AddressCountry:    "US",
			},
			expectedCode: i18n.ErrCodeAddressAngleBrackets,
		},
		{
			name: "Markup in the locality",
			input: ValidateAddressInput{
				AddressLine1:      "123 Main St",
				AddressLine2:      "Apt 4B",
				AddressLocality:   "<b>x</b>",
				AddressRegion:     "IL",
				AddressPostalCode: "62701",
				AddressCountry:    "US",
			},
			expectedCode: i18n.ErrCodeAddressAngleBrackets,
		},
		{
			name: "Markup in the region",
			input: ValidateAddressInput{
				AddressLine1:      "123 Main St",
				AddressLine2:      "Apt 4B",
				AddressLocality:   "Springfield",
				AddressRegion:     "<b>x</b>",
				AddressPostalCode: "62701",
				AddressCountry:    "US",
			},
			expectedCode: i18n.ErrCodeAddressAngleBrackets,
		},
		{
			name: "Markup in the postal code",
			input: ValidateAddressInput{
				AddressLine1:      "123 Main St",
				AddressLine2:      "Apt 4B",
				AddressLocality:   "Springfield",
				AddressRegion:     "IL",
				AddressPostalCode: "<b>x</b>",
				AddressCountry:    "US",
			},
			expectedCode: i18n.ErrCodeAddressAngleBrackets,
		},
		{
			// Decision 2 of #275: only "<" and ">" are refused, so an apostrophe,
			// an ampersand and quotes all reach the row unchanged.
			name: "Ampersand, apostrophe and quotes are accepted",
			input: ValidateAddressInput{
				AddressLine1:      `O'Brien & Sons, "The Mews"`,
				AddressLocality:   "Springfield",
				AddressPostalCode: "62701",
				AddressCountry:    "US",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateAddress(&tt.input)
			if tt.expectedCode == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				locErr, ok := err.(*i18n.LocalizedError)
				assert.True(t, ok, "expected *i18n.LocalizedError, got %T", err)
				if ok {
					assert.Equal(t, tt.expectedCode, locErr.Code)
					if tt.expectedArgs != nil {
						assert.Equal(t, tt.expectedArgs, locErr.Args)
					} else {
						// A row that names no args expects none: the message is a
						// fixed sentence and a stray arg would mean the wrong call
						// site produced the error.
						assert.Nil(t, locErr.Args)
					}
				}
			}
		})
	}
}
