package validators

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/stretchr/testify/assert"
)

func TestValidateAddress(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAddressValidator(mockDB)

	tests := []struct {
		name          string
		input         ValidateAddressInput
		expectedError *customerrors.ErrorDetail
	}{
		{
			name: "Valid address",
			input: ValidateAddressInput{
				AddressLine1:      "123 Main St",
				AddressLine2:      "Apt 4B",
				AddressLocality:   "Springfield",
				AddressRegion:     "IL",
				AddressPostalCode: "62701",
				AddressCountry:    "United States",
			},
			expectedError: nil,
		},
		{
			name: "Address line 1 too long",
			input: ValidateAddressInput{
				AddressLine1: "This address line is way too long and exceeds the maximum allowed length of sixty characters",
			},
			expectedError: customerrors.NewErrorDetail("", "Please ensure the address line 1 is no longer than 60 characters."),
		},
		{
			name: "Address line 2 too long",
			input: ValidateAddressInput{
				AddressLine2: "This address line 2 is way too long and exceeds the maximum allowed length of sixty characters",
			},
			expectedError: customerrors.NewErrorDetail("", "Please ensure the address line 2 is no longer than 60 characters."),
		},
		{
			name: "Locality too long",
			input: ValidateAddressInput{
				AddressLocality: "This locality name is way too long and exceeds the maximum allowed length of sixty characters",
			},
			expectedError: customerrors.NewErrorDetail("", "Please ensure the locality is no longer than 60 characters."),
		},
		{
			name: "Region too long",
			input: ValidateAddressInput{
				AddressRegion: "This region name is way too long and exceeds the maximum allowed length of sixty characters",
			},
			expectedError: customerrors.NewErrorDetail("", "Please ensure the region is no longer than 60 characters."),
		},
		{
			name: "Postal code too long",
			input: ValidateAddressInput{
				AddressPostalCode: "This postal code is way too long and exceeds the maximum allowed length",
			},
			expectedError: customerrors.NewErrorDetail("", "Please ensure the postal code is no longer than 30 characters."),
		},
		{
			name: "Invalid country",
			input: ValidateAddressInput{
				AddressCountry: "Nonexistent Country",
			},
			expectedError: customerrors.NewErrorDetail("", "Invalid country."),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateAddress(context.Background(), &tt.input)
			if tt.expectedError == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				customErr, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedError.GetDescription(), customErr.GetDescription())
				assert.Equal(t, tt.expectedError.GetCode(), customErr.GetCode())
			}
		})
	}
}
