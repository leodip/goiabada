package validators

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/stretchr/testify/assert"
)

func TestValidatePhone(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewPhoneValidator(mockDB)
	ctx := context.Background()

	tests := []struct {
		name          string
		input         ValidatePhoneInput
		expectedError string
	}{
		{
			name: "Valid phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123-456-7890",
			},
			expectedError: "",
		},
		{
			name: "Invalid phone country",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "INVALID",
				PhoneNumber:          "123-456-7890",
			},
			expectedError: "Phone country is invalid.",
		},
		{
			name: "Missing phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "",
			},
			expectedError: "The phone number field must contain a valid phone number. To remove the phone number information, please select the (blank) option from the dropdown menu for the phone country and leave the phone number field empty.",
		},
		{
			name: "Phone number too short",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "12345",
			},
			expectedError: "The phone number must be at least 6 digits long.",
		},
		{
			name: "Simple pattern phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "111111111",
			},
			expectedError: "The phone number appears to be a simple pattern. Please enter a valid phone number.",
		},
		{
			name: "Invalid characters in phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123-456-7890a",
			},
			expectedError: "Please enter a valid number. Phone numbers can contain only digits, and may include single spaces or hyphens as separators.",
		},
		{
			name: "Phone number too long",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123456789012345678901234567890123",
			},
			expectedError: "The maximum allowed length for a phone number is 30 characters.",
		},
		{
			name: "Missing country for phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "",
				PhoneNumber:          "123-456-7890",
			},
			expectedError: "You must select a country for your phone number.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePhone(ctx, &tt.input)
			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				customErr, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedError, customErr.GetDescription())
			}
		})
	}
}

func TestIsSimplePattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Repeating digit", "111111", true},
		{"Ascending sequence", "123456", true},
		{"Descending sequence", "987654", true},
		{"Non-simple pattern", "123454", false},
		{"Mixed pattern", "112233", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSimplePattern(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
