package validators

import (
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// The two longest sentences validator.phone.* renders, transcribed from
// src/core/i18n/catalogs/active.en.toml; the shorter ones sit on their rows.
// Asserting the code alone cannot tell a correct sentence from one that
// describes a different rule (#230).
const (
	phoneNumberRequiredMessage = "The phone number field must contain a valid phone number. To remove the " +
		"phone number information, please select the (blank) option from the dropdown menu for the phone " +
		"country and leave the phone number field empty."

	phoneInvalidFormatMessage = "Please enter a valid number. Phone numbers can contain only digits, and " +
		"may include single spaces or hyphens as separators."
)

func TestValidatePhone(t *testing.T) {
	validator := NewPhoneValidator()

	tests := []struct {
		name            string
		input           ValidatePhoneInput
		expectedCode    string
		expectedArgs    map[string]any
		expectedMessage string
	}{
		{
			name: "Valid phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123-456-7890",
			},
		},
		{
			name: "Invalid phone country",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "INVALID",
				PhoneNumber:          "123-456-7890",
			},
			expectedCode:    i18n.ErrCodePhoneCountryInvalid,
			expectedMessage: "Phone country is invalid.",
		},
		{
			name: "Missing phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "",
			},
			expectedCode:    i18n.ErrCodePhoneNumberRequired,
			expectedMessage: phoneNumberRequiredMessage,
		},
		{
			name: "Phone number too short",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "12345",
			},
			expectedCode:    i18n.ErrCodePhoneNumberTooShort,
			expectedArgs:    map[string]any{"min": 6},
			expectedMessage: "The phone number must be at least 6 digits long.",
		},
		{
			name: "Simple pattern phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "111111111",
			},
			expectedCode:    i18n.ErrCodePhoneSimplePattern,
			expectedMessage: "The phone number appears to be a simple pattern. Please enter a valid phone number.",
		},
		{
			name: "Invalid characters in phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123-456-7890a",
			},
			expectedCode:    i18n.ErrCodePhoneInvalidFormat,
			expectedMessage: phoneInvalidFormatMessage,
		},
		{
			name: "Phone number too long",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123456789012345678901234567890123",
			},
			expectedCode:    i18n.ErrCodePhoneNumberTooLong,
			expectedArgs:    map[string]any{"max": 30},
			expectedMessage: "The maximum allowed length for a phone number is 30 characters.",
		},
		{
			name: "Missing country for phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "",
				PhoneNumber:          "123-456-7890",
			},
			expectedCode:    i18n.ErrCodePhoneCountryRequired,
			expectedMessage: "You must select a country for your phone number.",
		},
		// Decision 3 of #275: the digits-and-separators pattern is the only guard
		// against markup in a phone number once nothing sanitizes.
		{
			name: "Pins decision 3 of #275 - no less-than",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123<456",
			},
			expectedCode:    i18n.ErrCodePhoneInvalidFormat,
			expectedMessage: phoneInvalidFormatMessage,
		},
		{
			name: "Pins decision 3 of #275 - no greater-than",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123>456",
			},
			expectedCode:    i18n.ErrCodePhoneInvalidFormat,
			expectedMessage: phoneInvalidFormatMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePhone(&tt.input)
			if tt.expectedCode == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				locErr, ok := err.(*i18n.LocalizedError)
				assert.True(t, ok, "expected *i18n.LocalizedError, got %T", err)
				if ok {
					assert.Equal(t, tt.expectedCode, locErr.Code)
					assert.Equal(t, tt.expectedMessage, locErr.EnglishFallback())
					if tt.expectedArgs != nil {
						assert.Equal(t, tt.expectedArgs, locErr.Args)
					}
				}
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
