package validators

import (
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

func TestValidatePhone(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewPhoneValidator(mockDB)

	tests := []struct {
		name         string
		input        ValidatePhoneInput
		expectedCode string
		expectedArgs map[string]any
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
			expectedCode: i18n.ErrCodePhoneCountryInvalid,
		},
		{
			name: "Missing phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "",
			},
			expectedCode: i18n.ErrCodePhoneNumberRequired,
		},
		{
			name: "Phone number too short",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "12345",
			},
			expectedCode: i18n.ErrCodePhoneNumberTooShort,
			expectedArgs: map[string]any{"min": 6},
		},
		{
			name: "Simple pattern phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "111111111",
			},
			expectedCode: i18n.ErrCodePhoneSimplePattern,
		},
		{
			name: "Invalid characters in phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123-456-7890a",
			},
			expectedCode: i18n.ErrCodePhoneInvalidFormat,
		},
		{
			name: "Phone number too long",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123456789012345678901234567890123",
			},
			expectedCode: i18n.ErrCodePhoneNumberTooLong,
			expectedArgs: map[string]any{"max": 30},
		},
		{
			name: "Missing country for phone number",
			input: ValidatePhoneInput{
				PhoneCountryUniqueId: "",
				PhoneNumber:          "123-456-7890",
			},
			expectedCode: i18n.ErrCodePhoneCountryRequired,
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
