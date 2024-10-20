package validators

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/stretchr/testify/assert"
)

func TestValidateIdentifier(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewIdentifierValidator(mockDB)

	tests := []struct {
		name             string
		identifier       string
		enforceMinLength bool
		expectedError    string
	}{
		{"Valid identifier", "valid-identifier123", true, ""},
		{"Valid identifier with underscore", "valid_identifier123", true, ""},
		{"Valid identifier minimum length", "abc", true, ""},
		{"Valid identifier not enforcing min length", "ab", false, ""},
		{"Too long identifier", "this-identifier-is-way-too-long-and-exceeds-maximum", true, "The identifier cannot exceed a maximum length of 38 characters."},
		{"Too short identifier", "ab", true, "The identifier must be at least 3 characters long."},
		{"Invalid start character", "1invalid-identifier", true, "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."},
		{"Invalid end character", "invalid-identifier-", true, "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."},
		{"Invalid end character underscore", "invalid_identifier_", true, "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."},
		{"Consecutive dashes", "invalid--identifier", true, "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."},
		{"Consecutive underscores", "invalid__identifier", true, "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."},
		{"Invalid characters", "invalid@identifier", true, "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateIdentifier(tt.identifier, tt.enforceMinLength)
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

func TestValidateIdentifierEdgeCases(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewIdentifierValidator(mockDB)

	tests := []struct {
		name             string
		identifier       string
		enforceMinLength bool
		expectedError    string
	}{
		{"Empty identifier enforcing min length", "", true, "The identifier must be at least 3 characters long."},
		{"Empty identifier not enforcing min length", "", false, "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."},
		{"Max length identifier", strings.Repeat("a", 38), true, ""},
		{"Just over max length identifier", strings.Repeat("a", 39), true, "The identifier cannot exceed a maximum length of 38 characters."},
		{"Single character identifier not enforcing min length", "a", false, ""},
		{"Single character identifier enforcing min length", "a", true, "The identifier must be at least 3 characters long."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateIdentifier(tt.identifier, tt.enforceMinLength)
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
