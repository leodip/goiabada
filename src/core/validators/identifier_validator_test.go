package validators

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

func TestValidateIdentifier(t *testing.T) {
	validator := NewIdentifierValidator()

	tests := []struct {
		name             string
		identifier       string
		enforceMinLength bool
		expectedCode     string
		expectedArgs     map[string]any
	}{
		{name: "Valid identifier", identifier: "valid-identifier123", enforceMinLength: true},
		{name: "Valid identifier with underscore", identifier: "valid_identifier123", enforceMinLength: true},
		{name: "Valid identifier minimum length", identifier: "abc", enforceMinLength: true},
		{name: "Valid identifier not enforcing min length", identifier: "ab", enforceMinLength: false},
		{name: "Too long identifier", identifier: "this-identifier-is-way-too-long-and-exceeds-maximum", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooLong, expectedArgs: map[string]any{"max": 38}},
		{name: "Too short identifier", identifier: "ab", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooShort, expectedArgs: map[string]any{"min": 3}},
		{name: "Invalid start character", identifier: "1invalid-identifier", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat},
		{name: "Invalid end character", identifier: "invalid-identifier-", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat},
		{name: "Invalid end character underscore", identifier: "invalid_identifier_", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat},
		{name: "Consecutive dashes", identifier: "invalid--identifier", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat},
		{name: "Consecutive underscores", identifier: "invalid__identifier", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat},
		{name: "Invalid characters", identifier: "invalid@identifier", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateIdentifier(tt.identifier, tt.enforceMinLength)
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

func TestValidateIdentifierEdgeCases(t *testing.T) {
	validator := NewIdentifierValidator()

	tests := []struct {
		name             string
		identifier       string
		enforceMinLength bool
		expectedCode     string
		expectedArgs     map[string]any
	}{
		{name: "Empty identifier enforcing min length", identifier: "", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooShort, expectedArgs: map[string]any{"min": 3}},
		{name: "Empty identifier not enforcing min length", identifier: "", enforceMinLength: false,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat},
		{name: "Max length identifier", identifier: strings.Repeat("a", 38), enforceMinLength: true},
		{name: "Just over max length identifier", identifier: strings.Repeat("a", 39), enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooLong, expectedArgs: map[string]any{"max": 38}},
		{name: "Single character identifier not enforcing min length", identifier: "a", enforceMinLength: false},
		{name: "Single character identifier enforcing min length", identifier: "a", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooShort, expectedArgs: map[string]any{"min": 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateIdentifier(tt.identifier, tt.enforceMinLength)
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
