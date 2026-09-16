package validators

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// The sentences validator.identifier.* renders, transcribed from
// src/core/i18n/catalogs/active.en.toml. Asserting the code alone cannot tell a
// correct sentence from one that describes a different rule, which is how the
// catalog was free to drift from the validator that names it (#230).
const (
	identifierTooLongMessage  = "The identifier cannot exceed a maximum length of 38 characters."
	identifierTooShortMessage = "The identifier must be at least 3 characters long."

	identifierInvalidFormatMessage = "Invalid identifier format. It must start with a letter, can include " +
		"letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two " +
		"consecutive dashes or underscores."
)

func TestValidateIdentifier(t *testing.T) {
	validator := NewIdentifierValidator()

	tests := []struct {
		name             string
		identifier       string
		enforceMinLength bool
		expectedCode     string
		expectedArgs     map[string]any
		expectedMessage  string
	}{
		{name: "Valid identifier", identifier: "valid-identifier123", enforceMinLength: true},
		{name: "Valid identifier with underscore", identifier: "valid_identifier123", enforceMinLength: true},
		{name: "Valid identifier minimum length", identifier: "abc", enforceMinLength: true},
		{name: "Valid identifier not enforcing min length", identifier: "ab", enforceMinLength: false},
		{name: "Too long identifier", identifier: "this-identifier-is-way-too-long-and-exceeds-maximum", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooLong, expectedArgs: map[string]any{"max": 38},
			expectedMessage: identifierTooLongMessage},
		{name: "Too short identifier", identifier: "ab", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooShort, expectedArgs: map[string]any{"min": 3},
			expectedMessage: identifierTooShortMessage},
		{name: "Invalid start character", identifier: "1invalid-identifier", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
		{name: "Invalid end character", identifier: "invalid-identifier-", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
		{name: "Invalid end character underscore", identifier: "invalid_identifier_", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
		{name: "Consecutive dashes", identifier: "invalid--identifier", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
		{name: "Consecutive underscores", identifier: "invalid__identifier", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
		{name: "Invalid characters", identifier: "invalid@identifier", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
		// Decision 3 of #275: the identifier pattern is the only guard against
		// markup in an identifier or attribute key once nothing sanitizes.
		{name: "Pins decision 3 of #275 - no less-than", identifier: "my<id", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
		{name: "Pins decision 3 of #275 - no greater-than", identifier: "my>id", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
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
					assert.Equal(t, tt.expectedMessage, locErr.EnglishFallback())
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
		expectedMessage  string
	}{
		{name: "Empty identifier enforcing min length", identifier: "", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooShort, expectedArgs: map[string]any{"min": 3},
			expectedMessage: identifierTooShortMessage},
		{name: "Empty identifier not enforcing min length", identifier: "", enforceMinLength: false,
			expectedCode: i18n.ErrCodeIdentifierInvalidFormat, expectedMessage: identifierInvalidFormatMessage},
		{name: "Max length identifier", identifier: strings.Repeat("a", 38), enforceMinLength: true},
		{name: "Just over max length identifier", identifier: strings.Repeat("a", 39), enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooLong, expectedArgs: map[string]any{"max": 38},
			expectedMessage: identifierTooLongMessage},
		{name: "Single character identifier not enforcing min length", identifier: "a", enforceMinLength: false},
		{name: "Single character identifier enforcing min length", identifier: "a", enforceMinLength: true,
			expectedCode: i18n.ErrCodeIdentifierTooShort, expectedArgs: map[string]any{"min": 3},
			expectedMessage: identifierTooShortMessage},
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
					assert.Equal(t, tt.expectedMessage, locErr.EnglishFallback())
					if tt.expectedArgs != nil {
						assert.Equal(t, tt.expectedArgs, locErr.Args)
					}
				}
			}
		})
	}
}
