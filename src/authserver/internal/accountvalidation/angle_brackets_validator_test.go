package accountvalidation

import (
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// ValidateNoAngleBrackets is the error half of a rule core still owns: it asks
// validators.ContainsAngleBrackets and turns a true into a localized refusal.
// The exhaustive table for the two characters is core's, beside the predicate;
// what is tested here is the wrapping (#385 decision 17).
func TestValidateNoAngleBrackets_AcceptsAValueWithoutThem(t *testing.T) {
	testCases := []string{"", "Acme Corporation", "Tom & Jerry", "&lt;", "東京"}

	for _, value := range testCases {
		t.Run(value, func(t *testing.T) {
			assert.NoError(t, ValidateNoAngleBrackets(value, i18n.ErrCodeDescriptionAngleBrackets))
		})
	}
}

func TestValidateNoAngleBrackets_RefusesAValueHoldingThem(t *testing.T) {
	testCases := []struct {
		name  string
		value string
	}{
		{"a lone less-than", "<"},
		{"a lone greater-than", ">"},
		{"greater-than used as arithmetic", "x > y"},
		{"an allowlisted tag the old sanitizer let through", "<b>x</b>"},
		{"a script tag", "<script>alert(1)</script>"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNoAngleBrackets(tc.value, i18n.ErrCodeDescriptionAngleBrackets)

			assertLocalizedError(t, err, i18n.ErrCodeDescriptionAngleBrackets,
				"The description cannot contain the characters < or >.")
		})
	}
}

// The caller chooses the error code so the localized message names the right
// field. ValidateNoAngleBrackets must return whichever code it was given, and
// each code must name its own field: the seven sentences differ only in the
// noun, so a catalog entry copied from its neighbour and left unedited is the
// mistake this table exists to catch. The messages are transcribed from
// src/core/i18n/catalogs/active.en.toml (#230).
func TestValidateNoAngleBrackets_ReturnsTheCallerSuppliedCode(t *testing.T) {
	testCases := []struct {
		code    string
		message string
	}{
		{i18n.ErrCodeDescriptionAngleBrackets, "The description cannot contain the characters < or >."},
		{i18n.ErrCodeDisplayNameAngleBrackets, "The display name cannot contain the characters < or >."},
		{i18n.ErrCodeAttributeValueAngleBrackets, "The attribute value cannot contain the characters < or >."},
		{i18n.ErrCodeAddressAngleBrackets, "Address fields cannot contain the characters < or >."},
		{i18n.ErrCodeSettingsAppNameAngleBrackets, "The application name cannot contain the characters < or >."},
		{i18n.ErrCodeSettingsIssuerAngleBrackets, "The issuer cannot contain the characters < or >."},
		{i18n.ErrCodeSettingsSmtpFromNameAngleBrackets, "The from name cannot contain the characters < or >."},
	}

	for _, tc := range testCases {
		t.Run(tc.code, func(t *testing.T) {
			err := ValidateNoAngleBrackets("<b>x</b>", tc.code)

			assertLocalizedError(t, err, tc.code, tc.message)
		})
	}
}
