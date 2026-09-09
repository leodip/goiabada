package validators

import (
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Tests for ContainsAngleBrackets and ValidateNoAngleBrackets
//
// This is the exhaustive table for the two characters: every consumer of the
// helper carries one accepted and one refused case only. Decision 2 of #275 is
// that "<" and ">" are the whole rule, so the accepted rows below (ampersands,
// entities, quotes) are as load-bearing as the refused ones.
// =============================================================================

func TestAngleBrackets_Accepted(t *testing.T) {
	testCases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"plain text", "Acme Corporation"},
		{"ampersand", "Tom & Jerry"},
		{"ampersand with no spaces", "AT&T"},
		{"an escaped less-than is text, not markup", "&lt;"},
		{"a numeric character reference is text too", "&#60;"},
		{"double quotes", `"quoted"`},
		{"single quotes", "'single'"},
		{"a newline inside the value", "first line\nsecond line"},
		{"accented letters", "José Müller"},
		{"non-latin script", "東京"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, ContainsAngleBrackets(tc.value))
			assert.NoError(t, ValidateNoAngleBrackets(tc.value, i18n.ErrCodeDescriptionAngleBrackets))
		})
	}
}

func TestAngleBrackets_Refused(t *testing.T) {
	testCases := []struct {
		name  string
		value string
	}{
		{"a lone less-than", "<"},
		{"a lone greater-than", ">"},
		{"less-than between letters", "a<b"},
		{"greater-than used as arithmetic", "x > y"},
		{"an allowlisted tag the old sanitizer let through", "<b>x</b>"},
		{"an html comment", "<!-- -->"},
		{"a script tag", "<script>alert(1)</script>"},
		{"a less-than after otherwise valid text", "Acme Corporation <"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, ContainsAngleBrackets(tc.value))

			err := ValidateNoAngleBrackets(tc.value, i18n.ErrCodeDescriptionAngleBrackets)

			assertLocalizedErrorCode(t, err, i18n.ErrCodeDescriptionAngleBrackets)
		})
	}
}

// The caller chooses the error code so the localized message names the right
// field. ValidateNoAngleBrackets must return whichever code it was given.
func TestValidateNoAngleBrackets_ReturnsTheCallerSuppliedCode(t *testing.T) {
	codes := []string{
		i18n.ErrCodeDescriptionAngleBrackets,
		i18n.ErrCodeDisplayNameAngleBrackets,
		i18n.ErrCodeAttributeValueAngleBrackets,
		i18n.ErrCodeAddressAngleBrackets,
		i18n.ErrCodeSettingsAppNameAngleBrackets,
		i18n.ErrCodeSettingsIssuerAngleBrackets,
		i18n.ErrCodeSettingsSmtpFromNameAngleBrackets,
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			err := ValidateNoAngleBrackets("<b>x</b>", code)

			assertLocalizedErrorCode(t, err, code)
		})
	}
}
