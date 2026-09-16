package validators

import (
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// assertLocalizedError asserts that err is an *i18n.LocalizedError carrying the
// expected code and rendering the expected English sentence.
//
// The sentence is asserted as well as the code because a code assertion alone
// passes whatever the catalog happens to say: rewording an entry to describe a
// different rule leaves every such test green while the user reads the wrong
// instruction. Rewording validator.password.uppercase_required to ask for a
// lowercase character survived the whole suite before this landed (#230).
//
// accountvalidation carries a second declaration of this helper, for the five
// validators that moved to the auth server in #344. Two small declarations, one
// per package, rather than an exported testing helper in core that production
// code would link: the packages are in different modules now, and core may not
// import the auth server at all.
func assertLocalizedError(t *testing.T, err error, expectedCode string, expectedMessage string) {
	t.Helper()
	assert.Error(t, err)
	locErr, ok := err.(*i18n.LocalizedError)
	assert.True(t, ok, "expected *i18n.LocalizedError, got %T", err)
	if ok {
		assert.Equal(t, expectedCode, locErr.Code)
		assert.Equal(t, expectedMessage, locErr.EnglishFallback())
	}
}

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
