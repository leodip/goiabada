package validators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Tests for ContainsAngleBrackets
//
// This is the exhaustive table for the two characters: every consumer of the
// helper carries one accepted and one refused case only. Decision 2 of #275 is
// that "<" and ">" are the whole rule, so the accepted rows below (ampersands,
// entities, quotes) are as load-bearing as the refused ones.
//
// The table stayed here when #385 moved ValidateNoAngleBrackets to
// authserver/internal/accountvalidation. The rule is what both processes share;
// wrapping it in an error only the auth server emits is not. That package's own
// test owns the code and the sentence, and reads this table's verdict through
// the wrapper rather than restating it.
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
		})
	}
}
