package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSplitSpaceDelimited pins the one grammar the five space-delimited request parameters (scope,
// response_type, prompt, acr_values, ui_locales) are read with. The escapes are spelled out, and
// never typed as the characters, so that no editor can turn a no-break space into a plain one.
func TestSplitSpaceDelimited(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  []string
	}{
		{"one value", "openid", []string{"openid"}},
		{"two values", "openid profile", []string{"openid", "profile"}},
		{"a run of spaces", "openid    profile", []string{"openid", "profile"}},
		{"leading and trailing runs", "  openid profile  ", []string{"openid", "profile"}},
		{"three values", "code id_token token", []string{"code", "id_token", "token"}},
		{"order and duplicates are kept", "b a b", []string{"b", "a", "b"}},
		{"empty", "", []string{}},
		{"spaces only", "     ", []string{}},

		// The five separators, each of which splits. Decision 20 keeps them: a client that puts a tab
		// between two scopes works today.
		{"a space splits", "a b", []string{"a", "b"}},
		{"a tab splits", "a\tb", []string{"a", "b"}},
		{"a newline splits", "a\nb", []string{"a", "b"}},
		{"a form feed splits", "a\fb", []string{"a", "b"}},
		{"a carriage return splits", "a\rb", []string{"a", "b"}},
		{"a carriage return and newline are one run", "a\r\nb", []string{"a", "b"}},
		{"mixed separators", " a \t\n b\f\rc ", []string{"a", "b", "c"}},
		{"separators only", " \t\n\f\r", []string{}},

		// #244 part 4: what strings.Fields split on and this does not. Each joins two words into one
		// value, which the parameter's own validation then refuses or ignores as unknown.
		{"a no-break space does not split", "a b", []string{"a b"}},
		{"a next-line character does not split", "a\u0085b", []string{"a\u0085b"}},
		{"a vertical tab does not split", "a\vb", []string{"a\vb"}},
		{"an ideographic space does not split", "a　b", []string{"a　b"}},
		{"an en space does not split", "a b", []string{"a b"}},

		// The edge trim, which the scope splitter has always applied and which stays: FieldsFunc
		// leaves a value with no separator in it, and TrimSpace takes the three characters above off
		// its ends, so a padded value is still the value.
		{"a no-break space after a value is trimmed", "a ", []string{"a"}},
		{"a no-break space before a value is trimmed", " a", []string{"a"}},
		{"a vertical tab either side is trimmed", "\va\v", []string{"a"}},
		{"a next-line character after a value is trimmed", "a\u0085 b", []string{"a", "b"}},
		{"a value of only such characters is dropped", "a   b", []string{"a", "b"}},
		{"only such characters is empty", " \v\u0085", []string{}},
		{"a value of such characters between two words joins nothing", "a  b", []string{"a  b"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SplitSpaceDelimited(tc.value))
		})
	}
}

// The result is never nil, so a caller ranging over it or taking its length needs no guard and a
// comparison with an empty slice holds for the empty case too.
func TestSplitSpaceDelimited_IsNeverNil(t *testing.T) {
	assert.NotNil(t, SplitSpaceDelimited(""))
	assert.NotNil(t, SplitSpaceDelimited("   "))
	assert.Empty(t, SplitSpaceDelimited(" \t "))
}
