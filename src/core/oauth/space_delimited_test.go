package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsWellFormedSpaceDelimited pins the one grammar the five space-delimited request parameters
// (scope, response_type, prompt, acr_values, ui_locales) are held to: RFC 6749 section 3.3's
// scope-token *( SP scope-token ), one space between each two values and none at either end. The
// escapes are spelled out, and never typed as the characters, so that no editor can turn a
// no-break space into a plain one.
func TestIsWellFormedSpaceDelimited(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty, which is an omitted parameter", "", true},
		{"one value", "openid", true},
		{"two values", "openid profile", true},
		{"three values", "code id_token token", true},
		{"duplicates are the reader's question", "a a", true},

		// The spaces the grammar does not allow. Each was accepted before #244 and read as if the
		// extra spaces were not there.
		{"a run of two spaces", "openid  profile", false},
		{"a run of three spaces", "openid   profile", false},
		{"a leading space", " openid", false},
		{"a trailing space", "openid ", false},
		{"both ends", " openid profile ", false},
		{"one space alone", " ", false},
		{"spaces alone", "   ", false},

		// The grammar judges only the separators. Any other character is part of a value, which the
		// parameter's own vocabulary refuses or ignores, so none of these is malformed here.
		{"a tab inside a value", "a\tb", true},
		{"a newline inside a value", "a\nb", true},
		{"a carriage return inside a value", "a\rb", true},
		{"a form feed inside a value", "a\fb", true},
		{"a vertical tab inside a value", "a\vb", true},
		{"a no-break space inside a value", "a b", true},
		{"a tab at an edge", "\ta", true},
		{"a no-break space at an edge", "a ", true},
		// A tab next to a space is still one space between two values.
		{"a tab beside a single space", "a \tb", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsWellFormedSpaceDelimited(tc.value))
		})
	}
}

// TestSplitSpaceDelimited pins the splitter: on the space (U+0020) alone, judging nothing. Every
// other character stays inside the value it is in, where until #244 a tab, a newline, a form feed
// and a carriage return separated, and those and a vertical tab, U+0085 and U+00A0 were trimmed off
// each value's edges.
func TestSplitSpaceDelimited(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  []string
	}{
		{"one value", "openid", []string{"openid"}},
		{"two values", "openid profile", []string{"openid", "profile"}},
		{"three values", "code id_token token", []string{"code", "id_token", "token"}},
		{"order and duplicates are kept", "b a b", []string{"b", "a", "b"}},
		{"empty", "", []string{}},

		// What IsWellFormedSpaceDelimited refuses is still split, so a reader that must see a value
		// in a malformed parameter can: a run of spaces or one at an edge yields no empty value.
		{"a run of spaces yields no empty value", "openid    profile", []string{"openid", "profile"}},
		{"a space at either end yields no empty value", " openid profile ", []string{"openid", "profile"}},
		{"spaces alone yield nothing", "     ", []string{}},

		// No character but the space separates.
		{"a tab does not split", "a\tb", []string{"a\tb"}},
		{"a newline does not split", "a\nb", []string{"a\nb"}},
		{"a form feed does not split", "a\fb", []string{"a\fb"}},
		{"a carriage return does not split", "a\rb", []string{"a\rb"}},
		{"a carriage return and newline do not split", "a\r\nb", []string{"a\r\nb"}},
		{"a vertical tab does not split", "a\vb", []string{"a\vb"}},
		{"a no-break space does not split", "a b", []string{"a b"}},
		{"a next-line character does not split", "a\u0085b", []string{"a\u0085b"}},
		{"an ideographic space does not split", "a　b", []string{"a　b"}},
		{"an en space does not split", "a b", []string{"a b"}},

		// Nothing is trimmed: a value padded with any of them is not the value.
		{"a tab at an edge stays", "\ta", []string{"\ta"}},
		{"a no-break space after a value stays", "a ", []string{"a "}},
		{"a vertical tab either side stays", "\va\v", []string{"\va\v"}},
		{"a tab beside a space stays with its value", "a \tb", []string{"a", "\tb"}},
		{"such characters alone are a value", "\t", []string{"\t"}},
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
	assert.Empty(t, SplitSpaceDelimited("   "))
}
