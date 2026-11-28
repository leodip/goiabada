package otp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// inScript writes an ASCII code in the digits of a script whose zero is zero: a test's input, not
// its expected answer, which is the step the ASCII code names.
func inScript(code string, zero rune) string {
	out := make([]rune, 0, len(code))
	for _, c := range code {
		if c >= '0' && c <= '9' {
			c = zero + (c - '0')
		}
		out = append(out, c)
	}
	return string(out)
}

const (
	fullWidthZero    = '０' // U+FF10
	arabicIndicZero  = '٠' // U+0660
	devanagariZero   = '०' // U+0966
	ideographicSpace = "　"
)

// A code typed in the digits of any script is the code it spells (#662 decision 9): a Japanese
// keyboard in kana mode types １２３４５６. What was refused before stays refused, and the passcode is
// trimmed as before, so a space around it goes, the ideographic one too, and one inside it stays.
func TestMatchStep_ReadsTheDigitsOfAnyScript(t *testing.T) {
	now := pinnedNow()
	code := codeAtStep(t, validSecret, pinnedStep)
	wrong := codeAtStep(t, validSecret, pinnedStep-2)

	for _, tc := range []struct {
		name     string
		passcode string
		match    Match
	}{
		{"full-width digits", inScript(code, fullWidthZero), Matched},
		{"Arabic-Indic digits", inScript(code, arabicIndicZero), Matched},
		{"Devanagari digits", inScript(code, devanagariZero), Matched},
		{"a mix of scripts in one code",
			code[:1] + inScript(code[1:3], fullWidthZero) + inScript(code[3:5], arabicIndicZero) +
				inScript(code[5:], devanagariZero), Matched},
		{"full-width digits with an ideographic space around them, which is trimmed",
			ideographicSpace + inScript(code, fullWidthZero) + ideographicSpace, Matched},
		{"a wrong code in full-width digits", inScript(wrong, fullWidthZero), NoMatch},
		{"five full-width digits", inScript(code[:5], fullWidthZero), NoMatch},
		{"seven full-width digits", inScript(code+"0", fullWidthZero), NoMatch},
		{"a space inside a full-width code", inScript(code[:3]+" "+code[3:], fullWidthZero), NoMatch},
		{"an ideographic space inside a full-width code",
			inScript(code[:3], fullWidthZero) + ideographicSpace + inScript(code[3:], fullWidthZero), NoMatch},
		{"a space inside an ASCII code", code[:3] + " " + code[3:], NoMatch},
		{"a circled digit is no decimal digit", "①" + code[1:], NoMatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step, match := MatchStep(tc.passcode, validSecret, now)
			assert.Equal(t, tc.match, match)
			if tc.match == Matched {
				assert.Equal(t, pinnedStep, step)
			}
		})
	}
}
