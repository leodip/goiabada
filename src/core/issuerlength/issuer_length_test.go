package issuerlength

import (
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bound on each side, counted in UTF-16 code units: an astral character such as U+1F600 is two
// units, one code point and four bytes, so a count in bytes or in code points lands on the wrong
// side of one of these cases (#615). The bound is a literal here rather than Max, so a test cannot
// agree with a moved bound, and each case states its three counts, so a literal cannot drift from
// the divergence it exists for.
func TestCheck_CountsUTF16CodeUnits(t *testing.T) {
	cases := []struct {
		name         string
		issuer       string
		units, runes int
		bytes        int
		wantRefusal  string
	}{
		{"60 ASCII", "https://auth.example.com/" + strings.Repeat("a", 35), 60, 60, 60, ""},
		{"61 ASCII", "https://auth.example.com/" + strings.Repeat("a", 36), 61, 61, 61,
			"it is 61 characters long, and the issuer allows at most 60 characters"},
		// Past the bound in bytes, at it in units: a count in bytes would refuse it.
		{"60 units in 64 bytes", "https://auth.example.com/" + strings.Repeat("a", 31) + "\U0001F600\U0001F600", 60, 58, 64, ""},
		// At the bound in code points, past it in units: a count in code points would accept it.
		{"61 units in 60 code points", "https://auth.example.com/" + strings.Repeat("a", 34) + "\U0001F600", 61, 60, 63,
			"it is 61 characters long, and the issuer allows at most 60 characters"},
		{"empty", "", 0, 0, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Len(t, utf16.Encode([]rune(tc.issuer)), tc.units)
			require.Equal(t, tc.runes, utf8.RuneCountInString(tc.issuer))
			require.Len(t, tc.issuer, tc.bytes)

			err := Check(tc.issuer)
			if tc.wantRefusal == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.wantRefusal, err.Error())
		})
	}
}
