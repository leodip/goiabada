package inputvalidation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The first administrator's password on each side of both bounds: 15 characters, counted as
// characters, and bcrypt's 72 bytes, counted as bytes (#500 decision 1, #409). The bounds are
// literals here rather than the rule's own constants, so a test cannot agree with a moved bound.
func TestCheckAdminPassword_AcceptsWithinBothBounds(t *testing.T) {
	for name, password := range map[string]string{
		"15 ASCII characters":                   strings.Repeat("a", 15),
		"15 two-byte characters, 30 bytes":      strings.Repeat("é", 15),
		"72 ASCII bytes":                        strings.Repeat("a", 72),
		"36 two-byte characters, 72 bytes":      strings.Repeat("é", 36),
		"a generated password of 16 characters": "Xq7-mZp2_vR9tLk4",
	} {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, CheckAdminPassword(password))
		})
	}
}

func TestCheckAdminPassword_Refuses(t *testing.T) {
	cases := []struct {
		name     string
		password string
		reason   []string
	}{
		{"empty", "", []string{"empty", "at least 15 characters"}},
		{"the published changeme", "changeme", []string{"changeme", "published"}},
		{"14 ASCII characters", strings.Repeat("a", 14), []string{"14 characters", "at least 15 characters"}},
		{"14 two-byte characters, 28 bytes", strings.Repeat("é", 14), []string{"14 characters", "at least 15 characters"}},
		{"73 ASCII bytes", strings.Repeat("a", 73), []string{"73 bytes", "at most 72 bytes", "non-ASCII"}},
		{"37 two-byte characters, 74 bytes", strings.Repeat("é", 37), []string{"74 bytes", "at most 72 bytes", "non-ASCII"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAdminPassword(tc.password)
			require.Error(t, err)
			for _, part := range tc.reason {
				assert.Contains(t, err.Error(), part)
			}
		})
	}
}

// changeme is refused with a reason of its own even though the length rule would refuse it too,
// so the operator who copied it from an old guide is told why (#500 decision 1).
func TestCheckAdminPassword_ChangemeIsNotRefusedForItsLength(t *testing.T) {
	err := CheckAdminPassword("changeme")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "8 characters")
}
