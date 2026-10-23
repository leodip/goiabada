package adminpassword

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin email and app name the cases below are checked against, decision 6's own example
// address and the app name a first start seeds by default (#550).
const (
	testAdminEmail = "jane.doe@example.com"
	testAppName    = "Goiabada"
)

// The first administrator's password on each side of both bounds: 15 characters, counted as
// characters, and bcrypt's 72 bytes, counted as bytes (#500 decision 1, #409). The bounds are
// literals here rather than the rule's own constants, so a test cannot agree with a moved bound.
// None of the passwords is on the list of commonly used passwords, which holds 15 of one letter.
func TestCheck_AcceptsWithinBothBounds(t *testing.T) {
	for name, password := range map[string]string{
		"15 ASCII characters":                   "tqvmzrkwplxhbnd",
		"15 two-byte characters, 30 bytes":      strings.Repeat("é", 15),
		"72 ASCII bytes":                        strings.Repeat("a", 72),
		"36 two-byte characters, 72 bytes":      strings.Repeat("é", 36),
		"a generated password of 16 characters": "Xq7-mZp2_vR9tLk4",
	} {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, Check(password, testAdminEmail, testAppName))
		})
	}
}

func TestCheck_Refuses(t *testing.T) {
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
		// The list of commonly used passwords, compared whole and ignoring case (#550 decisions 5 and 7).
		{"a listed password", "passwordpassword", []string{"commonly used passwords"}},
		{"a listed password in capitals", "PasswordPassword", []string{"commonly used passwords"}},
		{"15 of one letter, which the list holds", strings.Repeat("a", 15), []string{"commonly used passwords"}},
		// The admin email, its local part and the app name, and their derivatives (#550 decisions 6 and 7).
		{"the admin email", "Jane.Doe@Example.com", []string{"too close to the admin email"}},
		{"the local part padded", "jane.doe2026!!!!!!", []string{"too close to the admin email"}},
		{"the app name repeated", "GoiabadaGoiabada", []string{"too close to the admin email", "Goiabada"}},
		{"the app name padded", "Goiabada2026!!!!!!!", []string{"too close to the admin email", "Goiabada"}},
		// Length is checked first, so a derivative under 15 characters is told it is short.
		{"the local part padded to 12 characters", "jane.doe2026", []string{"12 characters", "at least 15 characters"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.password, testAdminEmail, testAppName)
			require.Error(t, err)
			for _, part := range tc.reason {
				assert.Contains(t, err.Error(), part)
			}
		})
	}
}

// The app name is the one the caller seeds, not a fixed Goiabada: an installation configured with
// another name has that name refused, and Goiabada's derivatives are then no closer than any word.
func TestCheck_ComparesWithTheAppNameGiven(t *testing.T) {
	err := Check("orchardorchard!!", testAdminEmail, "Orchard")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too close to the admin email")

	assert.NoError(t, Check("orchardorchard!!", testAdminEmail, testAppName))
}

// The admin email is the one the caller seeds: another administrator's address is refused for that
// administrator alone.
func TestCheck_ComparesWithTheAdminEmailGiven(t *testing.T) {
	err := Check("admin@example.org2026", "admin@example.org", testAppName)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too close to the admin email")

	assert.NoError(t, Check("admin@example.org2026", testAdminEmail, testAppName))
}

// A passphrase that merely contains the app name, or a listed password, is not refused: the
// comparison is of the whole password (#550 decision 6, NIST SP 800-63B-4 section 3.1.1.2).
func TestCheck_AcceptsAPassphraseThatMerelyContainsAWord(t *testing.T) {
	for _, password := range []string{
		"goiabada orchard keeps ripening",
		"passwordpassword is not my password",
		"jane.doe keeps a tidy orchard",
	} {
		assert.NoError(t, Check(password, testAdminEmail, testAppName), password)
	}
}

// changeme is refused with a reason of its own even though the length rule would refuse it too,
// so the operator who copied it from an old guide is told why (#500 decision 1).
func TestCheck_ChangemeIsNotRefusedForItsLength(t *testing.T) {
	err := Check("changeme", testAdminEmail, testAppName)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "8 characters")
}
