package accountvalidation

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/adminpassword"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordValidator_ValidatePassword(t *testing.T) {
	validator := NewPasswordValidator()

	t.Run("PasswordPolicyLow", func(t *testing.T) {
		policy := record.PasswordPolicyLow

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "123456", AccountWords{})
			assert.NoError(t, err)
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "12345", AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooShort,
				"Use at least 6 characters for the password.")
		})

		t.Run("TooLong", func(t *testing.T) {
			err := validator.ValidatePassword(policy, strings.Repeat("a", maxPasswordBytes+1), AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooLong, tooLongSentence)
		})

		// Accented rows either side of both bounds. "é" is one character and two bytes, so the
		// same string can be long enough in characters and too long in bytes (#409).
		t.Run("AccentedBelowMinimum", func(t *testing.T) {
			err := validator.ValidatePassword(policy, strings.Repeat("é", 5), AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooShort,
				"Use at least 6 characters for the password.")
		})

		t.Run("AccentedAtMinimum", func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, strings.Repeat("é", 6), AccountWords{}))
		})

		t.Run("AccentedAtMaximum", func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, strings.Repeat("é", maxPasswordBytes/2), AccountWords{}))
		})

		t.Run("AccentedOverMaximum", func(t *testing.T) {
			err := validator.ValidatePassword(policy, strings.Repeat("é", maxPasswordBytes/2+1), AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooLong, tooLongSentence)
		})

		t.Run("ASCIIAtMaximum", func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, strings.Repeat("a", maxPasswordBytes), AccountWords{}))
		})
	})

	t.Run("PasswordPolicyMedium", func(t *testing.T) {
		policy := record.PasswordPolicyMedium

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "Passw0rd", AccountWords{})
			assert.NoError(t, err)
		})

		t.Run("MissingUppercase", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "passw0rd", AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordUppercaseRequired,
				"Add an uppercase letter to the password.")
		})

		t.Run("MissingLowercase", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "PASSW0RD", AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordLowercaseRequired,
				"Add a lowercase letter to the password.")
		})

		t.Run("MissingNumber", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "Password", AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordNumberRequired,
				"Add a number to the password.")
		})
	})

	t.Run("PasswordPolicyHigh", func(t *testing.T) {
		policy := record.PasswordPolicyHigh

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "P@ssw0rd123", AccountWords{})
			assert.NoError(t, err)
		})

		t.Run("MissingSpecialChar", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "Passw0rd123", AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordSpecialCharRequired,
				"Add a symbol to the password.")
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "P@ss1", AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooShort,
				"Use at least 10 characters for the password.")
		})
	})
}

// The two nist refusals in English, transcribed from #550 decision 10.
const (
	tooCommonSentence = "This password is one attackers try first. Choose another: a few unrelated words " +
		"make a long password that's easy to remember."
	tooCloseSentence = "This password is too close to the account's email address, username or the app's " +
		"name. Choose another."
)

// janeDoe is #550 decision 6's own example account: the email jane.doe@example.com, the username
// janedoe and the app name Goiabada. The local part, jane.doe, is not handed in: the validator
// derives it from the email.
var janeDoe = AccountWords{Email: "jane.doe@example.com", Username: "janedoe", AppName: "Goiabada"}

// TestPasswordValidator_Nist holds the nist policy to NIST SP 800-63B-4 section 3.1.1.2 as #550
// decisions 1, 5, 6 and 10 apply it: at least 15 characters, counted as code points, at most
// bcrypt's 72 bytes, no composition rule, and neither a listed password, compared whole and
// ignoring case, nor the account's words or a simple derivative of them. Length is checked first.
func TestPasswordValidator_Nist(t *testing.T) {
	validator := NewPasswordValidator()
	policy := record.PasswordPolicyNist

	accepted := map[string]string{
		"exactly 15 characters, all lowercase, no digit or symbol": "violet tractors",
		"exactly 72 bytes":                         strings.Repeat("violet tractor umbrella ", 3),
		"15 accented characters, 30 bytes":         strings.Repeat("é", 15),
		"36 accented characters, 72 bytes":         strings.Repeat("é", 36),
		"a passphrase containing a listed one":     "my cat likes passwordpassword",
		"a listed one with a character added":      "passwordpassword1",
		"a passphrase that merely contains a name": "jane doe likes violet tractors",
		"a passphrase containing the app name":     "goiabada jam on toast",
	}
	for name, password := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, password, janeDoe))
		})
	}

	refused := []struct {
		name     string
		password string
		code     string
		message  string
	}{
		{"14 characters", "violettractorx", i18n.ErrCodePasswordTooShort, "Use at least 15 characters for the password."},
		{"14 accented characters, though 28 bytes", strings.Repeat("é", 14), i18n.ErrCodePasswordTooShort, "Use at least 15 characters for the password."},
		{"73 bytes", strings.Repeat("violet tractor umbrella ", 3) + "x", i18n.ErrCodePasswordTooLong, tooLongSentence},
		{"37 accented characters, 74 bytes", strings.Repeat("é", 37), i18n.ErrCodePasswordTooLong, tooLongSentence},
		{"the app name, too short before it is too close", "Goiabada", i18n.ErrCodePasswordTooShort, "Use at least 15 characters for the password."},
		{"a listed password", "passwordpassword", i18n.ErrCodePasswordTooCommon, tooCommonSentence},
		{"a listed password capitalised", "PasswordPassword", i18n.ErrCodePasswordTooCommon, tooCommonSentence},
		{"a listed password in capitals", "PASSWORDPASSWORD", i18n.ErrCodePasswordTooCommon, tooCommonSentence},
		{"a listed passphrase", "correcthorsebatterystaple", i18n.ErrCodePasswordTooCommon, tooCommonSentence},
		{"the email address", "jane.doe@example.com", i18n.ErrCodePasswordTooCloseToAccount, tooCloseSentence},
		{"the email address capitalised", "Jane.Doe@Example.com", i18n.ErrCodePasswordTooCloseToAccount, tooCloseSentence},
		{"the email's local part padded", "jane.doe2026!!!!!!", i18n.ErrCodePasswordTooCloseToAccount, tooCloseSentence},
		{"the username repeated and padded", "JaneDoeJaneDoe2026", i18n.ErrCodePasswordTooCloseToAccount, tooCloseSentence},
		{"the app name padded with a year", "goiabada2026!!!!!", i18n.ErrCodePasswordTooCloseToAccount, tooCloseSentence},
		{"the app name repeated", "GoiabadaGoiabada", i18n.ErrCodePasswordTooCloseToAccount, tooCloseSentence},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			assertLocalizedError(t, validator.ValidatePassword(policy, tc.password, janeDoe), tc.code, tc.message)
		})
	}

	// Only the words handed in count: with no account words, the app name padded is just a
	// password of 17 characters.
	t.Run("words not handed in refuse nothing", func(t *testing.T) {
		assert.NoError(t, validator.ValidatePassword(policy, "goiabada2026!!!!!", AccountWords{}))
		assert.NoError(t, validator.ValidatePassword(policy, "jane.doe2026!!!!!!", AccountWords{AppName: "Goiabada"}))
	})
}

// TestPasswordValidator_TheOldPoliciesCheckNoList holds #550 decision 6's last sentence: none,
// low, medium and high check neither the list nor the account's words.
func TestPasswordValidator_TheOldPoliciesCheckNoList(t *testing.T) {
	validator := NewPasswordValidator()
	for _, policy := range []record.PasswordPolicy{
		record.PasswordPolicyNone, record.PasswordPolicyLow,
	} {
		t.Run(policy.String(), func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, "passwordpassword", janeDoe))
			assert.NoError(t, validator.ValidatePassword(policy, "jane.doe@example.com", janeDoe))
		})
	}
	for _, policy := range []record.PasswordPolicy{
		record.PasswordPolicyMedium, record.PasswordPolicyHigh,
	} {
		t.Run(policy.String(), func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, "Passw0rd!Passw0rd!", janeDoe))
			assert.NoError(t, validator.ValidatePassword(policy, "Goiabada2026!!", janeDoe))
		})
	}
}

// TestPasswordValidator_MaximumIsWithinBcrypt holds #409 item 3: no password a form or the API
// accepts is one bcrypt refuses to hash. Held twice, by the constant and by behaviour under every
// policy, so a maximum raised past bcrypt's bound fails here whichever way it is raised.
func TestPasswordValidator_MaximumIsWithinBcrypt(t *testing.T) {
	assert.LessOrEqual(t, maxPasswordBytes, passwordhash.MaxPasswordBytes)

	validator := NewPasswordValidator()
	// Satisfies every policy's character classes, so only the length can refuse it.
	overBcrypt := "Aa1!" + strings.Repeat("a", passwordhash.MaxPasswordBytes+1-4)
	require.Len(t, overBcrypt, passwordhash.MaxPasswordBytes+1)

	for _, policy := range []record.PasswordPolicy{
		record.PasswordPolicyNone, record.PasswordPolicyLow, record.PasswordPolicyMedium, record.PasswordPolicyHigh,
		record.PasswordPolicyNist,
	} {
		t.Run(policy.String(), func(t *testing.T) {
			err := validator.ValidatePassword(policy, overBcrypt, AccountWords{})
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooLong, tooLongSentence)
		})
	}
}

// TestPasswordValidator_AcceptsTheFirstAdministratorsPassword holds #550's correction: the first
// administrator's password is held to bcrypt's bound, in bytes, by core/adminpassword, and the
// first start seeds one that satisfies it; every form and API that sets a password afterwards must
// take that password again, so the two caps cannot disagree silently.
func TestPasswordValidator_AcceptsTheFirstAdministratorsPassword(t *testing.T) {
	validator := NewPasswordValidator()
	// Bcrypt's whole bound, satisfying every policy's character classes: the longest password
	// the first start seeds.
	seeded := "Aa1!" + strings.Repeat("a", passwordhash.MaxPasswordBytes-4)
	require.Len(t, seeded, passwordhash.MaxPasswordBytes)
	require.NoError(t, adminpassword.Check(seeded, "admin@example.com", "Goiabada"), "the first start seeds a password of bcrypt's bound")

	for _, policy := range []record.PasswordPolicy{
		record.PasswordPolicyNone, record.PasswordPolicyLow, record.PasswordPolicyMedium, record.PasswordPolicyHigh,
		record.PasswordPolicyNist,
	} {
		t.Run(policy.String(), func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, seeded, AccountWords{}),
				"a password the first start seeded is refused on the paths that set one later")
		})
	}
}

// tooLongSentence is the English catalog's too-long message at the validator's maximum. It says
// bytes, because the maximum counts them.
const tooLongSentence = "Use at most 72 bytes for the password. " +
	"Accented and other non-English characters count as two or more bytes each."

func TestPasswordValidator_ContainsLowerCase(t *testing.T) {
	validator := NewPasswordValidator()

	if !validator.containsLowerCase("abcDEF") {
		t.Error("Expected true for string containing lowercase")
	}

	if validator.containsLowerCase("ABCDEF") {
		t.Error("Expected false for string not containing lowercase")
	}
}

func TestPasswordValidator_ContainsUpperCase(t *testing.T) {
	validator := NewPasswordValidator()

	if !validator.containsUpperCase("ABCdef") {
		t.Error("Expected true for string containing uppercase")
	}

	if validator.containsUpperCase("abcdef") {
		t.Error("Expected false for string not containing uppercase")
	}
}

func TestPasswordValidator_ContainsNumber(t *testing.T) {
	validator := NewPasswordValidator()

	if !validator.containsNumber("abc123") {
		t.Error("Expected true for string containing number")
	}

	if validator.containsNumber("abcdef") {
		t.Error("Expected false for string not containing number")
	}
}

func TestPasswordValidator_ContainsSpecialChar(t *testing.T) {
	validator := NewPasswordValidator()

	if !validator.containsSpecialChar("abc!@#") {
		t.Error("Expected true for string containing special character")
	}

	if validator.containsSpecialChar("abcdef123") {
		t.Error("Expected false for string not containing special character")
	}
}
