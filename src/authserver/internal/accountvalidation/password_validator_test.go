package accountvalidation

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordValidator_ValidatePassword(t *testing.T) {
	validator := NewPasswordValidator()

	t.Run("PasswordPolicyLow", func(t *testing.T) {
		policy := record.PasswordPolicyLow

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "123456")
			assert.NoError(t, err)
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "12345")
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooShort,
				"Use at least 6 characters for the password.")
		})

		t.Run("TooLong", func(t *testing.T) {
			err := validator.ValidatePassword(policy, strings.Repeat("a", 65))
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooLong, tooLongSentence)
		})

		// Accented rows either side of both bounds. "é" is one character and two bytes, so the
		// same string can be long enough in characters and too long in bytes (#409).
		t.Run("AccentedBelowMinimum", func(t *testing.T) {
			err := validator.ValidatePassword(policy, strings.Repeat("é", 5))
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooShort,
				"Use at least 6 characters for the password.")
		})

		t.Run("AccentedAtMinimum", func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, strings.Repeat("é", 6)))
		})

		t.Run("AccentedAtMaximum", func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, strings.Repeat("é", 32)))
		})

		t.Run("AccentedOverMaximum", func(t *testing.T) {
			err := validator.ValidatePassword(policy, strings.Repeat("é", 33))
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooLong, tooLongSentence)
		})

		t.Run("ASCIIAtMaximum", func(t *testing.T) {
			assert.NoError(t, validator.ValidatePassword(policy, strings.Repeat("a", 64)))
		})
	})

	t.Run("PasswordPolicyMedium", func(t *testing.T) {
		policy := record.PasswordPolicyMedium

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "Passw0rd")
			assert.NoError(t, err)
		})

		t.Run("MissingUppercase", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "passw0rd")
			assertLocalizedError(t, err, i18n.ErrCodePasswordUppercaseRequired,
				"Add an uppercase letter to the password.")
		})

		t.Run("MissingLowercase", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "PASSW0RD")
			assertLocalizedError(t, err, i18n.ErrCodePasswordLowercaseRequired,
				"Add a lowercase letter to the password.")
		})

		t.Run("MissingNumber", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "Password")
			assertLocalizedError(t, err, i18n.ErrCodePasswordNumberRequired,
				"Add a number to the password.")
		})
	})

	t.Run("PasswordPolicyHigh", func(t *testing.T) {
		policy := record.PasswordPolicyHigh

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "P@ssw0rd123")
			assert.NoError(t, err)
		})

		t.Run("MissingSpecialChar", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "Passw0rd123")
			assertLocalizedError(t, err, i18n.ErrCodePasswordSpecialCharRequired,
				"Add a symbol to the password.")
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(policy, "P@ss1")
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooShort,
				"Use at least 10 characters for the password.")
		})
	})
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
	} {
		t.Run(policy.String(), func(t *testing.T) {
			err := validator.ValidatePassword(policy, overBcrypt)
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooLong, tooLongSentence)
		})
	}
}

// tooLongSentence is the English catalog's too-long message at the validator's maximum. It says
// bytes, because the maximum counts them.
const tooLongSentence = "Use at most 64 bytes for the password. " +
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
