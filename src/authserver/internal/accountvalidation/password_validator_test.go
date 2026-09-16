package accountvalidation

import (
	"context"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestPasswordValidator_ValidatePassword(t *testing.T) {
	validator := NewPasswordValidator()

	t.Run("PasswordPolicyLow", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
			PasswordPolicy: enums.PasswordPolicyLow,
		})

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "123456")
			assert.NoError(t, err)
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "12345")
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooShort,
				"The minimum length for the password is 6 characters")
		})

		t.Run("TooLong", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, strings.Repeat("a", 65))
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooLong,
				"The maximum length for the password is 64 characters")
		})
	})

	t.Run("PasswordPolicyMedium", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
			PasswordPolicy: enums.PasswordPolicyMedium,
		})

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "Passw0rd")
			assert.NoError(t, err)
		})

		t.Run("MissingUppercase", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "passw0rd")
			assertLocalizedError(t, err, i18n.ErrCodePasswordUppercaseRequired,
				"As per our policy, an uppercase character is required in the password.")
		})

		t.Run("MissingLowercase", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "PASSW0RD")
			assertLocalizedError(t, err, i18n.ErrCodePasswordLowercaseRequired,
				"As per our policy, a lowercase character is required in the password.")
		})

		t.Run("MissingNumber", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "Password")
			assertLocalizedError(t, err, i18n.ErrCodePasswordNumberRequired,
				"As per our policy, your password must contain a numerical digit.")
		})
	})

	t.Run("PasswordPolicyHigh", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
			PasswordPolicy: enums.PasswordPolicyHigh,
		})

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "P@ssw0rd123")
			assert.NoError(t, err)
		})

		t.Run("MissingSpecialChar", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "Passw0rd123")
			assertLocalizedError(t, err, i18n.ErrCodePasswordSpecialCharRequired,
				"As per our policy, a special character/symbol is required in the password.")
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "P@ss1")
			assertLocalizedError(t, err, i18n.ErrCodePasswordTooShort,
				"The minimum length for the password is 10 characters")
		})
	})
}

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
