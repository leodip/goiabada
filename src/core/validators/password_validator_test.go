package validators

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

func assertLocalizedCode(t *testing.T, err error, expectedCode string) {
	t.Helper()
	assert.Error(t, err)
	locErr, ok := err.(*i18n.LocalizedError)
	assert.True(t, ok, "expected *i18n.LocalizedError, got %T", err)
	if ok {
		assert.Equal(t, expectedCode, locErr.Code)
	}
}

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
			assertLocalizedCode(t, err, i18n.ErrCodePasswordTooShort)
		})

		t.Run("TooLong", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, strings.Repeat("a", 65))
			assertLocalizedCode(t, err, i18n.ErrCodePasswordTooLong)
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
			assertLocalizedCode(t, err, i18n.ErrCodePasswordUppercaseRequired)
		})

		t.Run("MissingLowercase", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "PASSW0RD")
			assertLocalizedCode(t, err, i18n.ErrCodePasswordLowercaseRequired)
		})

		t.Run("MissingNumber", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "Password")
			assertLocalizedCode(t, err, i18n.ErrCodePasswordNumberRequired)
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
			assertLocalizedCode(t, err, i18n.ErrCodePasswordSpecialCharRequired)
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "P@ss1")
			assertLocalizedCode(t, err, i18n.ErrCodePasswordTooShort)
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
