package validators

import (
	"context"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

func TestPasswordValidator_ValidatePassword(t *testing.T) {
	validator := NewPasswordValidator()

	t.Run("PasswordPolicyLow", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
			PasswordPolicy: enums.PasswordPolicyLow,
		})

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "123456")
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "12345")
			if err == nil {
				t.Error("Expected error for too short password, got nil")
			}
		})

		t.Run("TooLong", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, strings.Repeat("a", 65))
			if err == nil {
				t.Error("Expected error for too long password, got nil")
			}
		})
	})

	t.Run("PasswordPolicyMedium", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
			PasswordPolicy: enums.PasswordPolicyMedium,
		})

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "Passw0rd")
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})

		t.Run("MissingUppercase", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "passw0rd")
			if err == nil {
				t.Error("Expected error for missing uppercase, got nil")
			}
		})

		t.Run("MissingLowercase", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "PASSW0RD")
			if err == nil {
				t.Error("Expected error for missing lowercase, got nil")
			}
		})

		t.Run("MissingNumber", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "Password")
			if err == nil {
				t.Error("Expected error for missing number, got nil")
			}
		})
	})

	t.Run("PasswordPolicyHigh", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
			PasswordPolicy: enums.PasswordPolicyHigh,
		})

		t.Run("ValidPassword", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "P@ssw0rd123")
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})

		t.Run("MissingSpecialChar", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "Passw0rd123")
			if err == nil {
				t.Error("Expected error for missing special char, got nil")
			}
		})

		t.Run("TooShort", func(t *testing.T) {
			err := validator.ValidatePassword(ctx, "P@ss1")
			if err == nil {
				t.Error("Expected error for too short password, got nil")
			}
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
