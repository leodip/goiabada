package validators

import (
	"context"
	"unicode"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
)

type PasswordValidator struct {
}

func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{}
}

func (val *PasswordValidator) ValidatePassword(ctx context.Context, password string) error {
	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	minLength := 1
	maxLength := 64
	mustIncludeLowerCase := false
	mustIncludeUpperCase := false
	mustIncludeANumber := false
	mustIncludeASpecialChar := false

	switch settings.PasswordPolicy {
	case enums.PasswordPolicyLow:
		minLength = 6
	case enums.PasswordPolicyMedium:
		minLength = 8
		mustIncludeLowerCase = true
		mustIncludeUpperCase = true
		mustIncludeANumber = true
	case enums.PasswordPolicyHigh:
		minLength = 10
		mustIncludeLowerCase = true
		mustIncludeUpperCase = true
		mustIncludeANumber = true
		mustIncludeASpecialChar = true
	}

	// i18n surface: A | C — registration, reset-password, account API,
	// admin user CRUD.
	if len(password) < minLength {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordTooShort, map[string]any{"min": minLength})
	}

	if len(password) > maxLength {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordTooLong, map[string]any{"max": maxLength})
	}

	if mustIncludeLowerCase && !val.containsLowerCase(password) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordLowercaseRequired, nil)
	}

	if mustIncludeUpperCase && !val.containsUpperCase(password) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordUppercaseRequired, nil)
	}

	if mustIncludeANumber && !val.containsNumber(password) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordNumberRequired, nil)
	}

	if mustIncludeASpecialChar && !val.containsSpecialChar(password) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordSpecialCharRequired, nil)
	}

	return nil
}

func (val *PasswordValidator) containsLowerCase(s string) bool {
	for _, char := range s {
		if unicode.IsLower(char) {
			return true
		}
	}
	return false
}

func (val *PasswordValidator) containsUpperCase(s string) bool {
	for _, char := range s {
		if unicode.IsUpper(char) {
			return true
		}
	}
	return false
}

func (val *PasswordValidator) containsNumber(s string) bool {
	for _, char := range s {
		if unicode.IsNumber(char) {
			return true
		}
	}
	return false
}

func (val *PasswordValidator) containsSpecialChar(s string) bool {
	for _, char := range s {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) {
			return true
		}
	}
	return false
}
