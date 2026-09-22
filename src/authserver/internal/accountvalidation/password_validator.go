package accountvalidation

import (
	"context"
	"unicode"
	"unicode/utf8"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/i18n"
)

// maxPasswordBytes is the longest password any form or API accepts. It counts bytes, the unit
// bcrypt counts, and must stay at or below passwordhash.MaxPasswordBytes, where bcrypt refuses to
// hash at all: a raise past it turns a validation message into a failed hash on every path that
// sets a password (#409). The test file holds it there.
const maxPasswordBytes = 64

type PasswordValidator struct {
}

func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{}
}

func (val *PasswordValidator) ValidatePassword(ctx context.Context, password string) error {
	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	minLength := 1
	mustIncludeLowerCase := false
	mustIncludeUpperCase := false
	mustIncludeANumber := false
	mustIncludeASpecialChar := false

	switch settings.PasswordPolicy {
	case models.PasswordPolicyLow:
		minLength = 6
	case models.PasswordPolicyMedium:
		minLength = 8
		mustIncludeLowerCase = true
		mustIncludeUpperCase = true
		mustIncludeANumber = true
	case models.PasswordPolicyHigh:
		minLength = 10
		mustIncludeLowerCase = true
		mustIncludeUpperCase = true
		mustIncludeANumber = true
		mustIncludeASpecialChar = true
	}

	// i18n surface: A | C — registration, reset-password, account API,
	// admin user CRUD.
	//
	// The minimum counts characters, which is what its message says and what a user counts; the
	// maximum counts bytes, because it guards bcrypt's bound, and its message says bytes. Counting
	// the minimum in bytes let three accented characters pass a six-character policy (#409).
	if utf8.RuneCountInString(password) < minLength {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordTooShort, map[string]any{"min": minLength})
	}

	if len(password) > maxPasswordBytes {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordTooLong, map[string]any{"max": maxPasswordBytes})
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
