package validators

import (
	"context"
	"fmt"
	"unicode"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/enums"
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

	if len(password) < minLength {
		return customerrors.NewErrorDetail("", fmt.Sprintf("The minimum length for the password is %v characters", minLength))
	}

	if len(password) > maxLength {
		return customerrors.NewErrorDetail("", fmt.Sprintf("The maximum length for the password is %v characters", maxLength))
	}

	if mustIncludeLowerCase && !val.containsLowerCase(password) {
		return customerrors.NewErrorDetail("", "As per our policy, a lowercase character is required in the password.")
	}

	if mustIncludeUpperCase && !val.containsUpperCase(password) {
		return customerrors.NewErrorDetail("", "As per our policy, an uppercase character is required in the password.")
	}

	if mustIncludeANumber && !val.containsNumber(password) {
		return customerrors.NewErrorDetail("", "As per our policy, your password must contain a numerical digit.")
	}

	if mustIncludeASpecialChar && !val.containsSpecialChar(password) {
		return customerrors.NewErrorDetail("", "As per our policy, a special character/symbol is required in the password.")
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
