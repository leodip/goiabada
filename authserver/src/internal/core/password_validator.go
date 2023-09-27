package core

import (
	"context"
	"fmt"
	"net/http"
	"unicode"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
)

type PasswordValidator struct {
}

func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{}
}

func (val *PasswordValidator) ValidatePassword(ctx context.Context, password string) error {
	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	minLength := 1
	mustIncludeLowerCase := false
	mustIncludeUpperCase := false
	mustIncludeANumber := false
	mustIncludeASpecialChar := false

	if settings.PasswordPolicy == enums.PasswordPolicyLow {
		minLength = 6
	} else if settings.PasswordPolicy == enums.PasswordPolicyMedium {
		minLength = 8
		mustIncludeLowerCase = true
		mustIncludeUpperCase = true
		mustIncludeANumber = true
	} else if settings.PasswordPolicy == enums.PasswordPolicyHigh {
		minLength = 10
		mustIncludeLowerCase = true
		mustIncludeUpperCase = true
		mustIncludeANumber = true
		mustIncludeASpecialChar = true
	}

	if len(password) < minLength {
		return customerrors.NewAppError(nil, "", fmt.Sprintf("The minimum length for the password is %v characters", minLength), http.StatusOK)
	}

	if mustIncludeLowerCase && !val.containsLowerCase(password) {
		return customerrors.NewAppError(nil, "", "As per our policy, a lowercase character is required in the password.", http.StatusOK)
	}

	if mustIncludeUpperCase && !val.containsUpperCase(password) {
		return customerrors.NewAppError(nil, "", "As per our policy, an uppercase character is required in the password.", http.StatusOK)
	}

	if mustIncludeANumber && !val.containsNumber(password) {
		return customerrors.NewAppError(nil, "", "In accordance with our policy, your password must contain a numerical digit.", http.StatusOK)
	}

	if mustIncludeASpecialChar && !val.containsSpecialChar(password) {
		return customerrors.NewAppError(nil, "", "As per our policy, a special character/symbol is required in the password.", http.StatusOK)
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
