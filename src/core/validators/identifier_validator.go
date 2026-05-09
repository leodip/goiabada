package validators

import (
	"strings"

	"regexp"

	"github.com/leodip/goiabada/core/i18n"
)

type IdentifierValidator struct {
}

func NewIdentifierValidator() *IdentifierValidator {
	return &IdentifierValidator{}
}

func (val *IdentifierValidator) ValidateIdentifier(identifier string, enforceMinLength bool) error {
	const maxLength = 38
	// i18n surface: A | C — browser-flow handlers and admin/account API.
	if len(identifier) > maxLength {
		return i18n.NewLocalizedError(i18n.ErrCodeIdentifierTooLong, map[string]any{"max": maxLength})
	}

	if enforceMinLength {
		const minLength = 3
		if len(identifier) < minLength {
			return i18n.NewLocalizedError(i18n.ErrCodeIdentifierTooShort, map[string]any{"min": minLength})
		}
	}

	match, _ := regexp.MatchString("^[a-zA-Z]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$", identifier)
	if !match {
		return i18n.NewLocalizedError(i18n.ErrCodeIdentifierInvalidFormat, nil)
	}

	// check if identifier has 2 dashes or underscores in a row
	if strings.Contains(identifier, "--") || strings.Contains(identifier, "__") {
		return i18n.NewLocalizedError(i18n.ErrCodeIdentifierInvalidFormat, nil)
	}

	return nil
}
