// Package inputvalidation holds the two input rules both applications apply to text an
// administrator or a registering client supplies: IdentifierValidator, which admits a resource,
// permission, group or client identifier or an attribute key, and ContainsAngleBrackets, the
// predicate the auth server wraps in a localized refusal and the admin console checks a
// permission's description with.
package inputvalidation

import (
	"regexp"
	"strings"

	"github.com/leodip/goiabada/core/i18n"
)

// identifierPattern is the identifier's shape: a letter first, then letters, digits, dashes and
// underscores, ending on a letter or a digit. Compiled once here rather than on every call.
var identifierPattern = regexp.MustCompile(`^[a-zA-Z]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$`)

type IdentifierValidator struct {
}

func NewIdentifierValidator() *IdentifierValidator {
	return &IdentifierValidator{}
}

func (val *IdentifierValidator) Validate(identifier string, enforceMinLength bool) error {
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

	if !identifierPattern.MatchString(identifier) {
		return i18n.NewLocalizedError(i18n.ErrCodeIdentifierInvalidFormat, nil)
	}

	// check if identifier has 2 dashes or underscores in a row
	if strings.Contains(identifier, "--") || strings.Contains(identifier, "__") {
		return i18n.NewLocalizedError(i18n.ErrCodeIdentifierInvalidFormat, nil)
	}

	return nil
}
