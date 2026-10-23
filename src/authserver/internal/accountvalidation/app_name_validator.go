package accountvalidation

import (
	"strings"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// MaxAppNameLength is the longest App name, in inputvalidation.TextLength's units, once trimmed.
// The authenticator key generator allows 32, so every name this rule accepts is one it can mint a
// key under.
const MaxAppNameLength = 30

// ValidateAppName answers the App name as stored, trimmed, or the refusal of it: empty once trimmed,
// longer than MaxAppNameLength once trimmed, or holding an angle bracket. It is the one rule the
// general settings save and the first start's GOIABADA_APPNAME are held to, so the two cannot
// disagree on which names a deployment can have. The first start never asks it about a blank name:
// an unset variable there means the default (#646 decisions 3 and 7).
func ValidateAppName(appName string) (string, error) {
	trimmed := strings.TrimSpace(appName)
	if trimmed == "" {
		return "", i18n.NewLocalizedError(i18n.ErrCodeSettingsGeneralAppNameRequired, nil)
	}
	if inputvalidation.TextLength(trimmed) > MaxAppNameLength {
		return "", i18n.NewLocalizedError(i18n.ErrCodeSettingsGeneralAppNameTooLong, map[string]any{"max": MaxAppNameLength})
	}
	if err := ValidateNoAngleBrackets(trimmed, i18n.ErrCodeSettingsAppNameAngleBrackets); err != nil {
		return "", err
	}
	return trimmed, nil
}
