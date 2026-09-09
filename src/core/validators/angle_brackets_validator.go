package validators

import (
	"strings"

	"github.com/leodip/goiabada/core/i18n"
)

// ContainsAngleBrackets reports whether s holds "<" or ">".
func ContainsAngleBrackets(s string) bool { return strings.ContainsAny(s, "<>") }

// ValidateNoAngleBrackets refuses a value holding "<" or ">" with the caller's code, so the
// localized message names the field (#275). Empty is accepted; the field's own rules decide
// whether it may be empty.
//
// The two characters are refused rather than stripped: the HTML sanitizer this replaced did not
// have one behaviour but three, dropping everything from a "<" to the next ">", rewriting a bare
// ">" to the literal text "&gt;", and passing its own allowlist of tags through untouched. A value
// that is accepted here is stored exactly as it was sent, which is what makes every field readable
// back byte for byte. Relaxing this to a strip reintroduces the corruption on ordinary text such
// as "x > y".
//
// Only "<" and ">" are refused. Ampersands and entities are harmless at every sink this repository
// has, and refusing "&" would break "Tom & Jerry" in a description.
func ValidateNoAngleBrackets(value string, code string) error {
	if ContainsAngleBrackets(value) {
		return i18n.NewLocalizedError(code, nil)
	}
	return nil
}
