package apihandlers

import (
	"strings"

	"github.com/leodip/goiabada/core/stringutil"
)

// generateEmailVerificationCode returns the code an email verification check compares
// against: four uppercase letters followed by four digits.
//
// 26^4 x 10^4 is 32.1 bits, up from the 24.1 of the three-plus-three code this replaces. The
// width matters independently of the rate limiter in front of the check, because the limiter
// is off unless a deployment enables it: at a couple of thousand guesses a second the old
// code fell in about an hour, where this one takes on the order of a fortnight. Entropy
// protects every deployment; the limiter protects the ones that configured it (#219).
//
// The alphabet is single-case on purpose. The comparison accepts a code in either case, so
// an alphabet carrying both would halve the space and let two distinct codes compare equal.
//
// One function for both call sites, the account's own verification and the admin-triggered
// one, so the format cannot drift between the code that is sent and the code that is
// checked.
func generateEmailVerificationCode() string {
	return strings.ToUpper(stringutil.GenerateRandomLetterString(4)) +
		stringutil.GenerateRandomNumberString(4)
}
