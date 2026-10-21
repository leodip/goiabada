package accountvalidation

import (
	"unicode"
	"unicode/utf8"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
)

// maxPasswordBytes is the longest password any form or API accepts: passwordhash.MaxPasswordBytes
// itself, bcrypt's bound, counted in the unit bcrypt counts. The first administrator's password is
// held to the same bound, which core/adminpassword states in bytes, so a password the first start
// seeds is accepted on every later path too rather than refused as too long (#550). A lower
// constant makes the two disagree; a higher one turns a validation message into a failed hash on
// every path that sets a password, because past passwordhash.MaxPasswordBytes bcrypt refuses to
// hash at all (#409). The test file holds it there.
const maxPasswordBytes = passwordhash.MaxPasswordBytes

type PasswordValidator struct {
}

func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{}
}

// PasswordRules is what a password policy asks of a new password. MinLength counts characters and
// MaxBytes bytes.
type PasswordRules struct {
	MinLength        int
	MaxBytes         int
	LowerCase        bool
	UpperCase        bool
	Number           bool
	SpecialCharacter bool
}

// PasswordRulesFor answers the rules policy holds a new password to: what ValidatePassword checks,
// and what DescribePasswordRules tells the person choosing one, so the form never states a rule
// the server does not apply, nor applies one it does not state (#617).
func PasswordRulesFor(policy record.PasswordPolicy) PasswordRules {
	switch policy {
	case record.PasswordPolicyLow:
		return PasswordRules{MinLength: 6, MaxBytes: maxPasswordBytes}
	case record.PasswordPolicyMedium:
		return PasswordRules{MinLength: 8, MaxBytes: maxPasswordBytes, LowerCase: true, UpperCase: true, Number: true}
	case record.PasswordPolicyHigh:
		return PasswordRules{MinLength: 10, MaxBytes: maxPasswordBytes, LowerCase: true, UpperCase: true, Number: true, SpecialCharacter: true}
	default:
		return PasswordRules{MinLength: 1, MaxBytes: maxPasswordBytes}
	}
}

// ValidatePassword checks password against policy's rules. The caller reads the policy off its
// settings, so this reads nothing from the request (#433).
func (val *PasswordValidator) ValidatePassword(policy record.PasswordPolicy, password string) error {
	rules := PasswordRulesFor(policy)

	// i18n surface: A | C — registration, reset-password, account API,
	// admin user CRUD.
	//
	// The minimum counts characters, which is what its message says and what a user counts; the
	// maximum counts bytes, because it guards bcrypt's bound, and its message says bytes. Counting
	// the minimum in bytes let three accented characters pass a six-character policy (#409).
	if utf8.RuneCountInString(password) < rules.MinLength {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordTooShort, map[string]any{"min": rules.MinLength})
	}

	if len(password) > rules.MaxBytes {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordTooLong, map[string]any{"max": rules.MaxBytes})
	}

	if rules.LowerCase && !val.containsLowerCase(password) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordLowercaseRequired, nil)
	}

	if rules.UpperCase && !val.containsUpperCase(password) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordUppercaseRequired, nil)
	}

	if rules.Number && !val.containsNumber(password) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordNumberRequired, nil)
	}

	if rules.SpecialCharacter && !val.containsSpecialChar(password) {
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
