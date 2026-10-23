package accountvalidation

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/passwordblocklist"
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

// AccountWords are what a new password must not be, nor a simple derivative of, under a policy
// that refuses the account's details: the account's email address and username and the app's name,
// the "context-specific words, such as the name of the service, the username, and derivatives
// thereof" NIST SP 800-63B-4 section 3.1.1.2 counts among expected passwords (#550 decision 6).
// Each path that sets a password hands in the words it has: a registration has no username yet.
// The email's local part is derived here rather than by each caller, so no two derive it
// differently. An empty word refuses nothing.
type AccountWords struct {
	Email    string
	Username string
	AppName  string
}

// list answers the words a password is compared with: the email, its local part, the username and
// the app name.
func (w AccountWords) list() []string {
	words := []string{w.Email, w.Username, w.AppName}
	if at := strings.LastIndex(w.Email, "@"); at > 0 {
		words = append(words, w.Email[:at])
	}
	return words
}

// PasswordRules is what a password policy asks of a new password. MinLength counts characters and
// MaxBytes bytes. RefusesCommon refuses a password on core/passwordblocklist's list, and
// RefusesAccountWords one that is the account's words or a simple derivative of them.
type PasswordRules struct {
	MinLength           int
	MaxBytes            int
	LowerCase           bool
	UpperCase           bool
	Number              bool
	SpecialCharacter    bool
	RefusesCommon       bool
	RefusesAccountWords bool
}

// PasswordRulesFor answers the rules policy holds a new password to: what ValidatePassword checks,
// and, through apimapping.ToPasswordRulesResponse and core/passwordrules, what a form tells the
// person choosing one, so the form never states a rule the server does not apply, nor applies one it
// does not state (#617, #550 decision 11).
func PasswordRulesFor(policy record.PasswordPolicy) PasswordRules {
	switch policy {
	case record.PasswordPolicyLow:
		return PasswordRules{MinLength: 6, MaxBytes: maxPasswordBytes}
	case record.PasswordPolicyMedium:
		return PasswordRules{MinLength: 8, MaxBytes: maxPasswordBytes, LowerCase: true, UpperCase: true, Number: true}
	case record.PasswordPolicyHigh:
		return PasswordRules{MinLength: 10, MaxBytes: maxPasswordBytes, LowerCase: true, UpperCase: true, Number: true, SpecialCharacter: true}
	case record.PasswordPolicyNist:
		// NIST SP 800-63B-4 section 3.1.1.2: 15 characters for a password that may be the only
		// factor, no other composition rule, and a comparison against commonly used, expected or
		// compromised passwords (#550 decision 1).
		return PasswordRules{MinLength: 15, MaxBytes: maxPasswordBytes, RefusesCommon: true, RefusesAccountWords: true}
	default:
		return PasswordRules{MinLength: 1, MaxBytes: maxPasswordBytes}
	}
}

// ValidatePassword checks password against policy's rules, words being the account's that a policy
// refusing them compares it with. The caller reads the policy and the app name off its settings,
// so this reads nothing from the request (#433).
func (val *PasswordValidator) ValidatePassword(policy record.PasswordPolicy, password string, words AccountWords) error {
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

	// The two refusals ask for different remedies, choosing something less common against leaving
	// the account's details out, so each has its own message and code (#550 decision 10).
	if rules.RefusesCommon && passwordblocklist.IsCommon(password) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordTooCommon, nil)
	}

	if rules.RefusesAccountWords && passwordblocklist.IsTooClose(password, words.list()...) {
		return i18n.NewLocalizedError(i18n.ErrCodePasswordTooCloseToAccount, nil)
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
