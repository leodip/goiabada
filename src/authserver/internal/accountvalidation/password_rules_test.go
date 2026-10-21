package accountvalidation

// The rules a form that sets a password describes are the rules the validator applies: a password
// built to meet exactly what PasswordRulesFor answers passes, one short of the length, one byte
// past the maximum or missing a required kind of character fails, one lacking a kind that is not
// required passes, and the sentence DescribePasswordRules shows names the length and the kinds.

import (
	"context"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var everyPasswordPolicy = []record.PasswordPolicy{
	record.PasswordPolicyNone, record.PasswordPolicyLow, record.PasswordPolicyMedium, record.PasswordPolicyHigh,
}

// passwordKinds are the kinds of character a policy may require, each with one character of it.
var passwordKinds = []struct {
	name     string
	char     string
	required func(PasswordRules) bool
}{
	{"lowercase", "a", func(r PasswordRules) bool { return r.LowerCase }},
	{"uppercase", "A", func(r PasswordRules) bool { return r.UpperCase }},
	{"number", "1", func(r PasswordRules) bool { return r.Number }},
	{"symbol", "!", func(r PasswordRules) bool { return r.SpecialCharacter }},
}

// passwordFor builds a password of length characters holding one character of every kind rules
// requires except the one named without, padded with a character of no kind named without.
func passwordFor(rules PasswordRules, length int, without string) string {
	var b strings.Builder
	for _, kind := range passwordKinds {
		if kind.required(rules) && kind.name != without {
			b.WriteString(kind.char)
		}
	}
	pad := "a"
	if without == "lowercase" {
		pad = "A"
	}
	for b.Len() < length {
		b.WriteString(pad)
	}
	return b.String()
}

func TestPasswordRules_TheValidatorAppliesWhatTheFormDescribes(t *testing.T) {
	validator := NewPasswordValidator()
	for _, policy := range everyPasswordPolicy {
		rules := PasswordRulesFor(policy)
		t.Run(policy.String(), func(t *testing.T) {
			require.NoError(t, validator.ValidatePassword(policy, passwordFor(rules, rules.MinLength, "")),
				"a password meeting exactly the described rules is refused")
			if rules.MinLength > 1 {
				require.Error(t, validator.ValidatePassword(policy, passwordFor(rules, rules.MinLength-1, "")),
					"a password one character short of the described length passed")
			}
			require.NoError(t, validator.ValidatePassword(policy, passwordFor(rules, rules.MaxBytes, "")),
				"a password of exactly the maximum bytes is refused")
			require.Error(t, validator.ValidatePassword(policy, passwordFor(rules, rules.MaxBytes+1, "")),
				"a password one byte past the maximum passed")
			// The maximum counts bytes: "é" is one lowercase letter of two bytes.
			accented := passwordFor(rules, rules.MinLength, "")
			if (rules.MaxBytes-len(accented))%2 == 1 {
				accented += "a"
			}
			accented += strings.Repeat("é", (rules.MaxBytes-len(accented))/2)
			require.NoError(t, validator.ValidatePassword(policy, accented),
				"an accented password of exactly the maximum bytes is refused")
			require.Error(t, validator.ValidatePassword(policy, accented+"é"),
				"an accented password past the maximum bytes, though not past it in characters, passed")
			for _, kind := range passwordKinds {
				password := passwordFor(rules, rules.MinLength, kind.name)
				if kind.required(rules) {
					require.Error(t, validator.ValidatePassword(policy, password),
						"a password with no %s character passed, although the form says one is required", kind.name)
				} else {
					require.NoError(t, validator.ValidatePassword(policy, password),
						"a password with no %s character was refused, although the form does not ask for one", kind.name)
				}
			}
		})
	}
}

func TestPasswordRules_TheSentenceNamesEachRule(t *testing.T) {
	english := map[record.PasswordPolicy]string{
		record.PasswordPolicyNone:   "",
		record.PasswordPolicyLow:    "At least 6 characters.",
		record.PasswordPolicyMedium: "At least 8 characters, with a lowercase letter, an uppercase letter and a number.",
		record.PasswordPolicyHigh:   "At least 10 characters, with a lowercase letter, an uppercase letter, a number and a symbol.",
	}
	for _, policy := range everyPasswordPolicy {
		assert.Equal(t, english[policy], DescribePasswordRules(context.Background(), policy), "policy %s", policy)
	}

	portuguese := i18n.WithLocale(context.Background(), true, "pt-BR")
	assert.Equal(t, "Pelo menos 6 caracteres.", DescribePasswordRules(portuguese, record.PasswordPolicyLow))
	assert.Equal(t, "Pelo menos 10 caracteres, com uma letra minúscula, uma letra maiúscula, um número e um símbolo.",
		DescribePasswordRules(portuguese, record.PasswordPolicyHigh))
}
