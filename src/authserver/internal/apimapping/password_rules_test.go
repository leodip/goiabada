package apimapping

// The public settings carry the stored policy's rules as data, and both applications build the hint
// a page that sets a password shows from them through core/passwordrules (#550 decision 11). Each
// policy's rules are written out here, and the sentence each one gives, so a rule the validator
// applies and the wire leaves out, or the reverse, fails here.

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/passwordrules"
	"github.com/stretchr/testify/assert"
)

func TestToPasswordRulesResponse_EachPolicysRules(t *testing.T) {
	for _, tc := range []struct {
		policy   record.PasswordPolicy
		rules    api.PasswordRulesResponse
		sentence string
	}{
		{record.PasswordPolicyNone, api.PasswordRulesResponse{MinLength: 1}, ""},
		{record.PasswordPolicyLow, api.PasswordRulesResponse{MinLength: 6}, "At least 6 characters."},
		{record.PasswordPolicyMedium,
			api.PasswordRulesResponse{MinLength: 8, RequiresLowercase: true, RequiresUppercase: true, RequiresNumber: true},
			"At least 8 characters, with a lowercase letter, an uppercase letter and a number."},
		{record.PasswordPolicyHigh,
			api.PasswordRulesResponse{MinLength: 10, RequiresLowercase: true, RequiresUppercase: true, RequiresNumber: true,
				RequiresSymbol: true},
			"At least 10 characters, with a lowercase letter, an uppercase letter, a number and a symbol."},
		// #550 decision 10's hint, word for word.
		{record.PasswordPolicyNist, api.PasswordRulesResponse{MinLength: 15, RefusesCommon: true, RefusesAccountWords: true},
			"At least 15 characters. A few unrelated words make a long password that's easy to remember. " +
				"Common passwords, and the account's email address or the app's name, are refused."},
	} {
		t.Run(tc.policy.String(), func(t *testing.T) {
			rules := ToPasswordRulesResponse(tc.policy)
			assert.Equal(t, tc.rules, rules)
			assert.Equal(t, tc.sentence, passwordrules.Describe(context.Background(), rules))
		})
	}
}
