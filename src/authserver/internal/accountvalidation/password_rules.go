package accountvalidation

import (
	"context"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
)

// DescribePasswordRules is the sentence a form that sets a password shows under the field, in the
// language of ctx: the length and the kinds of character PasswordRulesFor answers for policy, in
// the order ValidatePassword checks them. It is empty when the policy asks for a single character,
// which needs no telling. The maximum is left to its refusal, which explains it: it counts bytes,
// so a sentence in characters would misstate it for an accented password, and one in bytes would
// ask every reader what a byte is, for a bound few passwords reach.
//
// A policy refusing common passwords or the account's words adds the guidance NIST SP 800-63B-4
// section 3.1.1.2 asks to be offered ("SHALL offer guidance to the subscriber to help the
// subscriber choose a strong password"), a passphrase, and says what is refused. The nist policy is
// the one refusing either, and refuses both, so the sentence names the two together (#550
// decision 10).
func DescribePasswordRules(ctx context.Context, policy record.PasswordPolicy) string {
	rules := PasswordRulesFor(policy)
	if rules.MinLength <= 1 && !rules.LowerCase && !rules.UpperCase && !rules.Number && !rules.SpecialCharacter {
		return ""
	}
	if rules.RefusesCommon || rules.RefusesAccountWords {
		return strings.Join([]string{
			describeLengthAndKinds(ctx, rules),
			i18n.T(ctx, "password_rules.passphrase_guidance"),
			i18n.T(ctx, "password_rules.common_and_account_refused"),
		}, " ")
	}
	return describeLengthAndKinds(ctx, rules)
}

// describeLengthAndKinds is the sentence naming the length and the kinds of character rules
// requires.
func describeLengthAndKinds(ctx context.Context, rules PasswordRules) string {

	var kinds []string
	for _, kind := range []struct {
		required bool
		key      string
	}{
		{rules.LowerCase, "password_rules.lowercase"},
		{rules.UpperCase, "password_rules.uppercase"},
		{rules.Number, "password_rules.number"},
		{rules.SpecialCharacter, "password_rules.symbol"},
	} {
		if kind.required {
			kinds = append(kinds, i18n.T(ctx, kind.key))
		}
	}

	if len(kinds) == 0 {
		return i18n.T(ctx, "password_rules.length", map[string]any{"min": rules.MinLength})
	}
	requirements := kinds[0]
	if len(kinds) > 1 {
		requirements = i18n.T(ctx, "password_rules.list", map[string]any{
			"items": strings.Join(kinds[:len(kinds)-1], ", "),
			"last":  kinds[len(kinds)-1],
		})
	}
	return i18n.T(ctx, "password_rules.length_with", map[string]any{"min": rules.MinLength, "requirements": requirements})
}
