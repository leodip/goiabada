// Package passwordrules words the stored password policy's rules for the person choosing a
// password. Both applications show the sentence under a new password's field, the auth server on its
// registration, activation and reset forms and the admin console on its change-password, new user
// and Authentication tab pages, and both build it here from the same rules, the ones the public
// settings carry, so the two cannot word the same rules differently (#550 decision 11).
package passwordrules

import (
	"context"
	"strings"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// Describe is the sentence a page that sets a password shows under the field, in the language of
// ctx: the length and the kinds of character rules requires, in the order the auth server's
// validator checks them. It is empty when the rules ask for a single character, which needs no
// telling. The maximum is left to its refusal, which explains it: it counts bytes, so a sentence in
// characters would misstate it for an accented password, and one in bytes would ask every reader
// what a byte is, for a bound few passwords reach.
//
// Rules refusing common passwords or the account's words add the guidance NIST SP 800-63B-4
// section 3.1.1.2 asks to be offered ("SHALL offer guidance to the subscriber to help the
// subscriber choose a strong password"), a passphrase, and say what is refused. The nist policy is
// the one refusing either, and refuses both, so the sentence names the two together (#550
// decision 10).
func Describe(ctx context.Context, rules api.PasswordRulesResponse) string {
	if rules.MinLength <= 1 && !rules.RequiresLowercase && !rules.RequiresUppercase && !rules.RequiresNumber &&
		!rules.RequiresSymbol && !rules.RefusesCommon && !rules.RefusesAccountWords {
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
func describeLengthAndKinds(ctx context.Context, rules api.PasswordRulesResponse) string {
	var kinds []string
	for _, kind := range []struct {
		required bool
		key      string
	}{
		{rules.RequiresLowercase, "password_rules.lowercase"},
		{rules.RequiresUppercase, "password_rules.uppercase"},
		{rules.RequiresNumber, "password_rules.number"},
		{rules.RequiresSymbol, "password_rules.symbol"},
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
