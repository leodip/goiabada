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
// which needs no telling.
func DescribePasswordRules(ctx context.Context, policy record.PasswordPolicy) string {
	rules := PasswordRulesFor(policy)
	if rules.MinLength <= 1 && !rules.LowerCase && !rules.UpperCase && !rules.Number && !rules.SpecialCharacter {
		return ""
	}

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
