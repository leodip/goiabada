package passwordrules

// The sentence a page that sets a password shows under the field names the length and the kinds of
// character the rules require, in the order the auth server's validator checks them, and under rules
// refusing common passwords or the account's words adds the passphrase guidance and what is refused
// (#550 decisions 10 and 11). The rules are the data the public settings carry, so each case here
// is the rules a policy answers, written out.

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

func TestDescribe_TheSentenceNamesEachRule(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules api.PasswordRulesResponse
		want  string
	}{
		{"one character asks nothing", api.PasswordRulesResponse{MinLength: 1}, ""},
		{"no rules at all asks nothing", api.PasswordRulesResponse{}, ""},
		{"a length alone", api.PasswordRulesResponse{MinLength: 6}, "At least 6 characters."},
		{"one kind", api.PasswordRulesResponse{MinLength: 8, RequiresNumber: true},
			"At least 8 characters, with a number."},
		{"three kinds", api.PasswordRulesResponse{MinLength: 8, RequiresLowercase: true, RequiresUppercase: true, RequiresNumber: true},
			"At least 8 characters, with a lowercase letter, an uppercase letter and a number."},
		{"four kinds", api.PasswordRulesResponse{MinLength: 10, RequiresLowercase: true, RequiresUppercase: true,
			RequiresNumber: true, RequiresSymbol: true},
			"At least 10 characters, with a lowercase letter, an uppercase letter, a number and a symbol."},
		// #550 decision 10's hint, word for word.
		{"the nist rules", api.PasswordRulesResponse{MinLength: 15, RefusesCommon: true, RefusesAccountWords: true},
			"At least 15 characters. A few unrelated words make a long password that's easy to remember. " +
				"Common passwords, and the account's email address or the app's name, are refused."},
		{"refusing common passwords alone still guides", api.PasswordRulesResponse{MinLength: 15, RefusesCommon: true},
			"At least 15 characters. A few unrelated words make a long password that's easy to remember. " +
				"Common passwords, and the account's email address or the app's name, are refused."},
		{"refusing the account's words alone still guides", api.PasswordRulesResponse{MinLength: 15, RefusesAccountWords: true},
			"At least 15 characters. A few unrelated words make a long password that's easy to remember. " +
				"Common passwords, and the account's email address or the app's name, are refused."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Describe(context.Background(), tc.rules))
		})
	}
}

func TestDescribe_InThePagesLanguage(t *testing.T) {
	portuguese := i18n.WithLocale(context.Background(), true, "pt-BR")

	assert.Equal(t, "Pelo menos 6 caracteres.", Describe(portuguese, api.PasswordRulesResponse{MinLength: 6}))
	assert.Equal(t, "Pelo menos 10 caracteres, com uma letra minúscula, uma letra maiúscula, um número e um símbolo.",
		Describe(portuguese, api.PasswordRulesResponse{MinLength: 10, RequiresLowercase: true, RequiresUppercase: true,
			RequiresNumber: true, RequiresSymbol: true}))
	//nolint:misspell // the pt-BR catalog's text: "relação" is Portuguese, not a misspelling of "real"
	assert.Equal(t, "Pelo menos 15 caracteres. Algumas palavras sem relação entre si formam uma senha longa e "+
		"fácil de lembrar. Senhas comuns, o endereço de e-mail da conta e o nome do aplicativo são recusados.",
		Describe(portuguese, api.PasswordRulesResponse{MinLength: 15, RefusesCommon: true, RefusesAccountWords: true}))
}
