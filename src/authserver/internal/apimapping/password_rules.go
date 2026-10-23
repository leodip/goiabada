package apimapping

import (
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// ToPasswordRulesResponse is the rules policy holds a new password to, as the public settings carry
// them and as core/passwordrules words them: those accountvalidation.PasswordRulesFor answers, which
// ValidatePassword applies, so neither application's hint states a rule the validator does not
// apply, nor leaves out one it does (#550 decision 11). The maximum stays behind, as the sentence
// leaves it to its refusal.
func ToPasswordRulesResponse(policy record.PasswordPolicy) api.PasswordRulesResponse {
	rules := accountvalidation.PasswordRulesFor(policy)
	return api.PasswordRulesResponse{
		MinLength:           rules.MinLength,
		RequiresLowercase:   rules.LowerCase,
		RequiresUppercase:   rules.UpperCase,
		RequiresNumber:      rules.Number,
		RequiresSymbol:      rules.SpecialCharacter,
		RefusesCommon:       rules.RefusesCommon,
		RefusesAccountWords: rules.RefusesAccountWords,
	}
}
