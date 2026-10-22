package accounthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// passwordRulesHint is the sentence the forms that set a password, registration, activation and
// reset, show under the password field: the rules the request's password policy holds a new
// password to, which ValidatePassword applies (#617). A request without its settings gets none;
// its page is refused by the renderer, which reads the same settings.
func passwordRulesHint(r *http.Request) string {
	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		return ""
	}
	return accountvalidation.DescribePasswordRules(r.Context(), settings.PasswordPolicy)
}
