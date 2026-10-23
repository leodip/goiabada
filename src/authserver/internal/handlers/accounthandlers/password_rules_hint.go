package accounthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/passwordrules"
)

// passwordRulesHint is the sentence the forms that set a password, registration, activation and
// reset, show under the password field: the rules the request's password policy holds a new
// password to, which ValidatePassword applies (#617), worded by core/passwordrules from the rules
// the public settings carry, as the admin console words them (#550 decision 11). A request without
// its settings gets none; its page is refused by the renderer, which reads the same settings.
func passwordRulesHint(r *http.Request) string {
	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		return ""
	}
	return passwordrules.Describe(r.Context(), apimapping.ToPasswordRulesResponse(settings.PasswordPolicy))
}
