package render

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/passwordrules"
)

// PasswordRulesHint is the sentence the pages that set a password, Account > Change password,
// Admin > Users > New user and a user's Authentication tab, show under the new password's field:
// the stored policy's rules, as the auth server's public settings carry them, worded by
// core/passwordrules as the auth server's registration, activation and reset forms word them (#550
// decision 11). A request without its settings gets none; its page is refused by the renderer,
// which reads the same settings.
func PasswordRulesHint(r *http.Request) string {
	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		return ""
	}
	return passwordrules.Describe(r.Context(), settings.PasswordRules)
}
