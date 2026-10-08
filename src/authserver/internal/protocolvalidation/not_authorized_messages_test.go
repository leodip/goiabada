package protocolvalidation

import (
	"context"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// quotedConsoleLabel is a place in the admin console a refusal names, in the single quotes the
// message puts it in. The opening quote follows a space, which tells it from the apostrophe in
// "the client's settings".
var quotedConsoleLabel = regexp.MustCompile(`\s'([^']+)'`)

// TestNotAuthorizedMessages_NameConsolePlacesTheConsoleHas: the ROPC and implicit refusals tell
// the operator where to turn the grant on, per client and globally. Both sent them to
// 'Settings > General', a menu the admin console doesn't have: the global switches are under
// Admin, then General. Every place either message quotes is built here from the English catalog's
// own labels, so renaming a menu or a tab fails this test until the messages follow it.
func TestNotAuthorizedMessages_NameConsolePlacesTheConsoleHas(t *testing.T) {
	ctx := context.Background()
	places := map[string]bool{
		i18n.Raw(ctx, "adminconsole.client_tabs.oauth2_flows"):                                                       true,
		i18n.Raw(ctx, "adminconsole.menu.admin") + " > " + i18n.Raw(ctx, "adminconsole.admin_menu.settings_general"): true,
	}

	for name, message := range map[string]string{
		"ROPCNotAuthorizedErrorMsg":     ROPCNotAuthorizedErrorMsg,
		"ImplicitNotAuthorizedErrorMsg": ImplicitNotAuthorizedErrorMsg,
	} {
		quoted := quotedConsoleLabel.FindAllStringSubmatch(message, -1)
		require.Lenf(t, quoted, 2, "%s names the client's tab and the global switch's menu", name)
		for _, q := range quoted {
			assert.Truef(t, places[q[1]], "%s names '%s', which the admin console's English catalog doesn't label; it has %v",
				name, q[1], places)
		}
	}
}
