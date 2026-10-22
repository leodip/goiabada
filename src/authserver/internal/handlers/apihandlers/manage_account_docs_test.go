package apihandlers

// The documentation of who may get authserver:manage-account, the Account API's scope, held to the
// code (#509).
//
// The Scopes page said any client that signs a user in can ask for it, which was true and was the
// defect: every user holds manage-account, so any client with Consent required off got an Account
// API token for whoever was signed in, with no screen shown. A client other than the admin console's
// now gets it only once the user's stored consent covers it, so the Scopes page and the Account API
// setup say so, the setup says what a refresh and prompt=none are answered until the user has
// consented, and the Clients page's administrative-scopes section no longer says the consent screen
// follows Consent required alone. The authentication page also names the three ways an application
// changes a user's account: the Account API with the user's token, the Admin API with the client's
// own token, and a link to the admin console's Account pages.
//
// It reads files and nothing else.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/userconsent"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/i18n"
)

// The sections that say who gets authserver:manage-account.
var (
	accountScopeSection      = docSection{apiScopesPage, "## The Account API scope"}
	accountChangeWaysSection = docSection{apiAuthenticationPage, "## Change a user's account from your app"}
)

// manageAccountScope is the scope userconsent owes a consent for whatever the client says, read from
// the rule rather than spelled here, so a page naming another scope fails.
func manageAccountScope(t *testing.T) string {
	t.Helper()
	asked := builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier
	owed := userconsent.AlwaysOwed("my-app", "openid "+asked)
	if len(owed) != 1 || owed[0] != asked {
		t.Fatalf("userconsent.AlwaysOwed owes %q for %q, not the Account API's scope alone", owed, asked)
	}
	if again := userconsent.AlwaysOwed(builtin.AdminConsoleClientIdentifier, "openid "+asked); len(again) != 0 {
		t.Fatalf("userconsent.AlwaysOwed owes %q to the admin console's client", again)
	}
	return asked
}

// The Scopes page says which clients may get the Account API's scope and on what condition: the
// user's approval on the consent screen, once, the admin console's own client excepted. It no longer
// says any client that signs a user in can ask for it.
func TestManageAccountDocs_TheScopesPageSaysWhoGetsIt(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), accountScopeSection.page, accountScopeSection.heading,
		[]string{"`" + manageAccountScope(t) + "`", "consent screen", "admin console's own client",
			"**" + i18n.T(context.Background(), "adminconsole.admin_clients.settings.field.consent_required") + "**"},
		[]string{"any client that signs a user in can ask for it"})
}

// The Account API setup says the user is shown the consent screen once, and what a refresh and a
// prompt=none request are answered while the user has not consented, which is what an application
// that called the Account API before this rule meets first.
func TestManageAccountDocs_TheAccountAPISetupSaysTheUserConsentsOnce(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), accountAPISetupSection.page, accountAPISetupSection.heading,
		[]string{"consent screen", "once", "`invalid_grant`", "`" + oidc.ErrorConsentRequired + "`", "prompt=none"},
		[]string{"needs no permission of its own to ask for it."})
}

// The authentication page names the three ways an application changes a user's account: the Account
// API with the user's token, the Admin API with the client's own token through client credentials,
// holding authserver:manage-users, and the admin console's Account pages.
func TestManageAccountDocs_TheAuthenticationPageNamesTheThreeWays(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), accountChangeWaysSection.page, accountChangeWaysSection.heading,
		[]string{
			"`" + manageAccountScope(t) + "`",
			"`" + builtin.AuthServerResourceIdentifier + ":" + builtin.ManageUsersPermissionIdentifier + "`",
			"client credentials",
			"/account/profile",
		}, nil)
}

// The Clients page's administrative-scopes section no longer says the consent screen follows
// Consent required alone, and sends the reader to the consent section, where the manage-account
// condition is.
func TestManageAccountDocs_TheAdministrativeScopesSectionLeavesConsentToItsSection(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), allowanceClientsSection.page, allowanceClientsSection.heading,
		[]string{"(#consent-required)", "`" + manageAccountScope(t) + "`"},
		[]string{"the consent screen still follows **Consent required**"})
}
