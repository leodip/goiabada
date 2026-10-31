package renderintegration

import (
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const signOutListTab = `<a class="tab-item" href="/admin/clients/7/sign-out-redirect-uris"`

// Every tab of a client links to its Sign-out redirect URIs tab, right after Redirect URIs and before
// Web origins, and marks it current on its own page only (#147 decision 6).
func TestRender_AdminClientTabs_SignOutRedirectURIsFollowsRedirectURIs(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true}}
	for tab, handler := range clientTabs(t, pages) {
		t.Run(tab, func(t *testing.T) {
			out := serveClientTab(t, handler, tab, "en")

			redirectURIs := strings.Index(out, `<a class="tab-item" href="/admin/clients/7/redirect-uris"`)
			signOut := strings.Index(out, signOutListTab)
			webOrigins := strings.Index(out, `<a class="tab-item" href="/admin/clients/7/web-origins"`)
			require.NotEqual(t, -1, signOut, "the %s tab links to the Sign-out redirect URIs tab", tab)
			assert.Less(t, redirectURIs, signOut, "Sign-out redirect URIs follows Redirect URIs")
			assert.Less(t, signOut, webOrigins, "Sign-out redirect URIs comes before Web origins")

			current := strings.Contains(out, signOutListTab+` aria-current="page">Sign-out redirect URIs</a>`)
			plain := strings.Contains(out, signOutListTab+`>Sign-out redirect URIs</a>`)
			assert.Equal(t, tab == "sign-out-redirect-uris", current, "the tab is current on its own page only")
			assert.Equal(t, tab != "sign-out-redirect-uris", plain, "the tab is named Sign-out redirect URIs")
		})
	}
}

// A client that signs users in through a redirect gets the list, drawn as stored and sorted, with
// the line saying how a sign-out uses it, the save naming its route and its two lists, and the list
// script the Redirect URIs and Web origins tabs share. Only its sign-out list is drawn, not its
// redirect URIs.
func TestRender_AdminClientSignOutRedirectURIs_AClientThatRedirects(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{
		Id:                       7,
		ClientIdentifier:         "a-web-app",
		AuthorizationCodeEnabled: true,
		RedirectURIs:             []api.RedirectURIResponse{{Id: 1, URI: "https://app.example.com/callback"}},
		PostLogoutRedirectURIs: []api.PostLogoutRedirectURIResponse{
			{Id: 3, URI: "https://app.example.com/signed-out"},
			{Id: 2, URI: "https://app.example.com/bye?state=fixed&x=1"},
		},
	}}

	out := serveClientTab(t, clientTabs(t, pages)["sign-out-redirect-uris"], "sign-out-redirect-uris", "en")

	assert.Contains(t, out, `<title>Sign-out redirect URIs – a-web-app – Test</title>`)
	assert.Contains(t, out, `id="uriListForm"`)
	assert.Contains(t, out, `data-save-url="/admin/clients/7/sign-out-redirect-uris" data-client-id="7" data-list-key="signOutRedirectURIs" data-expected-key="expectedSignOutRedirectURIs"`)
	assert.Contains(t, out, `src="/static/pages/client-uri-list.js`)
	assertListScriptSendsTheLoadedList(t, "pages/client-uri-list.js", "loadedEntries", "entries()")
	assert.Contains(t, out, `<label class="field-label" for="signOutRedirectURI">Sign-out redirect URI</label>`)
	assert.Contains(t, out, `After signing out, the user is sent back only to an address listed here, matched exactly, port included. Redirect URIs aren&#39;t used for sign-out.`)

	bye := strings.Index(out, `<tr data-value="https://app.example.com/bye?state=fixed&amp;x=1">`)
	signedOut := strings.Index(out, `<tr data-value="https://app.example.com/signed-out">`)
	require.NotEqual(t, -1, bye, "the URI with a query is a row")
	require.NotEqual(t, -1, signedOut, "the plain URI is a row")
	assert.Less(t, bye, signedOut, "the rows are sorted")
	assert.NotContains(t, out, `https://app.example.com/callback`, "a redirect URI is not drawn on this tab")
	assert.Contains(t, out, `data-list-empty hidden`, "a list with rows hides the empty state")

	assert.NotContains(t, out, `data-confirm-always=`, "an ordinary client's save asks nothing")
	assert.NotContains(t, out, `Sign-out redirect URIs are for the authorization code flow`)
}

// An empty list says so, with the table hidden.
func TestRender_AdminClientSignOutRedirectURIs_AnEmptyList(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true}}

	out := serveClientTab(t, clientTabs(t, pages)["sign-out-redirect-uris"], "sign-out-redirect-uris", "en")

	assert.NotContains(t, out, `<tr data-value=`)
	assert.Contains(t, out, `<p class="panel empty-state" data-list-empty>No sign-out redirect URIs yet.</p>`)
}

// A client with neither the authorization code flow nor the implicit flow has no sign-out to return
// from: the tab shows the notice instead of the list, and loads no script.
func TestRender_AdminClientSignOutRedirectURIs_AClientWithoutARedirectFlow(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-service", ClientCredentialsEnabled: true}}

	out := serveClientTab(t, clientTabs(t, pages)["sign-out-redirect-uris"], "sign-out-redirect-uris", "en")

	assert.Contains(t, out, `Sign-out redirect URIs are for the authorization code flow and the implicit flow. Turn one of them on, on the OAuth2 flows tab, to set them here.`)
	assert.NotContains(t, out, `id="uriListForm"`)
	assert.NotContains(t, out, `id="btnSave"`)
	assert.NotContains(t, out, `client-uri-list.js`)
}

// Saving the admin console's own client asks first, with the warning every save of it carries.
func TestRender_AdminClientSignOutRedirectURIs_TheSystemClientAsksBeforeSaving(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client", AuthorizationCodeEnabled: true, IsSystemLevelClient: true}}

	out := serveClientTab(t, clientTabs(t, pages)["sign-out-redirect-uris"], "sign-out-redirect-uris", "en")

	assert.Contains(t, out, `data-confirm-dialog="confirmSave"`)
	assert.Contains(t, out, `data-confirm-always="This is the admin console&#39;s own client: a wrong change can stop administrators from signing in to the admin console."`)
}

// The tab's strings are in every built-in catalog: a missing key leaks its own name into the page,
// and an untranslated one shows the English sentence.
func TestRender_AdminClientSignOutRedirectURIs_InEveryLocale(t *testing.T) {
	leakedKey := regexp.MustCompile(`adminconsole\.[a-z_.]+`)
	for _, locale := range []string{"en", "de", "es", "fr", "it", "pt-BR"} {
		for _, client := range []*api.ClientResponse{
			{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true,
				PostLogoutRedirectURIs: []api.PostLogoutRedirectURIResponse{{Id: 1, URI: "https://app.example.com/signed-out"}}},
			{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true},
			{Id: 7, ClientIdentifier: "a-service", ClientCredentialsEnabled: true},
		} {
			pages := &clientPagesAPI{client: client}
			out := serveClientTab(t, clientTabs(t, pages)["sign-out-redirect-uris"], "sign-out-redirect-uris", locale)
			visible := regexp.MustCompile(`(?s)<script.*?</script>`).ReplaceAllString(out, "")
			assert.Empty(t, leakedKey.FindString(visible), "%s: a catalog key leaked into the page", locale)
			if locale != "en" {
				assert.NotContains(t, out, "Sign-out redirect URI", "%s: the tab is translated", locale)
			}
		}
	}
}
