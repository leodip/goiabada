package renderintegration

import (
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const backchannelLogoutTab = `<a class="tab-item" href="/admin/clients/7/backchannel-logout"`

// uriInputRe and sessionRequiredRe match the tab's two controls, whatever order their attributes
// come in.
var (
	uriInputRe        = regexp.MustCompile(`<input [^>]*id="backchannelLogoutUri"[^>]*>`)
	sessionRequiredRe = regexp.MustCompile(`<input [^>]*id="backchannelLogoutSessionRequired"[^>]*>`)
)

// Every tab of a client links to its Back-channel logout tab, right after Sign-out redirect URIs and
// before Web origins, and marks it current on its own page only (#784 decision 9).
func TestRender_AdminClientTabs_BackchannelLogoutFollowsSignOutRedirectURIs(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true}}
	tabs := clientTabs(t, pages)
	require.Contains(t, tabs, "backchannel-logout", "the tab has a handler of its own")
	for tab, handler := range tabs {
		t.Run(tab, func(t *testing.T) {
			out := serveClientTab(t, handler, tab, "en")

			signOut := strings.Index(out, signOutListTab)
			backchannel := strings.Index(out, backchannelLogoutTab)
			webOrigins := strings.Index(out, `<a class="tab-item" href="/admin/clients/7/web-origins"`)
			require.NotEqual(t, -1, backchannel, "the %s tab links to the Back-channel logout tab", tab)
			assert.Less(t, signOut, backchannel, "Back-channel logout follows Sign-out redirect URIs")
			assert.Less(t, backchannel, webOrigins, "Back-channel logout comes before Web origins")

			current := strings.Contains(out, backchannelLogoutTab+` aria-current="page">Back-channel logout</a>`)
			plain := strings.Contains(out, backchannelLogoutTab+`>Back-channel logout</a>`)
			assert.Equal(t, tab == "backchannel-logout", current, "the tab is current on its own page only")
			assert.Equal(t, tab != "backchannel-logout", plain, "the tab is named Back-channel logout")
		})
	}
}

// A client that signs users in gets a form with the URI and the checkbox, drawn as stored, the line
// saying what the URI is for, and one Save; the form posts to the tab itself.
func TestRender_AdminClientBackchannelLogout_AClientThatSignsUsersIn(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true,
		BackchannelLogoutURI: "https://app.example.com/backchannel-logout?tenant=a&x=1", BackchannelLogoutSessionRequired: true}}

	out := serveClientTab(t, clientTabs(t, pages)["backchannel-logout"], "backchannel-logout", "en")

	assert.Contains(t, out, `<title>Back-channel logout – a-web-app – Test</title>`)
	assert.Contains(t, out, `<form id="formClientBackchannelLogout" class="panel" method="post" novalidate`)
	assert.Contains(t, out, `When a session this client was on ends, the auth server POSTs a signed token to this address on your app&#39;s server, so your app can sign the user out too. Leave it empty and nothing is sent.`)
	assert.Contains(t, out, `<label class="field-label" for="backchannelLogoutUri">Back-channel logout URI</label>`)

	uri := uriInputRe.FindString(out)
	require.NotEmpty(t, uri, "the URI is an input")
	assert.Contains(t, uri, `name="backchannelLogoutUri"`)
	assert.Contains(t, uri, `type="url"`)
	assert.Contains(t, uri, `value="https://app.example.com/backchannel-logout?tenant=a&amp;x=1"`, "the URI as stored, query included")
	assert.NotContains(t, uri, `aria-invalid`, "nothing is refused on a first draw")

	checkbox := sessionRequiredRe.FindString(out)
	require.NotEmpty(t, checkbox, "the session identifier is a checkbox")
	assert.Contains(t, checkbox, `type="checkbox"`)
	assert.Contains(t, checkbox, `name="backchannelLogoutSessionRequired"`)
	assert.True(t, hasAttr(checkbox, "checked"), "ticked as stored: %s", checkbox)
	assert.Contains(t, out, `Require the session identifier`)

	assert.Equal(t, 1, strings.Count(out, `id="btnSave"`))
	assert.NotContains(t, out, `data-confirm-always=`, "an ordinary client's save asks nothing")
	assert.NotContains(t, out, `A back-channel logout URI is for the authorization code flow`)
}

// A client with neither the authorization code flow nor the implicit flow signs nobody in: the tab
// shows the note its neighbour shows instead of the form.
func TestRender_AdminClientBackchannelLogout_AClientWithoutASignInFlow(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-service", ClientCredentialsEnabled: true}}

	out := serveClientTab(t, clientTabs(t, pages)["backchannel-logout"], "backchannel-logout", "en")

	assert.Contains(t, out, `A back-channel logout URI is for the authorization code flow and the implicit flow. Turn one of them on, on the OAuth2 flows tab, to set it here.`)
	assert.Contains(t, out, `notice notice-note`)
	assert.NotContains(t, out, `id="formClientBackchannelLogout"`)
	assert.NotContains(t, out, `id="btnSave"`)
}

// Saving the admin console's own client asks first, with the warning every save of it carries.
func TestRender_AdminClientBackchannelLogout_TheSystemClientAsksBeforeSaving(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client", AuthorizationCodeEnabled: true, IsSystemLevelClient: true}}

	out := serveClientTab(t, clientTabs(t, pages)["backchannel-logout"], "backchannel-logout", "en")

	assert.Contains(t, out, `data-confirm-dialog="confirmSave"`)
	assert.Contains(t, out, `data-confirm-always="This is the admin console&#39;s own client: a wrong change can stop administrators from signing in to the admin console."`)
}

// renderBackchannelLogout draws the tab from bind, in English, as an administrator holding
// authserver:manage unless bind says otherwise.
func renderBackchannelLogout(t *testing.T, bind map[string]interface{}) string {
	t.Helper()
	full := map[string]interface{}{"isAdmin": true}
	for k, v := range bind {
		full[k] = v
	}
	return renderMenuPageIn(t, "/admin_clients_backchannel_logout.html", full, "en", true)
}

// A refusal is drawn at the top of the form and marks the field it is about: invalid, described by
// the notice, focused. The URI keeps what was typed (#784 decision 9).
func TestRender_AdminClientBackchannelLogout_ARefusalMarksItsField(t *testing.T) {
	client := adminclienthandlers.ClientBackchannelLogout{ClientId: 7, ClientIdentifier: "a-web-app",
		CanManageBackchannelLogout: true, BackchannelLogoutURI: "ftp://typed.example.com/bcl"}

	out := renderBackchannelLogout(t, map[string]interface{}{"client": client,
		"error": "Back-channel logout URI must use https or http: ftp://typed.example.com/bcl", "errorField": "backchannelLogoutUri"})

	assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="backchannel-logout-error">`)
	assert.Contains(t, out, `Back-channel logout URI must use https or http: ftp://typed.example.com/bcl`)
	uri := uriInputRe.FindString(out)
	require.NotEmpty(t, uri)
	assert.Contains(t, uri, `aria-invalid="true"`)
	assert.True(t, hasAttr(uri, "autofocus"), "the refused field takes the focus: %s", uri)
	assert.Regexp(t, `aria-describedby="backchannel-logout-error [^"]*"`, uri, "the notice describes the field")
	assert.Contains(t, uri, `value="ftp://typed.example.com/bcl"`)
	checkbox := sessionRequiredRe.FindString(out)
	assert.NotContains(t, checkbox, `aria-invalid`, "the refusal is not about the checkbox")
}

// An administrator without authserver:manage is told under the URI that only an administrator
// holding it sets or changes the URI, and that they can still clear it; one holding it is not
// (#784 decision 15).
func TestRender_AdminClientBackchannelLogout_SaysWhoSetsTheURI(t *testing.T) {
	const manageOnly = "Only an administrator holding authserver:manage can set or change it. You can clear it."
	client := adminclienthandlers.ClientBackchannelLogout{ClientId: 7, ClientIdentifier: "a-web-app", CanManageBackchannelLogout: true}

	withManage := renderBackchannelLogout(t, map[string]interface{}{"client": client})
	assert.NotContains(t, withManage, manageOnly)

	withoutManage := renderBackchannelLogout(t, map[string]interface{}{"client": client, "isAdmin": false})
	assert.Contains(t, withoutManage, manageOnly)
	uri := uriInputRe.FindString(withoutManage)
	assert.False(t, hasAttr(uri, "disabled"), "the URI stays editable, since clearing it is allowed: %s", uri)
	assert.False(t, hasAttr(uri, "readonly"), "the URI stays editable: %s", uri)
}

// A save drawn back from its redirect says it was saved.
func TestRender_AdminClientBackchannelLogout_Saved(t *testing.T) {
	client := adminclienthandlers.ClientBackchannelLogout{ClientId: 7, ClientIdentifier: "a-web-app", CanManageBackchannelLogout: true}

	out := renderBackchannelLogout(t, map[string]interface{}{"client": client, "savedSuccessfully": true})

	assert.Contains(t, out, `<div class="notice notice-positive" role="status">`)
	assert.Contains(t, out, `Back-channel logout settings saved.`)
}

// The tab's strings are in every built-in catalog: a missing key leaks its own name into the page,
// and an untranslated one shows the English sentence.
func TestRender_AdminClientBackchannelLogout_InEveryLocale(t *testing.T) {
	leakedKey := regexp.MustCompile(`adminconsole\.[a-z_.]+`)
	for _, locale := range []string{"en", "de", "es", "fr", "it", "pt-BR"} {
		for _, client := range []*api.ClientResponse{
			{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true, BackchannelLogoutURI: "https://app.example.com/bcl"},
			{Id: 7, ClientIdentifier: "a-service", ClientCredentialsEnabled: true},
		} {
			out := serveClientTab(t, clientTabs(t, &clientPagesAPI{client: client})["backchannel-logout"], "backchannel-logout", locale)
			visible := regexp.MustCompile(`(?s)<script.*?</script>`).ReplaceAllString(out, "")
			assert.Empty(t, leakedKey.FindString(visible), "%s: a catalog key leaked into the page", locale)
			if locale != "en" {
				for _, english := range []string{"Back-channel logout URI", "Require the session identifier", "auth server POSTs",
					"for the authorization code flow and the implicit flow"} {
					assert.NotContains(t, visible, english, "%s: the tab is translated", locale)
				}
			}
		}
		for _, bind := range []map[string]interface{}{
			{"savedSuccessfully": true},
			{"isAdmin": false},
		} {
			bind["client"] = adminclienthandlers.ClientBackchannelLogout{ClientId: 7, ClientIdentifier: "a-web-app", CanManageBackchannelLogout: true}
			if _, ok := bind["isAdmin"]; !ok {
				bind["isAdmin"] = true
			}
			out := renderMenuPageIn(t, "/admin_clients_backchannel_logout.html", bind, locale, true)
			if locale != "en" {
				assert.NotContains(t, out, "settings saved", "%s: the saved notice is translated", locale)
				assert.NotContains(t, out, "can set or change it", "%s: the manage line is translated", locale)
			}
		}
	}
}
