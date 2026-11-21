package renderintegration

import (
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
)

// connectedClientsBind is the user's Connected clients tab bind for user 7 with the clients named.
func connectedClientsBind(clients []render.ConnectedClientInfo) map[string]interface{} {
	return map[string]interface{}{
		"user":    &api.UserResponse{ID: 7, Email: "someone@example.com"},
		"clients": clients,
		"page":    "1",
		"query":   "",
	}
}

// Each row shows the scopes the user gave the client consent for and the scopes its live grants
// hold, each under its own label: whichever exists, and both when both do. The two can differ, so
// neither stands in for the other: a scope only the grants hold appears under the grants' label
// alone (#135 decision 7). The consent cell says when consent was given, or that none was asked.
func TestRender_UserConnectedClientsTabLabelsEachScopeListItHas(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_users_connected_clients.html", connectedClientsBind([]render.ConnectedClientInfo{
		{ClientID: 1, Client: "consent-only", HasConsent: true, ConsentScope: "openid email"},
		{ClientID: 2, Client: "grants-only", GrantScope: "openid profile"},
		{ClientID: 3, Client: "both", HasConsent: true, ConsentScope: "openid", GrantScope: "openid offline_access"},
	}), "en", true)
	rows := applicationRows(t, out)
	require.Len(t, rows, 3)

	const consentLabel, grantLabel = "Consented to", "Holds now"
	const notAsked = "Not asked"

	consentOnly := rows[0]
	assert.Contains(t, consentOnly, consentLabel)
	assert.NotContains(t, consentOnly, grantLabel, "a client with no live grant shows no grants list")
	assert.Equal(t, []string{"openid", "email"}, scopeItems(consentOnly))
	assert.NotContains(t, consentOnly, notAsked)

	grantsOnly := rows[1]
	assert.Contains(t, grantsOnly, grantLabel)
	assert.NotContains(t, grantsOnly, consentLabel, "a client with no consent shows no consent list")
	assert.Equal(t, []string{"openid", "profile"}, scopeItems(grantsOnly))
	assert.Contains(t, grantsOnly, `data-label="Consent">`+notAsked+`</td>`, "a client with no consent was never asked")

	both := rows[2]
	consentAt, grantAt := strings.Index(both, consentLabel), strings.Index(both, grantLabel)
	require.True(t, consentAt >= 0 && grantAt > consentAt, "both lists are shown, the consent's first")
	assert.Equal(t, []string{"openid"}, scopeItems(both[consentAt:grantAt]), "the consent lists only what was consented to")
	assert.Equal(t, []string{"openid", "offline_access"}, scopeItems(both[grantAt:]), "the grants list what they hold")
	assert.NotContains(t, both, notAsked)
}

// Each row names the client by the name the user is shown for it, with its identifier beside it to
// tell clients apart (#135 decision 7). A client whose name is its identifier shows the identifier
// once, and a client that named itself, whose name is then its stored description, shows that
// description once under the identifier.
func TestRender_UserConnectedClientsTabNamesEachClient(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_users_connected_clients.html", connectedClientsBind([]render.ConnectedClientInfo{
		{ClientID: 1, Client: "review-calendar", ClientName: "Review calendar", ClientDescription: "Team calendar", GrantScope: "openid"},
		{ClientID: 2, Client: "portal", ClientName: "portal", GrantScope: "openid"},
		{ClientID: 3, Client: "dcr_a3f9", ClientName: "Payroll Portal", ClientNameUnverified: true,
			ClientDescription: "Payroll Portal", GrantScope: "openid"},
	}), "en", true)
	rows := applicationRows(t, out)
	require.Len(t, rows, 3)

	named := rows[0]
	assert.Contains(t, named, `<span class="font-semibold">Review calendar</span>`)
	assert.Contains(t, named, `<span class="cell-secondary font-mono text-sm">review-calendar</span>`,
		"the identifier stays visible beside the name")
	assert.Contains(t, named, `<span class="cell-secondary">Team calendar</span>`)

	unnamed := rows[1]
	assert.Contains(t, unnamed, `<span class="font-mono text-sm">portal</span>`)
	assert.NotContains(t, unnamed, "font-semibold", "a name that is the identifier is not shown twice")
	assert.Equal(t, 1, strings.Count(unnamed, ">portal<"))

	selfNamed := rows[2]
	assert.Contains(t, selfNamed, `<span class="font-mono text-sm">dcr_a3f9</span>`)
	assert.NotContains(t, selfNamed, "font-semibold")
	assert.Equal(t, 1, strings.Count(selfNamed, ">Payroll Portal<"), "the self-given name is the description, shown once")
}

// scopeItems is the scopes a fragment of a row of the tab lists, in order, one list item each.
func scopeItems(fragment string) []string {
	var scopes []string
	for _, m := range regexp.MustCompile(`<li>([^<]*)</li>`).FindAllStringSubmatch(fragment, -1) {
		scopes = append(scopes, m[1])
	}
	return scopes
}

// Each scope list is named by its label for assistive technology too, so a screen reader moving
// through a row's lists hears which is which.
func TestRender_UserConnectedClientsTabNamesEachScopeListByItsLabel(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_users_connected_clients.html", connectedClientsBind([]render.ConnectedClientInfo{
		{ClientID: 3, Client: "both", HasConsent: true, ConsentScope: "openid", GrantScope: "openid"},
	}), "en", true)

	for _, label := range []string{"Consented to", "Holds now"} {
		m := regexp.MustCompile(`<span class="block text-sm text-ink-muted" id="([^"]+)">` + label + `</span>`).FindStringSubmatch(out)
		require.NotNilf(t, m, "the label %q carries no id", label)
		assert.Containsf(t, out, `aria-labelledby="`+m[1]+`"`, "no list is named by %q", label)
	}
}

// The client the administrator's own token was issued to, the admin console itself, is tagged in
// place of its Disconnect button on their own user: disconnecting it from inside it would only
// bounce them through sign-in (#135 decision 5). Every other row keeps its button, which names the
// page's user in its route and the row's client in its body.
func TestRender_UserConnectedClientsTabTagsTheCurrentClientInPlaceOfDisconnect(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_users_connected_clients.html", connectedClientsBind([]render.ConnectedClientInfo{
		{ClientID: 1, Client: "admin-console-client", GrantScope: "openid", IsCurrent: true},
		{ClientID: 2, Client: "portal", GrantScope: "openid"},
	}), "en", true)
	rows := applicationRows(t, out)
	require.Len(t, rows, 2)

	assert.Contains(t, rows[0], `<span class="tag tag-note">This client</span>`)
	assert.NotContains(t, rows[0], "<button", "the current client offers no Disconnect")
	assert.Contains(t, rows[1], `data-action-url="/admin/users/7/connected-clients" data-action-body="{&#34;clientId&#34;:2}"`)
	assert.NotContains(t, rows[1], "This client")
}

// The confirmation says what a disconnect does: the consent is deleted and the client's access
// revoked on every device, some access tokens can last until they expire (decision 8), the auth
// server tries to tell it to sign the user out, and it can ask the user to sign in again (#135
// decision 7). The administrator's page names the client by its identifier.
func TestRender_UserConnectedClientsTabConfirmationSaysWhatADisconnectDoes(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_users_connected_clients.html", connectedClientsBind([]render.ConnectedClientInfo{
		{ClientID: 2, Client: "portal", ClientName: "Customer portal", GrantScope: "openid"},
	}), "en", true)

	confirms := regexp.MustCompile(`data-confirm="([^"]*)"`).FindAllStringSubmatch(out, -1)
	require.Len(t, confirms, 1)
	assert.Equal(t, "Disconnect portal? Any consent the user gave it will be deleted and the access it holds "+
		"for the user revoked on every device, offline refresh tokens included, though some access tokens "+
		"already issued can keep working until they expire. The auth server will try to tell it to sign "+
		"the user out. It can still ask the user to sign in again.", html.UnescapeString(confirms[0][1]))

	assert.Contains(t, out, `data-done="Client disconnected." data-done-label="Disconnected"`)
	assert.Contains(t, out, `>Disconnect<span class="sr-only"> portal</span></button>`,
		"the button names the client it disconnects")
	assert.Regexp(t, `id="disconnectClient_btnModal2" class="button button-danger">Disconnect</button>`, out,
		"the dialog's action names what it does")
	assert.Contains(t, out, `data-confirm-title="Disconnect this client?"`)
}

// With nothing connected the tab says so in place of the table.
func TestRender_UserConnectedClientsTabWithNoClientsSaysSo(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_users_connected_clients.html",
		connectedClientsBind([]render.ConnectedClientInfo{}), "en", true)

	assert.Contains(t, html.UnescapeString(out), `<p class="empty-state">This user isn't connected to any client.</p>`)
	assert.NotContains(t, out, "<table")
}

// The tab is the user's Connected clients tab, at /admin/users/{id}/connected-clients, which
// replaced Consents (#135 decision 7), and it is marked as the tab the administrator is on.
func TestRender_UserConnectedClientsTabReplacesConsents(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_users_connected_clients.html",
		connectedClientsBind([]render.ConnectedClientInfo{}), "en", true)

	assert.Contains(t, out,
		`<a class="tab-item" href="/admin/users/7/connected-clients?page=1&query=" aria-current="page">Connected clients</a>`)
	assert.Equal(t, 1, strings.Count(out, `class="tab-item" href="/admin/users/7/connected-clients`))
	assert.NotContains(t, out, "/consents", "the Consents tab is gone")
	assert.Contains(t, out, "<title>Connected clients – someone@example.com – Test</title>")
}
