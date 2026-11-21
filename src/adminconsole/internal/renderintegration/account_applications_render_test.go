package renderintegration

import (
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/render"
)

// applicationRows splits the Applications page's table body into its rows, in order.
func applicationRows(t *testing.T, out string) []string {
	t.Helper()
	body := regexp.MustCompile(`(?s)<tbody>(.*?)</tbody>`).FindStringSubmatch(out)
	require.NotNil(t, body, "the page draws no table body")
	rows := regexp.MustCompile(`(?s)<tr>.*?</tr>`).FindAllString(body[1], -1)
	return rows
}

// scopeHints is the scopes a fragment of a row lists, in order, each the code-hint under its words.
func scopeHints(fragment string) []string {
	var scopes []string
	for _, m := range regexp.MustCompile(`<span class="code-hint">([^<]*)</span>`).FindAllStringSubmatch(fragment, -1) {
		scopes = append(scopes, m[1])
	}
	return scopes
}

// Each row shows the scopes it was given consent for and the scopes its live grants hold, each
// under its own label: whichever exists, and both when both do. The two can differ, so neither
// stands in for the other: a scope only the grants hold appears under the grants' label alone
// (#135 decision 7). The consent cell says when consent was given, or that none was asked.
func TestRender_ApplicationsPageLabelsEachScopeListItHas(t *testing.T) {
	out := renderMenuPage(t, "/account_applications.html", map[string]interface{}{
		"clients": []render.ConnectedClientInfo{
			{ClientID: 1, Client: "consent-only", ClientName: "Consent only", HasConsent: true, ConsentScope: "openid email"},
			{ClientID: 2, Client: "grants-only", ClientName: "Grants only", GrantScope: "openid profile"},
			{ClientID: 3, Client: "both", ClientName: "Both", HasConsent: true, ConsentScope: "openid",
				GrantScope: "openid offline_access"},
		},
	})
	rows := applicationRows(t, out)
	require.Len(t, rows, 3)

	const consentLabel, grantLabel = "Você permitiu", "Tem agora"
	const notAsked = "Não solicitado"

	consentOnly := rows[0]
	assert.Contains(t, consentOnly, consentLabel)
	assert.NotContains(t, consentOnly, grantLabel, "a client with no live grant shows no grants list")
	assert.Equal(t, []string{"openid", "email"}, scopeHints(consentOnly))
	assert.NotContains(t, consentOnly, notAsked)

	grantsOnly := rows[1]
	assert.Contains(t, grantsOnly, grantLabel)
	assert.NotContains(t, grantsOnly, consentLabel, "a client with no consent shows no consent list")
	assert.Equal(t, []string{"openid", "profile"}, scopeHints(grantsOnly))
	assert.Contains(t, grantsOnly, `data-label="Consentimento">`+notAsked+`</td>`, "a client with no consent was never asked")

	both := rows[2]
	consentAt, grantAt := strings.Index(both, consentLabel), strings.Index(both, grantLabel)
	require.True(t, consentAt >= 0 && grantAt > consentAt, "both lists are shown, the consent's first")
	assert.Equal(t, []string{"openid"}, scopeHints(both[consentAt:grantAt]), "the consent lists only what was consented to")
	assert.Equal(t, []string{"openid", "offline_access"}, scopeHints(both[grantAt:]), "the grants list what they hold")
	assert.NotContains(t, both, notAsked)
}

// Each scope list is named by its label for assistive technology too, so a screen reader moving
// through a row's lists hears which is which.
func TestRender_ApplicationsPageNamesEachScopeListByItsLabel(t *testing.T) {
	out := renderMenuPage(t, "/account_applications.html", map[string]interface{}{
		"clients": []render.ConnectedClientInfo{
			{ClientID: 3, Client: "both", ClientName: "Both", HasConsent: true, ConsentScope: "openid", GrantScope: "openid"},
		},
	})

	for _, label := range []string{"Você permitiu", "Tem agora"} {
		m := regexp.MustCompile(`<span class="block text-sm text-ink-muted" id="([^"]+)">` + label + `</span>`).FindStringSubmatch(out)
		require.NotNilf(t, m, "the label %q carries no id", label)
		assert.Containsf(t, out, `<ul class="grid gap-2" aria-labelledby="`+m[1]+`">`, "no list is named by %q", label)
	}
}

// The client the caller's own token was issued to, the admin console itself, is tagged in place of
// its Disconnect button: disconnecting it from inside it would only bounce the user through sign-in
// (#135 decision 5). Every other row keeps its button.
func TestRender_ApplicationsPageTagsTheCurrentApplicationInPlaceOfDisconnect(t *testing.T) {
	out := renderMenuPage(t, "/account_applications.html", map[string]interface{}{
		"clients": []render.ConnectedClientInfo{
			{ClientID: 1, Client: "admin-console-client", ClientName: "Admin console", GrantScope: "openid", IsCurrent: true},
			{ClientID: 2, Client: "portal", ClientName: "Customer portal", GrantScope: "openid"},
		},
	})
	rows := applicationRows(t, out)
	require.Len(t, rows, 2)

	assert.Contains(t, rows[0], `<span class="tag tag-note">Este aplicativo</span>`)
	assert.NotContains(t, rows[0], "<button", "the current application offers no Disconnect")
	assert.Contains(t, rows[1], `data-action-body="{&#34;clientId&#34;:2}"`)
	assert.NotContains(t, rows[1], "Este aplicativo")
}

// The confirmation says what a disconnect does: the access the application was given is revoked on
// every device and the approval removed, some of it can last until it expires (decision 8), the auth
// server tries to tell it to sign the user out, and it can ask to sign them in again (#135
// decision 7). An application that named itself says so in the same sentence, as its row does.
func TestRender_ApplicationsPageConfirmationSaysWhatADisconnectDoes(t *testing.T) {
	out := renderMenuPageIn(t, "/account_applications.html", map[string]interface{}{
		"clients": []render.ConnectedClientInfo{
			{ClientID: 1, Client: "portal", ClientName: "Customer portal", GrantScope: "openid"},
			{ClientID: 2, Client: "dcr_a3f9", ClientName: "Payroll Portal", ClientNameUnverified: true, GrantScope: "openid"},
		},
	}, "en", true)

	confirms := regexp.MustCompile(`data-confirm="([^"]*)"`).FindAllStringSubmatch(out, -1)
	require.Len(t, confirms, 2)
	assert.Equal(t, "Disconnect Customer portal? The access it was given will be revoked on every device "+
		"and any approval you gave it removed, though some of that access can last until it expires. "+
		"We'll try to tell it to sign you out. It can still ask you to sign in again.", html.UnescapeString(confirms[0][1]))
	assert.Equal(t, "Disconnect Payroll Portal, an application that registered itself and has not been verified? "+
		"The access it was given will be revoked on every device and any approval you gave it removed, "+
		"though some of that access can last until it expires. We'll try to tell it to sign you out. "+
		"It can still ask you to sign in again.", html.UnescapeString(confirms[1][1]))

	assert.Contains(t, out, `data-done="Application disconnected." data-done-label="Disconnected"`)
	assert.Regexp(t, `id="disconnectClient_btnModal2" class="button button-danger">Disconnect</button>`, out,
		"the dialog's action names what it does")
	assert.Contains(t, out, `data-confirm-title="Disconnect this application?"`)
}

// With nothing connected the page says so in place of the table.
func TestRender_ApplicationsPageWithNoClientsSaysSo(t *testing.T) {
	out := renderMenuPageIn(t, "/account_applications.html", map[string]interface{}{
		"clients": []render.ConnectedClientInfo{},
	}, "en", true)

	assert.Contains(t, out, `<p class="empty-state">No application is connected to your account.</p>`)
	assert.NotContains(t, out, "<table")
}

// The page is the account menu's Applications entry, at /account/applications, which replaced
// Consents (#135 decision 7), and it carries the styling contract's name for it.
func TestRender_ApplicationsPageIsTheAccountMenusApplicationsEntry(t *testing.T) {
	out := renderPageAt(t, "/account/applications", "/layouts/menu_layout.html", "/account_applications.html",
		map[string]interface{}{"clients": []render.ConnectedClientInfo{}}, nil, "en", true)

	assert.Regexp(t, `<a class="nav-link" href="/account/applications" aria-current="page"><svg[^>]*aria-hidden="true">(?s:.*?)</svg>Applications</a>`, out)
	assert.Equal(t, 1, strings.Count(out, `aria-current="page"`), "only the Applications entry is current")
	assert.NotContains(t, out, "manage-consents", "the Consents entry is gone")
	assert.Contains(t, out, `data-page="account-applications"`)
	assert.Contains(t, out, "<title>Applications – Test</title>")
}
