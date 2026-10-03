package renderintegration

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRender_AdminClients is the template hop of the self-registered badge. The pipeline from the
// database to this page is the client row, then apimapping.ToClientResponse, then that value straight into
// the template, since HandleAdminClientsGet binds "clients" and does no adminconsole-side mapping.
// So rendering the real page over two real api.ClientResponse values is what proves the badge is
// driven by CreatedViaDCR: an ordinary client next to a self-registered one is the case that fails
// if the conditional is dropped and every client gets marked (#108).
func TestRender_AdminClients(t *testing.T) {
	bind := map[string]interface{}{
		"clients": []api.ClientResponse{
			{Id: 1, ClientIdentifier: "dcr_a3f9e1b2", Enabled: true, CreatedViaDCR: true},
			{Id: 2, ClientIdentifier: "web-app", Enabled: true, CreatedViaDCR: false},
		},
	}
	out := renderMenuPage(t, "/admin_clients.html", bind)

	// Both clients render, so the count is what carries the claim: one badge, not two and not zero.
	assert.Equal(t, 1, strings.Count(out, "Autorregistrado"),
		"the self-registered badge must appear for the DCR client and only for it")
	assert.Contains(t, out, "dcr_a3f9e1b2")
	assert.Contains(t, out, "web-app")
}

// TestRender_AdminClientRedirectURIs is the template hop of the redirect-flow gate. The handler
// resolves the per-client implicit override against the global setting and binds one boolean, so
// what is left to prove here is that the page shows the form for a client that can redirect and
// the explaining sentence for one that cannot (#250). renderMenuPage's own raw-key check is what proves
// the new catalog key exists in pt-BR: a missing key leaks its own name into the HTML.
func TestRender_AdminClientRedirectURIs(t *testing.T) {

	page := func(canManage bool) string {
		return renderMenuPage(t, "/admin_clients_redirect_uris.html", map[string]interface{}{
			"client": struct {
				ClientId              int64
				ClientIdentifier      string
				CanManageRedirectURIs bool
				RedirectURIs          map[int64]string
				IsSystemLevelClient   bool
			}{
				ClientId:              7,
				ClientIdentifier:      "an-implicit-app",
				CanManageRedirectURIs: canManage,
				RedirectURIs:          map[int64]string{1: "https://example.com/cb"},
			},
			"savedSuccessfully": false,
		})
	}

	manageable := page(true)
	assert.Contains(t, manageable, "redirectURIsEnabledPanel")
	assert.Contains(t, manageable, `id="btnSave"`)
	assert.NotContains(t, manageable, "URIs de redirecionamento são usadas pelo fluxo")

	blocked := page(false)
	assert.NotContains(t, blocked, "redirectURIsEnabledPanel")
	assert.NotContains(t, blocked, `id="btnSave"`)
	// The sentence names both redirect-based flows, which is the whole point of the change:
	// an implicit-only administrator used to be told to enable a flow their client never uses.
	assert.Contains(t, blocked, "URIs de redirecionamento são usadas pelo fluxo authorization code com PKCE e pelo fluxo implicit.")
}

// The redirect URIs page keeps the list as it loaded it and sends that copy with every save, so the
// auth server can refuse a save from a page another administrator's save has outdated rather than
// undo their change (#428). The copy has to be taken after the loaded values are pushed and never
// edited, or the page would send its edited list as the loaded one and every save would pass.
func TestRender_AdminClientRedirectURIs_SendsTheLoadedList(t *testing.T) {

	out := renderMenuPage(t, "/admin_clients_redirect_uris.html", map[string]interface{}{
		"client": struct {
			ClientId              int64
			ClientIdentifier      string
			CanManageRedirectURIs bool
			RedirectURIs          map[int64]string
			IsSystemLevelClient   bool
		}{
			ClientId:              7,
			ClientIdentifier:      "an-app",
			CanManageRedirectURIs: true,
			RedirectURIs:          map[int64]string{1: "https://example.com/a", 2: "https://example.com/b"},
		},
		"savedSuccessfully": false,
	})

	const copyTaken = "const loadedRedirectURIs = redirectURIs.slice();"
	lastPush := strings.LastIndex(out, `redirectURIs.push("https:\/\/example.com\/b");`)
	require.NotEqual(t, -1, lastPush, "the loaded values are pushed into the editable list")
	copyAt := strings.Index(out, copyTaken)
	require.NotEqual(t, -1, copyAt, "the page keeps a copy of the loaded list")
	assert.Greater(t, copyAt, lastPush, "the copy is taken after every loaded value is in the list")

	assert.Contains(t, out, `"expectedRedirectURIs": loadedRedirectURIs,`)
	assert.NotRegexp(t, `loadedRedirectURIs\.(push|splice|pop|shift|unshift)\(`, out)
	assert.NotRegexp(t, `loadedRedirectURIs\s*=[^=]`, strings.Replace(out, copyTaken, "", 1))
}

// The Web Origins page has no gate left and shows two lists: this client's editable rows, and the
// effective server-wide list every client's origins land in. This case proves the template can
// display what it is handed; that the handler assembles the server-wide list at all is proved in
// handler_admin_client_web_origins_test.go, because a bind written by the test cannot see a fetch
// that was deleted (#250).
func TestRender_AdminClientWebOrigins(t *testing.T) {

	type effectiveWebOrigin struct {
		Origin           string
		ClientIdentifier string
	}

	out := renderMenuPage(t, "/admin_clients_web_origins.html", map[string]interface{}{
		"client": struct {
			ClientId            int64
			ClientIdentifier    string
			WebOrigins          map[int64]string
			EffectiveWebOrigins []effectiveWebOrigin
			IsSystemLevelClient bool
		}{
			ClientId:         7,
			ClientIdentifier: "a-javascript-app",
			WebOrigins:       map[int64]string{1: "https://mine.example.com"},
			EffectiveWebOrigins: []effectiveWebOrigin{
				{Origin: "https://mine.example.com", ClientIdentifier: "a-javascript-app"},
				{Origin: "https://theirs.example.com", ClientIdentifier: "another-app"},
			},
		},
		"savedSuccessfully": false,
	})

	// The form renders unconditionally now. This client has the authorization code flow off,
	// which the bind no longer even carries, and it still gets the form and the save button:
	// needing a web origin is about the app being JavaScript in a browser, not about any flow.
	assert.Contains(t, out, "webOriginsEnabledPanel")
	assert.Contains(t, out, `id="btnSave"`)

	// Another client's origin is visible here, and the sentence above the list says why an
	// origin registered anywhere is honoured everywhere. Without both, the page still implies
	// a per-client scoping the server does not honour.
	assert.Contains(t, out, "https://theirs.example.com")
	assert.Contains(t, out, "another-app")
	assert.Contains(t, out, "Origens permitidas em todo o servidor")
	assert.Contains(t, out, "é permitida para todos os clientes")

	// The intro says the value is a bare origin rather than a URL, which is where the trailing
	// slash that CORS can never match used to come from.
	assert.Contains(t, out, "sem nada depois do host")
}

// The web origins page keeps the list as it loaded it and sends that copy with every save, as the
// redirect URIs page does, so the auth server can refuse a save from an outdated page rather than
// undo another administrator's change (#428). The copy is taken after the loaded values are pushed
// and never edited, or the page would send its edited list as the loaded one and every save would
// pass.
func TestRender_AdminClientWebOrigins_SendsTheLoadedList(t *testing.T) {

	out := renderMenuPage(t, "/admin_clients_web_origins.html", map[string]interface{}{
		"client": struct {
			ClientId            int64
			ClientIdentifier    string
			WebOrigins          map[int64]string
			EffectiveWebOrigins []struct{ Origin, ClientIdentifier string }
			IsSystemLevelClient bool
		}{
			ClientId:         7,
			ClientIdentifier: "a-javascript-app",
			WebOrigins:       map[int64]string{1: "https://a.example.com", 2: "https://b.example.com"},
		},
		"savedSuccessfully": false,
	})

	const copyTaken = "const loadedWebOrigins = webOrigins.slice();"
	lastPush := strings.LastIndex(out, `webOrigins.push("https:\/\/b.example.com");`)
	require.NotEqual(t, -1, lastPush, "the loaded values are pushed into the editable list")
	copyAt := strings.Index(out, copyTaken)
	require.NotEqual(t, -1, copyAt, "the page keeps a copy of the loaded list")
	assert.Greater(t, copyAt, lastPush, "the copy is taken after every loaded value is in the list")

	assert.Contains(t, out, `"expectedWebOrigins": loadedWebOrigins,`)
	assert.NotRegexp(t, `loadedWebOrigins\.(push|splice|pop|shift|unshift)\(`, out)
	assert.NotRegexp(t, `loadedWebOrigins\s*=[^=]`, strings.Replace(out, copyTaken, "", 1))
}

// The client permissions page does the same (#428).
func TestRender_AdminClientsPermissions_SendsTheLoadedList(t *testing.T) {
	out := renderMenuPage(t, "/admin_clients_permissions.html", map[string]interface{}{
		"client": struct {
			ClientId                 int64
			ClientIdentifier         string
			ClientCredentialsEnabled bool
			Permissions              map[int64]string
			IsSystemLevelClient      bool
		}{
			ClientId:                 7,
			ClientIdentifier:         "a-service",
			ClientCredentialsEnabled: true,
			Permissions:              map[int64]string{3: "some-resource:read", 4: "some-resource:write"},
		},
		"resources":         []api.ResourceResponse{},
		"savedSuccessfully": false,
	})
	assertSendsTheLoadedPermissionIds(t, out)
}
