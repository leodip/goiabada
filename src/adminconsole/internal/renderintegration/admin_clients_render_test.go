package renderintegration

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRender_AdminClients is the template hop of the self-registered badge. The pipeline from the
// database to this page is the client row, then apimapping.ToClientResponse, then that value straight into
// the template, since adminclienthandlers.HandleListGet binds "clients" and does no adminconsole-side mapping.
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
				RedirectURIs          []string
				IsSystemLevelClient   bool
			}{
				ClientId:              7,
				ClientIdentifier:      "an-implicit-app",
				CanManageRedirectURIs: canManage,
				RedirectURIs:          []string{"https://example.com/cb"},
			},
			"savedSuccessfully": false,
		})
	}

	manageable := page(true)
	assert.Contains(t, manageable, `id="uriListForm"`)
	assert.Contains(t, manageable, `id="btnSave"`)
	assert.NotContains(t, manageable, "URIs de redirecionamento servem ao fluxo")

	blocked := page(false)
	assert.NotContains(t, blocked, `id="uriListForm"`)
	assert.NotContains(t, blocked, `id="btnSave"`)
	// The sentence names both redirect-based flows, which is the whole point of the change:
	// an implicit-only administrator used to be told to enable a flow their client never uses.
	assert.Contains(t, blocked, "URIs de redirecionamento servem ao fluxo authorization code e ao fluxo implícito.")
}

// The redirect URIs page keeps the list as it loaded it and sends that copy with every save, so the
// auth server can refuse a save from a page another administrator's save has outdated rather than
// undo their change (#428). The page draws the stored list as rows, and its script reads them once
// as it loads and never edits that copy.
func TestRender_AdminClientRedirectURIs_SendsTheLoadedList(t *testing.T) {

	out := renderMenuPage(t, "/admin_clients_redirect_uris.html", map[string]interface{}{
		"client": struct {
			ClientId              int64
			ClientIdentifier      string
			CanManageRedirectURIs bool
			RedirectURIs          []string
			IsSystemLevelClient   bool
		}{
			ClientId:              7,
			ClientIdentifier:      "an-app",
			CanManageRedirectURIs: true,
			RedirectURIs:          []string{"https://example.com/a", "https://example.com/b?x=1&y=2"},
		},
		"savedSuccessfully": false,
	})

	assert.Contains(t, out, `<tr data-value="https://example.com/a">`)
	assert.Contains(t, out, `<tr data-value="https://example.com/b?x=1&amp;y=2">`,
		"a value is drawn escaped for its attribute, which the browser reads back as the value")
	assert.Contains(t, out, `data-list-key="redirectURIs" data-expected-key="expectedRedirectURIs"`)
	assert.Contains(t, out, `src="/static/pages/client-uri-list.js`)
	assertListScriptSendsTheLoadedList(t, "pages/client-uri-list.js", "loadedEntries", "entries()")
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
			WebOrigins          []string
			EffectiveWebOrigins []effectiveWebOrigin
			IsSystemLevelClient bool
		}{
			ClientId:         7,
			ClientIdentifier: "a-javascript-app",
			WebOrigins:       []string{"https://mine.example.com"},
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
	assert.Contains(t, out, `id="uriListForm"`)
	assert.Contains(t, out, `id="btnSave"`)

	// Another client's origin is visible here, and the sentence above the list says why an
	// origin registered anywhere is honoured everywhere. Without both, the page still implies
	// a per-client scoping the server does not honour.
	assert.Contains(t, out, "https://theirs.example.com")
	assert.Contains(t, out, "another-app")
	assert.Contains(t, out, "Origens permitidas em todo o servidor")
	assert.Contains(t, out, "é permitida para todos os clientes") //nolint:misspell // the pt-BR catalog's text: "clientes" is Portuguese, not a misspelling of "clients"

	// The lead says the value is a bare origin rather than a URL, which is where the trailing
	// slash that CORS can never match used to come from, and the form keeps only an entry's
	// origin.
	assert.Contains(t, out, "uma porta opcional, sem nada depois")
	assert.Contains(t, out, `data-expected-key="expectedWebOrigins" data-origins`)
}

// The web origins page keeps the list as it loaded it and sends that copy with every save, as the
// redirect URIs page does, through the same script (#428).
func TestRender_AdminClientWebOrigins_SendsTheLoadedList(t *testing.T) {

	out := renderMenuPage(t, "/admin_clients_web_origins.html", map[string]interface{}{
		"client": struct {
			ClientId            int64
			ClientIdentifier    string
			WebOrigins          []string
			EffectiveWebOrigins []struct{ Origin, ClientIdentifier string }
			IsSystemLevelClient bool
		}{
			ClientId:         7,
			ClientIdentifier: "a-javascript-app",
			WebOrigins:       []string{"https://a.example.com", "https://b.example.com"},
		},
		"savedSuccessfully": false,
	})

	assert.Contains(t, out, `<tr data-value="https://a.example.com">`)
	assert.Contains(t, out, `<tr data-value="https://b.example.com">`)
	assert.Contains(t, out, `data-list-key="webOrigins" data-expected-key="expectedWebOrigins"`)
	assert.Contains(t, out, `src="/static/pages/client-uri-list.js`)
	assertListScriptSendsTheLoadedList(t, "pages/client-uri-list.js", "loadedEntries", "entries()")
}

// The client permissions page does the same, through its own script (#428).
func TestRender_AdminClientsPermissions_SendsTheLoadedList(t *testing.T) {
	out := renderMenuPage(t, "/admin_clients_permissions.html", map[string]interface{}{
		"client": struct {
			ClientId                 int64
			ClientIdentifier         string
			ClientCredentialsEnabled bool
			Permissions              []struct {
				Id    int64
				Scope string
			}
			IsSystemLevelClient bool
		}{
			ClientId:                 7,
			ClientIdentifier:         "a-service",
			ClientCredentialsEnabled: true,
			Permissions: []struct {
				Id    int64
				Scope string
			}{{Id: 3, Scope: "some-resource:read"}, {Id: 4, Scope: "some-resource:write"}},
		},
		"resources":         []api.ResourceResponse{},
		"savedSuccessfully": false,
	})

	assert.Contains(t, out, `<tr data-id="3">`)
	assert.Contains(t, out, `<tr data-id="4">`)
	assert.Contains(t, out, `data-list-key="assignedPermissionsIds" data-expected-key="expectedPermissionIds"`)
	assert.Contains(t, out, `src="/static/pages/permission-list.js`)
	assertListScriptSendsTheLoadedList(t, "pages/permission-list.js", "loadedIds", "grantedIds()")
}

// The Remove buttons of the lists edited in the page, a client's redirect URIs, web origins and
// permissions, a user's permissions and groups, and a group's permissions, are named for what they do and to which row: the
// visible "Remove" and the row's value beside it for a screen reader, in the administrator's
// language, as the page draws the stored rows, and as the scripts build the row of an entry added
// in the page, from the form's data-remove-label.
func TestRender_ListRemoveButtonsAreNamedForTheirRow(t *testing.T) {
	type permission struct {
		Id    int64
		Scope string
	}
	cases := []struct {
		page   string
		bind   map[string]interface{}
		row    string
		script string
	}{
		{"/admin_clients_redirect_uris.html", map[string]interface{}{"client": struct {
			ClientId              int64
			ClientIdentifier      string
			CanManageRedirectURIs bool
			RedirectURIs          []string
			IsSystemLevelClient   bool
		}{ClientId: 7, ClientIdentifier: "an-app", CanManageRedirectURIs: true, RedirectURIs: []string{"https://example.com/cb"}}},
			"https://example.com/cb", "pages/client-uri-list.js"},
		{"/admin_clients_web_origins.html", map[string]interface{}{"client": struct {
			ClientId            int64
			ClientIdentifier    string
			WebOrigins          []string
			EffectiveWebOrigins []struct{ Origin, ClientIdentifier string }
			IsSystemLevelClient bool
		}{ClientId: 7, ClientIdentifier: "a-javascript-app", WebOrigins: []string{"https://a.example.com"}}},
			"https://a.example.com", "pages/client-uri-list.js"},
		{"/admin_clients_permissions.html", map[string]interface{}{"client": struct {
			ClientId                 int64
			ClientIdentifier         string
			ClientCredentialsEnabled bool
			Permissions              []permission
			IsSystemLevelClient      bool
		}{ClientId: 7, ClientIdentifier: "a-service", ClientCredentialsEnabled: true, Permissions: []permission{{3, "some-resource:read"}}},
			"resources": []api.ResourceResponse{}},
			"some-resource:read", "pages/permission-list.js"},
		{"/admin_users_permissions.html", map[string]interface{}{
			"user":      &api.UserResponse{Id: 5, Email: "someone@example.com"},
			"granted":   []permission{{3, "some-resource:read"}},
			"resources": []render.Choice{}},
			"some-resource:read", "pages/permission-list.js"},
		{"/admin_users_groups.html", map[string]interface{}{
			"user": &api.UserResponse{Id: 5, Email: "someone@example.com"},
			"memberships": []struct {
				Id              int64
				GroupIdentifier string
			}{{3, "admins"}},
			"groupChoices": []render.Choice{}},
			"admins", "pages/user-groups.js"},
		{"/admin_groups_permissions.html", map[string]interface{}{
			"group": struct {
				GroupId         int64
				GroupIdentifier string
			}{GroupId: 5, GroupIdentifier: "admins"},
			"granted":   []permission{{3, "some-resource:read"}},
			"resources": []render.Choice{}},
			"some-resource:read", "pages/permission-list.js"},
	}
	for _, tc := range cases {
		t.Run(tc.page, func(t *testing.T) {
			for lang, remove := range map[string]string{"en": "Remove", "pt-BR": "Remover"} {
				out := renderMenuPageIn(t, tc.page, tc.bind, lang, true)
				assert.Contains(t, out, `type="button" data-list-remove>`+remove+`<span class="sr-only"> `+tc.row+`</span></button>`)
				assert.Contains(t, out, `data-remove-label="`+remove+`"`)
			}
			script, err := fs.ReadFile(web.StaticFS(), tc.script)
			require.NoError(t, err)
			assert.Contains(t, string(script), `remove.type = "button";`, "a script-built Remove is a plain button")
			assert.Contains(t, string(script), `.dataset.removeLabel;`)
			assert.Contains(t, string(script), `name.className = "sr-only";`)
		})
	}
}
