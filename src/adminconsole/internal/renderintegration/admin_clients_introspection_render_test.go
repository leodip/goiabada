package renderintegration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientPagesAPI is the auth server as every tab of one client reaches it: the client, stored
// confidential or public, and harmless answers to each tab's other reads. listed is the client's
// introspection resources; resourcesRead counts the reads of every resource, which only a tab that
// offers resources to choose makes.
type clientPagesAPI struct {
	client        *api.ClientResponse
	listed        []api.ResourceResponse
	resourcesRead int
}

func (s *clientPagesAPI) GetClientById(context.Context, string, int64) (*api.ClientResponse, error) {
	return s.client, nil
}

func (s *clientPagesAPI) GetClientIntrospectionResources(context.Context, string, int64) (*api.ClientResponse, []api.ResourceResponse, error) {
	return s.client, s.listed, nil
}

func (s *clientPagesAPI) GetClientPermissions(context.Context, string, int64) (*api.ClientResponse, []api.PermissionResponse, error) {
	return s.client, nil, nil
}

// GetAllResources answers three resources, out of order: the auth server's own and two APIs.
func (s *clientPagesAPI) GetAllResources(context.Context, string) ([]api.ResourceResponse, error) {
	s.resourcesRead++
	return []api.ResourceResponse{
		{Id: 4, ResourceIdentifier: "orders-api", Description: "Orders"},
		{Id: 1, ResourceIdentifier: "authserver", Description: "Authorization server (system-level)", IsSystemLevelResource: true},
		{Id: 3, ResourceIdentifier: "billing-api", Description: "Billing"},
	}, nil
}

func (s *clientPagesAPI) GetClientSecret(context.Context, string, int64) (string, error) {
	return "a-secret", nil
}

func (s *clientPagesAPI) GetClientLogo(context.Context, string, int64) (*api.ClientLogoInfoResponse, error) {
	return &api.ClientLogoInfoResponse{}, nil
}

func (s *clientPagesAPI) GetSettingsGeneral(context.Context, string) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{}, nil
}

func (s *clientPagesAPI) GetSettingsTokens(context.Context, string) (*api.SettingsTokensResponse, error) {
	return &api.SettingsTokensResponse{}, nil
}

func (s *clientPagesAPI) GetAllClients(context.Context, string) ([]api.ClientResponse, error) {
	return []api.ClientResponse{*s.client}, nil
}

func (s *clientPagesAPI) GetClientSessionsByClientId(context.Context, string, int64, int, int) (*api.GetClientSessionsResponse, error) {
	return &api.GetClientSessionsResponse{}, nil
}

// The writes, which no first draw reaches.

func (*clientPagesAPI) UpdateClient(context.Context, string, int64, *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	panic("unexpected call to UpdateClient")
}

func (*clientPagesAPI) UpdateClientAdministrativeScopes(context.Context, string, int64, *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error) {
	panic("unexpected call to UpdateClientAdministrativeScopes")
}

func (*clientPagesAPI) UpdateClientTokens(context.Context, string, int64, *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	panic("unexpected call to UpdateClientTokens")
}

func (*clientPagesAPI) UpdateClientAuthentication(context.Context, string, int64, *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error) {
	panic("unexpected call to UpdateClientAuthentication")
}

func (*clientPagesAPI) UpdateClientOAuth2Flows(context.Context, string, int64, *api.UpdateClientOAuth2FlowsRequest) (*api.ClientResponse, error) {
	panic("unexpected call to UpdateClientOAuth2Flows")
}

func (*clientPagesAPI) UpdateClientRedirectURIs(context.Context, string, int64, *api.UpdateClientRedirectURIsRequest) (*api.ClientResponse, error) {
	panic("unexpected call to UpdateClientRedirectURIs")
}

func (*clientPagesAPI) UpdateClientWebOrigins(context.Context, string, int64, *api.UpdateClientWebOriginsRequest) (*api.ClientResponse, error) {
	panic("unexpected call to UpdateClientWebOrigins")
}

func (*clientPagesAPI) UpdateClientPermissions(context.Context, string, int64, *api.UpdateClientPermissionsRequest) error {
	panic("unexpected call to UpdateClientPermissions")
}

func (*clientPagesAPI) UpdateClientIntrospectionResources(context.Context, string, int64, *api.UpdateClientIntrospectionResourcesRequest) error {
	panic("unexpected call to UpdateClientIntrospectionResources")
}

func (*clientPagesAPI) UploadClientLogo(context.Context, string, int64, []byte, string) (*api.ClientLogoUploadResponse, error) {
	panic("unexpected call to UploadClientLogo")
}

func (*clientPagesAPI) DeleteClientLogo(context.Context, string, int64) error {
	panic("unexpected call to DeleteClientLogo")
}

func (*clientPagesAPI) DeleteUserSessionById(context.Context, string, int64) error {
	panic("unexpected call to DeleteUserSessionById")
}

// serveClientTab draws one tab of client 7 through its real handler and the real renderer, in the
// locale named, and returns the page.
func serveClientTab(t *testing.T, handler http.HandlerFunc, tab, locale string) string {
	t.Helper()
	req := handlertest.Request(http.MethodGet, "/admin/clients/7/"+tab,
		handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"}))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, locale))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "the %s tab is drawn: %s", tab, rec.Body.String())
	return rec.Body.String()
}

// clientTabs is every tab of a client, each drawn by its own handler over pages.
func clientTabs(t *testing.T, pages *clientPagesAPI) map[string]http.HandlerFunc {
	h := render.New(web.TemplateFS(), web.StaticFS())
	return map[string]http.HandlerFunc{
		"settings":       adminclienthandlers.HandleSettingsGet(h, newRenderSessionStore(t), pages),
		"logo":           adminclienthandlers.HandleLogoGet(h, pages),
		"tokens":         adminclienthandlers.HandleTokensGet(h, newRenderSessionStore(t), pages),
		"authentication": adminclienthandlers.HandleAuthenticationGet(h, newRenderSessionStore(t), pages),
		"oauth2-flows":   adminclienthandlers.HandleOAuth2FlowsGet(h, newRenderSessionStore(t), pages),
		"redirect-uris":  adminclienthandlers.HandleRedirectURIsGet(h, newRenderSessionStore(t), pages),
		"web-origins":    adminclienthandlers.HandleWebOriginsGet(h, newRenderSessionStore(t), pages),
		"user-sessions":  adminclienthandlers.HandleUserSessionsGet(h, pages),
		"permissions":    adminclienthandlers.HandlePermissionsGet(h, newRenderSessionStore(t), pages),
		"introspection":  adminclienthandlers.HandleIntrospectionGet(h, newRenderSessionStore(t), pages),
	}
}

const introspectionTab = `<a class="tab-item" href="/admin/clients/7/introspection"`

// Every tab of a confidential client links to its Introspection tab, beside Permissions, and no tab
// of a public client does: a public client cannot authenticate, so it never introspects (#676
// decision 14). Each tab is drawn by its own handler, so a handler that does not hand the template
// whether the client is public fails here.
func TestRender_AdminClientTabs_IntrospectionOnlyForAConfidentialClient(t *testing.T) {
	for _, isPublic := range []bool{false, true} {
		for tab, handler := range clientTabs(t, &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "orders-backend", IsPublic: isPublic}}) {
			kind := "confidential"
			if isPublic {
				kind = "public"
			}
			t.Run(kind+"/"+tab, func(t *testing.T) {
				out := serveClientTab(t, handler, tab, "en")

				permissions := `<a class="tab-item" href="/admin/clients/7/permissions"`
				require.Contains(t, out, permissions)
				if isPublic {
					assert.NotContains(t, out, introspectionTab, "a public client's %s tab links to no Introspection tab", tab)
					return
				}
				require.Contains(t, out, introspectionTab, "a confidential client's %s tab links to its Introspection tab", tab)
				assert.Less(t, strings.Index(out, permissions), strings.Index(out, introspectionTab),
					"the Introspection tab follows Permissions")
				current := strings.Contains(out, introspectionTab+` aria-current="page">Introspection</a>`)
				assert.Equal(t, tab == "introspection", current, "the Introspection tab is current on its own page only")
			})
		}
	}
}

// A confidential client's Introspection tab draws the resources it lists, by identifier and as
// stored, each a row the script reads the loaded list from; offers every resource to add; and names
// the save's route and the two lists it sends, the list wanted and the list as loaded (#428).
func TestRender_AdminClientIntrospection_AConfidentialClientsList(t *testing.T) {
	pages := &clientPagesAPI{
		client: &api.ClientResponse{Id: 7, ClientIdentifier: "orders-backend"},
		listed: []api.ResourceResponse{
			{Id: 4, ResourceIdentifier: "orders-api", Description: "Orders"},
			{Id: 3, ResourceIdentifier: "billing-api", Description: "Billing"},
		},
	}

	out := serveClientTab(t, clientTabs(t, pages)["introspection"], "introspection", "en")

	assert.Contains(t, out, `<title>Introspection – orders-backend – Test</title>`)
	assert.Contains(t, out, `<h1 class="page-title" id="page-title">orders-backend</h1>`)
	assert.Contains(t, out, `id="introspectionListForm"`)
	assert.Contains(t, out, `data-save-url="/admin/clients/7/introspection" data-list-key="resourceIds" data-expected-key="expectedResourceIds"`)
	assert.Contains(t, out, `src="/static/pages/introspection-resources.js`)
	assertListScriptSendsTheLoadedList(t, "pages/introspection-resources.js", "loadedResourceIds", "listedIds()")

	// The listed resources, sorted by identifier, each linking to its resource.
	billing := strings.Index(out, `<tr data-id="3">`)
	orders := strings.Index(out, `<tr data-id="4">`)
	require.NotEqual(t, -1, billing, "billing-api is a row")
	require.NotEqual(t, -1, orders, "orders-api is a row")
	assert.Less(t, billing, orders, "the rows are in identifier order")
	assert.Contains(t, out, `<a class="text-link" href="/admin/resources/3/settings">billing-api</a>`)
	assert.NotContains(t, out, `<tr data-id="1">`, "authserver is not listed")
	assert.Contains(t, out, `data-list-empty hidden`, "a list with rows hides the empty state")

	// Every resource is offered, the auth server's own among them.
	assert.Equal(t, 1, pages.resourcesRead)
	for _, id := range []string{"1", "3", "4"} {
		assert.Contains(t, out, `<option value="`+id+`" data-resource-identifier=`)
	}
	assert.Contains(t, out, `<option value="1" data-resource-identifier="authserver"`)

	assert.Contains(t, out, `The resources whose tokens this client may introspect.`)
	assert.NotContains(t, out, `data-confirm-always=`, "an ordinary client's save asks nothing")
	assert.NotContains(t, out, `A public client can&#39;t authenticate`)
}

// A confidential client listing nothing yet says so, with the table hidden.
func TestRender_AdminClientIntrospection_AnEmptyList(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "orders-backend"}, listed: []api.ResourceResponse{}}

	out := serveClientTab(t, clientTabs(t, pages)["introspection"], "introspection", "en")

	assert.Contains(t, out, `id="introspectionListForm"`)
	assert.NotContains(t, out, `<tr data-id=`)
	assert.Contains(t, out, `data-list-region>`)
	assert.Contains(t, out, `tabindex="0" hidden data-list-region>`, "the empty table is hidden")
	assert.Contains(t, out, `<p class="panel empty-state" data-list-empty>No introspection resources yet.</p>`)
}

// A public client's Introspection tab, reached by its address, says why it has no list and offers
// nothing to edit: no form, no Save, and no read of the resources it could not list.
func TestRender_AdminClientIntrospection_APublicClientHasNone(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-spa", IsPublic: true}, listed: []api.ResourceResponse{}}

	out := serveClientTab(t, clientTabs(t, pages)["introspection"], "introspection", "pt-BR")

	assert.NotContains(t, out, `id="introspectionListForm"`)
	assert.NotContains(t, out, `id="btnSave"`)
	assert.NotContains(t, out, `introspection-resources.js`)
	assert.Equal(t, 0, pages.resourcesRead, "a public client is offered no resources")
	assert.Contains(t, out, `Um cliente público não pode se autenticar e, portanto, não pode fazer a introspecção de tokens.`)
}

// Saving the admin console's own client asks first, with the warning every save of it carries.
func TestRender_AdminClientIntrospection_TheSystemClientAsksBeforeSaving(t *testing.T) {
	pages := &clientPagesAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client", IsSystemLevelClient: true}, listed: []api.ResourceResponse{}}

	out := serveClientTab(t, clientTabs(t, pages)["introspection"], "introspection", "en")

	assert.Contains(t, out, `data-confirm-dialog="confirmSave"`)
	assert.Contains(t, out, `data-confirm-always=`)
}
