package renderintegration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/admingrouphandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminresourcehandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pages below draw a refused save by the rule the client's Settings tab follows (#522): every
// input shows what was submitted, and everything that stands for the record as it is, the page
// title and every original value a confirmation or warning compares the inputs against, comes from
// the stored record. Drawn from the submission instead, a second attempt at the same change would
// ask nothing, and a title would name a record that does not exist (#562 decision 6).

// refusedSave is the auth server's answer to every save below: a 400 the administrator can act on.
func refusedSave(message string) error {
	return &apiclient.APIError{Code: "VALIDATION_ERROR", Message: message, StatusCode: http.StatusBadRequest}
}

// serveRefusal serves a POST through the real renderer, in pt-BR, and returns the page it answers
// with, which for a refused save is the form drawn again rather than a redirect.
func serveRefusal(t *testing.T, handler http.HandlerFunc, target string, form url.Values,
	options ...handlertest.Option) string {

	t.Helper()
	return servePage(t, handler, http.MethodPost, target, append(options, handlertest.WithForm(form))...)
}

// servePage serves a request through the real renderer, in pt-BR, and returns the page it answers
// with, failing on anything but a page.
func servePage(t *testing.T, handler http.HandlerFunc, method, target string, options ...handlertest.Option) string {
	t.Helper()
	options = append([]handlertest.Option{handlertest.WithAccessToken(),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"})}, options...)
	req := handlertest.Request(method, target, options...)
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "the page is drawn, not redirected: %s", rec.Body.String())
	return rec.Body.String()
}

// inputRe matches the opening tag of the input with the id named, whatever order its attributes come in.
func inputRe(id string) *regexp.Regexp {
	return regexp.MustCompile(`<input[^>]*id="` + id + `"[^>]*>`)
}

// ---- Client > Authentication ----

// authenticationTabAPI is the auth server as the Authentication tab reaches it: the client and its
// secret as stored, and a save it refuses.
type authenticationTabAPI struct {
	stored       *api.ClientResponse
	storedSecret string
	secretReads  int
}

func (s *authenticationTabAPI) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.stored, nil
}

func (s *authenticationTabAPI) GetClientSecret(_ context.Context, _ string, _ int64) (string, error) {
	s.secretReads++
	return s.storedSecret, nil
}

func (s *authenticationTabAPI) UpdateClientAuthentication(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error) {
	return nil, refusedSave("The client secret is invalid.")
}

func postClientAuthentication(t *testing.T, apiClient *authenticationTabAPI, form url.Values) string {
	t.Helper()
	return serveRefusal(t,
		adminclienthandlers.HandleAuthenticationPost(render.New(web.TemplateFS()), nil, apiClient, "https://console.example"),
		"/admin/clients/7/authentication", form, handlertest.WithRouteParam("clientId", "7"))
}

// The Authentication tab asks before a save that changes a stored secret or switches between public
// and confidential, comparing against the original state and the original secret. A refused save
// draws them from the stored client, so the same change attempted again is asked again, which on
// the system client protects the admin console's own secret; the radios and the secret input keep
// what was submitted.
func TestRender_AdminClientAuthentication_ARefusedSaveKeepsTheStoredClient(t *testing.T) {
	const storedSecret = "stored-secret-0123456789"
	const typedSecret = "typed-secret-9876543210"

	testCases := []struct {
		name            string
		storedPublic    bool
		form            url.Values
		wantIsPublic    string
		wantOriginal    string
		wantSecretReads int
		wantPublicRadio bool
		wantSecretTyped string
	}{
		{
			name:            "a new secret for a confidential client",
			form:            url.Values{"publicConfidential": {"confidential"}, "clientSecret": {typedSecret}},
			wantIsPublic:    "false",
			wantOriginal:    storedSecret,
			wantSecretReads: 1,
			wantSecretTyped: typedSecret,
		},
		{
			name:            "a confidential client switched to public",
			form:            url.Values{"publicConfidential": {"public"}},
			wantIsPublic:    "false",
			wantOriginal:    storedSecret,
			wantSecretReads: 1,
			wantPublicRadio: true,
		},
		{
			name:            "a public client switched to confidential",
			storedPublic:    true,
			form:            url.Values{"publicConfidential": {"confidential"}, "clientSecret": {typedSecret}},
			wantIsPublic:    "true",
			wantOriginal:    "",
			wantSecretReads: 0,
			wantSecretTyped: typedSecret,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &authenticationTabAPI{
				stored:       &api.ClientResponse{Id: 7, ClientIdentifier: "portal", IsPublic: tc.storedPublic},
				storedSecret: storedSecret,
			}

			out := postClientAuthentication(t, apiClient, tc.form)

			assert.Contains(t, out, "The client secret is invalid.")
			assert.Contains(t, out, `<span class="text-accent">portal</span>`, "the page title names the stored client")
			assert.Contains(t, out, `var isPublic = `+tc.wantIsPublic+`;`, "the original state is the stored one")
			assert.Contains(t, out, `var originalClientSecret = "`+tc.wantOriginal+`";`, "the original secret is the stored one")
			assert.Equal(t, tc.wantSecretReads, apiClient.secretReads, "a public client holds no secret to read")

			publicRadio := inputRe("publicClientRadio").FindString(out)
			confidentialRadio := inputRe("confidentialClientRadio").FindString(out)
			require.NotEmpty(t, publicRadio)
			require.NotEmpty(t, confidentialRadio)
			assert.Equal(t, tc.wantPublicRadio, regexp.MustCompile(`\bchecked\b`).MatchString(publicRadio),
				"the choice as submitted: %s", publicRadio)
			assert.Equal(t, !tc.wantPublicRadio, regexp.MustCompile(`\bchecked\b`).MatchString(confidentialRadio),
				"the choice as submitted: %s", confidentialRadio)

			secret := inputRe("clientSecret").FindString(out)
			require.NotEmpty(t, secret)
			assert.Contains(t, secret, `value="`+tc.wantSecretTyped+`"`, "the secret input keeps what was submitted")
		})
	}
}

// ---- Group > Settings ----

// groupSettingsTabAPI is the auth server as the group Settings tab reaches it.
type groupSettingsTabAPI struct {
	stored *api.GroupResponse
}

func (s *groupSettingsTabAPI) GetGroupById(_ context.Context, _ string, _ int64) (*api.GroupResponse, error) {
	return s.stored, nil
}

func (s *groupSettingsTabAPI) UpdateGroup(_ context.Context, _ string, _ int64,
	_ *api.UpdateGroupRequest) (*api.GroupResponse, error) {
	return nil, refusedSave("The group identifier is already in use.")
}

// A refused group save draws the title and the original identifier the rename question compares
// against from the stored group, so a second attempt at the same rename is asked again.
func TestRender_AdminGroupSettings_ARefusedSaveKeepsTheStoredGroup(t *testing.T) {
	apiClient := &groupSettingsTabAPI{stored: &api.GroupResponse{Id: 4, GroupIdentifier: "sales",
		Description: "Sales team", IncludeInIdToken: true, IncludeInAccessToken: true}}

	out := serveRefusal(t,
		admingrouphandlers.HandleSettingsPost(render.New(web.TemplateFS()), nil, apiClient, "https://console.example"),
		"/admin/groups/4/settings",
		url.Values{"groupIdentifier": {"marketing"}, "description": {"Marketing team"}, "includeInIdToken": {"on"}},
		handlertest.WithRouteParam("groupId", "4"))

	assert.Contains(t, out, "The group identifier is already in use.")
	assert.Contains(t, out, `<title>Test - Configurações do grupo - sales</title>`)
	assert.Contains(t, out, `<span class="text-accent">sales</span>`, "the page title names the stored group")
	assert.NotContains(t, out, `<span class="text-accent">marketing</span>`)
	assert.Contains(t, out, `var originalGroupIdentifier = "sales";`)

	identifier := inputRe("groupIdentifier").FindString(out)
	require.NotEmpty(t, identifier)
	assert.Contains(t, identifier, `value="marketing"`, "the input keeps what was typed")
	assert.Contains(t, out, `value="Marketing team"`)
}

// ---- Resource > Settings ----

// resourceSettingsTabAPI is the auth server as the resource Settings tab reaches it.
type resourceSettingsTabAPI struct {
	stored *api.ResourceResponse
}

func (s *resourceSettingsTabAPI) GetResourceById(_ context.Context, _ string, _ int64) (*api.ResourceResponse, error) {
	return s.stored, nil
}

func (s *resourceSettingsTabAPI) UpdateResource(_ context.Context, _ string, _ int64,
	_ *api.UpdateResourceRequest) (*api.ResourceResponse, error) {
	return nil, refusedSave("The resource identifier is already in use.")
}

// A refused resource save draws the title and the original identifier the rename question compares
// against from the stored resource, so a second attempt at the same rename is asked again.
func TestRender_AdminResourceSettings_ARefusedSaveKeepsTheStoredResource(t *testing.T) {
	apiClient := &resourceSettingsTabAPI{stored: &api.ResourceResponse{Id: 3, ResourceIdentifier: "billing-api",
		Description: "Billing"}}

	out := serveRefusal(t,
		adminresourcehandlers.HandleSettingsPost(render.New(web.TemplateFS()), nil, apiClient, "https://console.example"),
		"/admin/resources/3/settings",
		url.Values{"resourceIdentifier": {"invoices-api"}, "description": {"Invoices"}},
		handlertest.WithRouteParam("resourceId", "3"))

	assert.Contains(t, out, "The resource identifier is already in use.")
	assert.Contains(t, out, `<title>Test - Configurações do recurso - billing-api</title>`)
	assert.Contains(t, out, `<span class="text-accent">billing-api</span>`, "the page title names the stored resource")
	assert.NotContains(t, out, `<span class="text-accent">invoices-api</span>`)
	assert.Contains(t, out, `var originalResourceIdentifier = "billing-api";`)

	identifier := inputRe("resourceIdentifier").FindString(out)
	require.NotEmpty(t, identifier)
	assert.Contains(t, identifier, `value="invoices-api"`, "the input keeps what was typed")
	assert.Contains(t, out, `value="Invoices"`)
}

// ---- Settings > General ----

// generalSettingsAPI is the auth server as Settings > General reaches it.
type generalSettingsAPI struct {
	stored *api.SettingsGeneralResponse
}

func (s *generalSettingsAPI) GetSettingsGeneral(_ context.Context, _ string) (*api.SettingsGeneralResponse, error) {
	return s.stored, nil
}

func (s *generalSettingsAPI) UpdateSettingsGeneral(_ context.Context, _ string,
	_ *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	return nil, refusedSave("The app name is too long.")
}

// noInvalidation is the settings cache, which a refused save must not touch.
type noInvalidation struct{ t *testing.T }

func (n noInvalidation) Invalidate() {
	n.t.Error("the settings cache was invalidated after a refused save")
}

// A refused save of the general settings draws the original issuer the issuer-change warning
// compares against from the stored settings, so the warning shows again when the same issuer is
// saved again; the input keeps the issuer as typed.
func TestRender_AdminSettingsGeneral_ARefusedSaveKeepsTheStoredIssuer(t *testing.T) {
	apiClient := &generalSettingsAPI{stored: &api.SettingsGeneralResponse{AppName: "Goiabada",
		Issuer: "storedissuer", PasswordPolicy: "low"}}

	out := serveRefusal(t,
		adminsettingshandlers.HandleGeneralPost(render.New(web.TemplateFS()), nil, apiClient,
			noInvalidation{t}, "https://console.example"),
		"/admin/settings/general",
		url.Values{"appName": {"A name far too long"}, "issuer": {"typedissuer"}, "passwordPolicy": {"low"}})

	assert.Contains(t, out, "The app name is too long.")
	assert.Contains(t, out, `const originalIssuerValue = "storedissuer";`, "the original issuer is the stored one")

	issuer := inputRe("issuer").FindString(out)
	require.NotEmpty(t, issuer)
	assert.Contains(t, issuer, `value="typedissuer"`, "the input keeps what was typed")
	assert.Contains(t, out, `value="A name far too long"`)
}

// ---- Group and user attribute edit pages ----

// groupAttributeEditAPI is the auth server as the group attribute edit page reaches it.
type groupAttributeEditAPI struct {
	group  *api.GroupResponse
	stored *api.GroupAttributeResponse
}

func (s *groupAttributeEditAPI) GetGroupById(_ context.Context, _ string, _ int64) (*api.GroupResponse, error) {
	return s.group, nil
}

func (s *groupAttributeEditAPI) GetGroupAttributeById(_ context.Context, _ string, _ int64) (*api.GroupAttributeResponse, error) {
	stored := *s.stored
	return &stored, nil
}

func (s *groupAttributeEditAPI) UpdateGroupAttribute(_ context.Context, _ string, _ int64,
	_ *api.UpdateGroupAttributeRequest) (*api.GroupAttributeResponse, error) {
	return nil, refusedSave("The attribute key is invalid.")
}

// A refused group attribute save names the stored key in the title, never the refused one or an
// empty one; the inputs keep what was submitted.
func TestRender_AdminGroupAttributeEdit_ARefusedSaveNamesTheStoredKey(t *testing.T) {
	for _, typedKey := range []string{"cost centre", ""} {
		t.Run("typed "+typedKey, func(t *testing.T) {
			apiClient := &groupAttributeEditAPI{
				group:  &api.GroupResponse{Id: 4, GroupIdentifier: "sales"},
				stored: &api.GroupAttributeResponse{Id: 11, GroupId: 4, Key: "department", Value: "Sales"},
			}

			out := serveRefusal(t,
				admingrouphandlers.HandleAttributesEditPost(render.New(web.TemplateFS()), apiClient),
				"/admin/groups/4/attributes/edit/11",
				url.Values{"attributeKey": {typedKey}, "attributeValue": {"Retail"}},
				handlertest.WithRouteParam("groupId", "4"), handlertest.WithRouteParam("attributeId", "11"))

			assert.Contains(t, out, "The attribute key is invalid.")
			assert.Contains(t, out, `<title>Test - Editar atributo do grupo - department</title>`)
			assert.Contains(t, out, `<span class="text-accent">department</span>`, "the page title names the stored key")

			key := inputRe("attributeKey").FindString(out)
			require.NotEmpty(t, key)
			assert.Contains(t, key, `value="`+typedKey+`"`, "the input keeps what was typed")
			assert.Contains(t, out, `value="Retail"`)
		})
	}
}

// userAttributeEditAPI is the auth server as the user attribute edit page reaches it.
type userAttributeEditAPI struct {
	user   *api.UserResponse
	stored *api.UserAttributeResponse
}

func (s *userAttributeEditAPI) GetUserById(_ context.Context, _ string, _ int64) (*api.UserResponse, error) {
	return s.user, nil
}

func (s *userAttributeEditAPI) GetUserAttributeById(_ context.Context, _ string, _ int64) (*api.UserAttributeResponse, error) {
	stored := *s.stored
	return &stored, nil
}

func (s *userAttributeEditAPI) UpdateUserAttribute(_ context.Context, _ string, _ int64,
	_ *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	return nil, refusedSave("The attribute key is invalid.")
}

// A refused user attribute save names the stored key in the title, never the refused one or an
// empty one, whether the console refuses it (an empty key) or the auth server does; the inputs
// keep what was submitted.
func TestRender_AdminUserAttributeEdit_ARefusedSaveNamesTheStoredKey(t *testing.T) {
	testCases := []struct {
		typedKey    string
		wantRefusal string
	}{
		{typedKey: "cost centre", wantRefusal: "The attribute key is invalid."},
		{typedKey: "", wantRefusal: "Attribute key is required"},
	}

	for _, tc := range testCases {
		t.Run("typed "+tc.typedKey, func(t *testing.T) {
			apiClient := &userAttributeEditAPI{
				user:   &api.UserResponse{Id: 9, Email: "ana@example.com"},
				stored: &api.UserAttributeResponse{Id: 12, UserId: 9, Key: "employee-id", Value: "E-100"},
			}

			out := serveRefusal(t,
				adminuserhandlers.HandleAttributesEditPost(render.New(web.TemplateFS()), apiClient, "https://console.example"),
				"/admin/users/9/attributes/edit/12",
				url.Values{"attributeKey": {tc.typedKey}, "attributeValue": {"E-200"}},
				handlertest.WithRouteParam("userId", "9"), handlertest.WithRouteParam("attributeId", "12"))

			assert.Contains(t, out, tc.wantRefusal)
			assert.Contains(t, out, `<title>Test - Editar atributo do usuário - employee-id</title>`)
			assert.Contains(t, out, `<span class="text-accent">employee-id</span>`, "the page title names the stored key")

			key := inputRe("attributeKey").FindString(out)
			require.NotEmpty(t, key)
			assert.Contains(t, key, `value="`+tc.typedKey+`"`, "the input keeps what was typed")
			assert.Contains(t, out, `value="E-200"`)
		})
	}
}

// The first draw of each page binds the stored record both ways: the inputs and the title and
// original values agree, so a save of the page as loaded asks nothing.
func TestRender_TheFirstDrawNamesTheStoredRecord(t *testing.T) {
	renderer := render.New(web.TemplateFS())
	testCases := []struct {
		name    string
		handler http.HandlerFunc
		target  string
		options []handlertest.Option
		want    []string
	}{
		{
			name: "client authentication",
			handler: adminclienthandlers.HandleAuthenticationGet(renderer, newRenderSessionStore(t),
				&authenticationTabAPI{stored: &api.ClientResponse{Id: 7, ClientIdentifier: "portal"}, storedSecret: "s3cret"}),
			target:  "/admin/clients/7/authentication",
			options: []handlertest.Option{handlertest.WithRouteParam("clientId", "7")},
			want: []string{`<span class="text-accent">portal</span>`, `var isPublic = false;`,
				`var originalClientSecret = "s3cret";`, `value="s3cret"`},
		},
		{
			name: "group settings",
			handler: admingrouphandlers.HandleSettingsGet(renderer, newRenderSessionStore(t),
				&groupSettingsTabAPI{stored: &api.GroupResponse{Id: 4, GroupIdentifier: "sales"}}),
			target:  "/admin/groups/4/settings",
			options: []handlertest.Option{handlertest.WithRouteParam("groupId", "4")},
			want: []string{`<span class="text-accent">sales</span>`, `var originalGroupIdentifier = "sales";`,
				`name="groupIdentifier" value="sales"`},
		},
		{
			name: "resource settings",
			handler: adminresourcehandlers.HandleSettingsGet(renderer, newRenderSessionStore(t),
				&resourceSettingsTabAPI{stored: &api.ResourceResponse{Id: 3, ResourceIdentifier: "billing-api"}}),
			target:  "/admin/resources/3/settings",
			options: []handlertest.Option{handlertest.WithRouteParam("resourceId", "3")},
			want: []string{`<span class="text-accent">billing-api</span>`,
				`var originalResourceIdentifier = "billing-api";`, `name="resourceIdentifier" value="billing-api"`},
		},
		{
			name: "general settings",
			handler: adminsettingshandlers.HandleGeneralGet(renderer, newRenderSessionStore(t),
				&generalSettingsAPI{stored: &api.SettingsGeneralResponse{AppName: "Goiabada", Issuer: "storedissuer",
					PasswordPolicy: "low"}}),
			target: "/admin/settings/general",
			want:   []string{`const originalIssuerValue = "storedissuer";`, `name="issuer" value="storedissuer"`},
		},
		{
			name: "group attribute edit",
			handler: admingrouphandlers.HandleAttributesEditGet(renderer, &groupAttributeEditAPI{
				group:  &api.GroupResponse{Id: 4, GroupIdentifier: "sales"},
				stored: &api.GroupAttributeResponse{Id: 11, GroupId: 4, Key: "department"}}),
			target: "/admin/groups/4/attributes/edit/11",
			options: []handlertest.Option{handlertest.WithRouteParam("groupId", "4"),
				handlertest.WithRouteParam("attributeId", "11")},
			want: []string{`<span class="text-accent">department</span>`, `name="attributeKey" value="department"`},
		},
		{
			name: "user attribute edit",
			handler: adminuserhandlers.HandleAttributesEditGet(renderer, &userAttributeEditAPI{
				user:   &api.UserResponse{Id: 9, Email: "ana@example.com"},
				stored: &api.UserAttributeResponse{Id: 12, UserId: 9, Key: "employee-id"}}),
			target: "/admin/users/9/attributes/edit/12",
			options: []handlertest.Option{handlertest.WithRouteParam("userId", "9"),
				handlertest.WithRouteParam("attributeId", "12")},
			want: []string{`<span class="text-accent">employee-id</span>`, `name="attributeKey" value="employee-id"`},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := servePage(t, tc.handler, http.MethodGet, tc.target, tc.options...)
			for _, want := range tc.want {
				assert.Contains(t, out, want)
			}
		})
	}
}
