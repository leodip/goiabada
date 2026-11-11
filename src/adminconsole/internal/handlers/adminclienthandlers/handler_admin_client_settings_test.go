package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/oauth"
)

// stubAdministrativeScopesApiClient implements the Settings tab's port: the client the tab is drawn
// from, the brands its Brand select offers, and the settings', the allowance's and the brand's
// writes, each recording what it was sent and in which order.
type stubAdministrativeScopesApiClient struct {
	client *api.ClientResponse
	// brands is what the brands' read answers.
	brands []api.BrandResponse
	// brandErr is what the brand's write answers; brandAnswer the client it answers otherwise.
	brandErr    error
	brandAnswer *api.ClientResponse
	sentBrand   *api.UpdateClientBrandRequest
	sentBrandTo int64
	sentBrandAs string
	brandWrites int
	// writes names each write in the order it was made.
	writes []string
	// updated is what the settings' write answers, the client as it then stands.
	updated *api.ClientResponse
	// settingsErr and updateErr are what the settings' write and the allowance's answer.
	settingsErr error
	updateErr   error

	// sentSettings is what the settings' write was last sent.
	sentSettings    *api.UpdateClientSettingsRequest
	sentAllowance   *api.UpdateClientAdministrativeScopesRequest
	sentAllowanceTo int64
	sentAllowanceAs string
	allowanceWrites int
	settingsWrites  int
}

func (s *stubAdministrativeScopesApiClient) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.client, nil
}

func (s *stubAdministrativeScopesApiClient) UpdateClient(_ context.Context, _ string, _ int64,
	request *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	s.settingsWrites++
	s.writes = append(s.writes, "settings")
	s.sentSettings = request
	if s.settingsErr != nil {
		return nil, s.settingsErr
	}
	if s.updated != nil {
		return s.updated, nil
	}
	return s.client, nil
}

func (s *stubAdministrativeScopesApiClient) UpdateClientAdministrativeScopes(_ context.Context, accessToken string,
	clientId int64, request *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error) {
	s.allowanceWrites++
	s.writes = append(s.writes, "allowance")
	s.sentAllowance = request
	s.sentAllowanceTo = clientId
	s.sentAllowanceAs = accessToken
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	return s.client, nil
}

func (s *stubAdministrativeScopesApiClient) GetAllBrands(_ context.Context, _ string) ([]api.BrandResponse, error) {
	return s.brands, nil
}

func (s *stubAdministrativeScopesApiClient) UpdateClientBrand(_ context.Context, accessToken string, clientId int64,
	request *api.UpdateClientBrandRequest) (*api.ClientResponse, error) {
	s.brandWrites++
	s.writes = append(s.writes, "brand")
	s.sentBrand = request
	s.sentBrandTo = clientId
	s.sentBrandAs = accessToken
	if s.brandErr != nil {
		return nil, s.brandErr
	}
	if s.brandAnswer != nil {
		return s.brandAnswer, nil
	}
	return s.client, nil
}

// invalidationRecorder stands in for the console's cache of the public settings, counting the
// times it was dropped.
type invalidationRecorder struct {
	invalidations int
}

func (c *invalidationRecorder) Invalidate() {
	c.invalidations++
}

// manageGrant is the scope an administrator holding authserver:manage was granted, the one scope the
// auth server lets switch the allowance.
const manageGrant = "openid authserver:manage"

// postSettings posts the Settings tab for client 7 with form, and with query on the URL when given,
// as an administrator granted scope.
func postSettings(t *testing.T, apiClient clientSettingsAPI, httpHelper *stubHttpHelper, form url.Values, query string, scope ...string) *httptest.ResponseRecorder {
	t.Helper()
	return postSettingsDropping(t, apiClient, httpHelper, &invalidationRecorder{}, form, query, scope...)
}

// postSettingsDropping posts the Settings tab as postSettings does, with cache standing for the
// console's cached public settings.
func postSettingsDropping(t *testing.T, apiClient clientSettingsAPI, httpHelper *stubHttpHelper, cache *invalidationRecorder,
	form url.Values, query string, scope ...string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/admin/clients/7/settings"
	if query != "" {
		target += "?" + query
	}
	grant := manageGrant
	if len(scope) > 0 {
		grant = scope[0]
	}
	req := handlertest.Request(http.MethodPost, target,
		handlertest.WithJwtInfo(oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken, Scope: grant}}),
		handlertest.WithPathValue("clientId", "7"), handlertest.WithForm(form))
	rec := httptest.NewRecorder()
	HandleSettingsPost(httpHelper, newTestSessionStore(), apiClient, cache, consoleBaseURL).ServeHTTP(rec, req)
	return rec
}

// The switch shows the allowance the auth server answers: on for an allowed client, off for one
// that is not, and on for the admin console's own client, which the page marks as system-level so
// the template can disable it (#499 decision 5).
func TestHandleSettingsGet_BindsTheAdministrativeScopesAllowance(t *testing.T) {
	testCases := []struct {
		name        string
		client      *api.ClientResponse
		wantAllowed bool
		wantSystem  bool
	}{
		{
			name:        "an allowed client",
			client:      &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool", AdministrativeScopesAllowed: true},
			wantAllowed: true,
		},
		{
			name:   "a client that is not allowed",
			client: &api.ClientResponse{Id: 7, ClientIdentifier: "portal"},
		},
		{
			name: "the admin console's client",
			client: &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client",
				AdministrativeScopesAllowed: true, IsSystemLevelClient: true},
			wantAllowed: true,
			wantSystem:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := &stubHttpHelper{}
			req := handlertest.Request(http.MethodGet, "/admin/clients/7/settings",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"))

			HandleSettingsGet(httpHelper, newTestSessionStore(), &stubAdministrativeScopesApiClient{client: tc.client}).
				ServeHTTP(httptest.NewRecorder(), req)

			require.NoError(t, httpHelper.err)
			require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
			bound := reflect.ValueOf(httpHelper.bind["client"])
			assert.Equal(t, tc.wantAllowed, bound.FieldByName("AdministrativeScopesAllowed").Bool())
			assert.Equal(t, tc.wantSystem, bound.FieldByName("IsSystemLevelClient").Bool())
		})
	}
}

// The tab is told whether the client registered itself, so the template can keep its identifier
// read-only: on for a self-registered client, off for one an administrator created.
func TestHandleSettingsGet_BindsWhetherTheClientRegisteredItself(t *testing.T) {
	for _, createdViaDCR := range []bool{true, false} {
		httpHelper := &stubHttpHelper{}
		req := handlertest.Request(http.MethodGet, "/admin/clients/7/settings",
			handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"))
		client := &api.ClientResponse{Id: 7, ClientIdentifier: "dcr_a3f9e1b2", CreatedViaDCR: createdViaDCR}

		HandleSettingsGet(httpHelper, newTestSessionStore(), &stubAdministrativeScopesApiClient{client: client}).
			ServeHTTP(httptest.NewRecorder(), req)

		require.NoError(t, httpHelper.err)
		require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
		assert.Equal(t, createdViaDCR, reflect.ValueOf(httpHelper.bind["client"]).FieldByName("CreatedViaDCR").Bool())
	}
}

// One Save stores the whole tab (#542): the settings, then the allowance through its own route, and
// the allowance only when the switch differs from the stored one, so an administrator without
// authserver:manage saves the other settings as before. Only the checkbox's own value switches it
// on; anything else fails closed, as a security switch should.
func TestHandleSettingsPost_WritesTheAllowanceOnlyWhenItChanged(t *testing.T) {
	testCases := []struct {
		name        string
		stored      bool
		form        url.Values
		wantWrite   bool
		wantAllowed bool
	}{
		{"switched on", false, url.Values{"administrativeScopesAllowed": {"on"}}, true, true},
		{"switched off, which a browser submits as nothing", true, url.Values{}, true, false},
		{"left off", false, url.Values{}, false, false},
		{"left on", true, url.Values{"administrativeScopesAllowed": {"on"}}, false, false},
		{"a value the checkbox never sends, over an allowed client", true, url.Values{"administrativeScopesAllowed": {"off"}}, true, false},
		{"a value the checkbox never sends, over a client not allowed", false, url.Values{"administrativeScopesAllowed": {"off"}}, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &stubAdministrativeScopesApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool",
				AdministrativeScopesAllowed: tc.stored}}
			httpHelper := &stubHttpHelper{}

			rec := postSettings(t, apiClient, httpHelper, tc.form, "")

			require.NoError(t, httpHelper.err)
			assert.Equal(t, 1, apiClient.settingsWrites, "the settings are written by every save")
			if !tc.wantWrite {
				assert.Zero(t, apiClient.allowanceWrites, "an unchanged allowance is not written")
			} else {
				require.Equal(t, 1, apiClient.allowanceWrites, "a changed allowance is written once")
				require.NotNil(t, apiClient.sentAllowance.Allowed, "allowed is always sent, never left for the server to refuse")
				assert.Equal(t, tc.wantAllowed, *apiClient.sentAllowance.Allowed)
				assert.Equal(t, int64(7), apiClient.sentAllowanceTo)
				assert.Equal(t, handlertest.AccessToken, apiClient.sentAllowanceAs)
			}
			assert.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, consoleBaseURL+"/admin/clients/7/settings", rec.Header().Get("Location"))
		})
	}
}

// The admin console's own client is always allowed: its switch is drawn disabled, so a browser never
// submits it, and the save never writes it, whatever the body says.
func TestHandleSettingsPost_NeverWritesASystemLevelClientsAllowance(t *testing.T) {
	for _, form := range []url.Values{{}, {"administrativeScopesAllowed": {"on"}}} {
		apiClient := &stubAdministrativeScopesApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client",
			AdministrativeScopesAllowed: true, IsSystemLevelClient: true}}

		postSettings(t, apiClient, &stubHttpHelper{}, form, "")

		assert.Equal(t, 1, apiClient.settingsWrites)
		assert.Zero(t, apiClient.allowanceWrites, "form %v", form)
	}
}

// The switch is read from the request body alone. A switch in the URL is not a submission of the
// form, so it switches nothing on.
func TestHandleSettingsPost_IgnoresTheSwitchInTheQuery(t *testing.T) {
	apiClient := &stubAdministrativeScopesApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool"}}

	postSettings(t, apiClient, &stubHttpHelper{}, url.Values{}, "administrativeScopesAllowed=on")

	assert.Zero(t, apiClient.allowanceWrites, "the stored allowance is off and the body says off")
}

// A refused allowance comes after the settings were written, so the tab is drawn again from the
// client as it now stands, saying the settings were saved, with the refusal beside the switch, and
// nothing is redirected.
func TestHandleSettingsPost_ARefusedAllowanceLeavesTheSettingsSaved(t *testing.T) {
	const refusal = "Only authserver:manage may switch this."
	apiClient := &stubAdministrativeScopesApiClient{
		client:    &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool", DisplayName: "Ops"},
		updated:   &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool", DisplayName: "Ops tool"},
		updateErr: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: refusal, StatusCode: http.StatusBadRequest},
	}
	httpHelper := &stubHttpHelper{}

	rec := postSettings(t, apiClient, httpHelper, url.Values{"displayName": {"Ops tool"}, "administrativeScopesAllowed": {"on"}}, "")

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the settings page is rendered again")
	assert.Equal(t, refusal, httpHelper.bind["administrativeScopesError"])
	assert.Equal(t, true, httpHelper.bind["savedSuccessfully"], "the settings were written before the refusal")
	assert.Nil(t, httpHelper.bind["error"], "the settings form's own error slot stays empty")
	assert.Empty(t, rec.Header().Get("Location"))

	bound := reflect.ValueOf(httpHelper.bind["client"])
	assert.Equal(t, "Ops tool", bound.FieldByName("DisplayName").String(), "the client as it now stands")
	assert.False(t, bound.FieldByName("AdministrativeScopesAllowed").Bool(), "the stored allowance, not the refused one")
}

// A refused settings save writes no allowance, and draws the tab again with the switch as submitted,
// as every other input is.
func TestHandleSettingsPost_ARefusedSettingsSaveWritesNoAllowance(t *testing.T) {
	apiClient := &stubAdministrativeScopesApiClient{
		client:      &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool"},
		settingsErr: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "Invalid website URL.", StatusCode: http.StatusBadRequest},
	}
	httpHelper := &stubHttpHelper{}

	postSettings(t, apiClient, httpHelper, url.Values{"websiteUrl": {"not a url"}, "administrativeScopesAllowed": {"on"}}, "")

	require.NoError(t, httpHelper.err)
	assert.Zero(t, apiClient.allowanceWrites)
	require.NotNil(t, httpHelper.bind)
	assert.Equal(t, "Invalid website URL.", httpHelper.bind["error"])
	assert.True(t, reflect.ValueOf(httpHelper.bind["client"]).FieldByName("AdministrativeScopesAllowed").Bool(),
		"the switch as submitted")
	assert.False(t, reflect.ValueOf(httpHelper.bind["storedClient"]).FieldByName("AdministrativeScopesAllowed").Bool(),
		"and the stored allowance, which the switching-on question compares against")
}

// Only authserver:manage switches the allowance. For an administrator without it the switch is drawn
// disabled and never submitted, so the save keeps the stored allowance whatever the body says, and
// writes every other setting as before.
func TestHandleSettingsPost_WithoutManageTheAllowanceStands(t *testing.T) {
	for _, stored := range []bool{true, false} {
		for _, form := range []url.Values{{}, {"administrativeScopesAllowed": {"on"}}} {
			apiClient := &stubAdministrativeScopesApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool",
				AdministrativeScopesAllowed: stored}}
			httpHelper := &stubHttpHelper{}

			rec := postSettings(t, apiClient, httpHelper, form, "", "openid authserver:manage-clients")

			require.NoError(t, httpHelper.err)
			assert.Equal(t, 1, apiClient.settingsWrites)
			assert.Zero(t, apiClient.allowanceWrites, "stored %v, form %v", stored, form)
			assert.Equal(t, http.StatusFound, rec.Code)
		}
	}
}

// The tab shows the client's own privacy policy and terms of service URLs as the auth server
// answers them (#622 decision 12).
func TestHandleSettingsGet_BindsTheClientsDocumentURLs(t *testing.T) {
	httpHelper := &stubHttpHelper{}
	req := handlertest.Request(http.MethodGet, "/admin/clients/7/settings",
		handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"))
	client := &api.ClientResponse{Id: 7, ClientIdentifier: "portal",
		PrivacyPolicyURL: "https://portal.example.com/privacy", TermsOfServiceURL: "https://portal.example.com/terms"}

	HandleSettingsGet(httpHelper, newTestSessionStore(), &stubAdministrativeScopesApiClient{client: client}).
		ServeHTTP(httptest.NewRecorder(), req)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
	bound := reflect.ValueOf(httpHelper.bind["client"])
	assert.Equal(t, "https://portal.example.com/privacy", bound.FieldByName("PrivacyPolicyURL").String())
	assert.Equal(t, "https://portal.example.com/terms", bound.FieldByName("TermsOfServiceURL").String())
}

// A save sends the two URLs as typed, trimmed, and an emptied field as empty, which clears it; a
// refused save draws them again as typed.
func TestHandleSettingsPost_SendsTheClientsDocumentURLs(t *testing.T) {
	stored := &api.ClientResponse{Id: 7, ClientIdentifier: "portal",
		PrivacyPolicyURL: "https://portal.example.com/privacy", TermsOfServiceURL: "https://portal.example.com/terms"}
	apiClient := &stubAdministrativeScopesApiClient{client: stored}

	rec := postSettings(t, apiClient, &stubHttpHelper{}, url.Values{
		"clientIdentifier":  {"portal"},
		"privacyPolicyUrl":  {"  https://legal.example.org/portal/privacy  "},
		"termsOfServiceUrl": {""},
	}, "")

	assert.Equal(t, http.StatusFound, rec.Code)
	require.NotNil(t, apiClient.sentSettings)
	assert.Equal(t, "https://legal.example.org/portal/privacy", apiClient.sentSettings.PrivacyPolicyURL)
	assert.Empty(t, apiClient.sentSettings.TermsOfServiceURL, "an emptied field clears the URL")

	refused := &stubAdministrativeScopesApiClient{client: stored,
		settingsErr: &apiclient.APIError{Code: "handler.client.terms_of_service_url_invalid", Message: "Invalid terms of service URL.", StatusCode: http.StatusBadRequest}}
	httpHelper := &stubHttpHelper{}
	postSettings(t, refused, httpHelper, url.Values{
		"clientIdentifier":  {"portal"},
		"privacyPolicyUrl":  {"https://legal.example.org/portal/privacy"},
		"termsOfServiceUrl": {"not a url"},
	}, "")
	require.NotNil(t, httpHelper.bind, "the refused save is drawn again")
	assert.Equal(t, "termsOfServiceUrl", httpHelper.bind["errorField"], "the refusal names its field")
	drawn := reflect.ValueOf(httpHelper.bind["client"])
	assert.Equal(t, "https://legal.example.org/portal/privacy", drawn.FieldByName("PrivacyPolicyURL").String())
	assert.Equal(t, "not a url", drawn.FieldByName("TermsOfServiceURL").String(), "the input keeps what was typed")
}

// The tab draws Remember consent from the client as the auth server answers it, with whether the
// client is public, which decides whether the checkbox is drawn at all (#711 decision 8).
func TestHandleSettingsGet_BindsRememberConsent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client *api.ClientResponse
	}{
		{"a public client remembering consent", &api.ClientResponse{Id: 7, ClientIdentifier: "spa", IsPublic: true, RememberConsent: true}},
		{"a public client not remembering consent", &api.ClientResponse{Id: 7, ClientIdentifier: "spa", IsPublic: true}},
		{"a confidential client", &api.ClientResponse{Id: 7, ClientIdentifier: "portal", RememberConsent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := &stubHttpHelper{}
			req := handlertest.Request(http.MethodGet, "/admin/clients/7/settings",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"))

			HandleSettingsGet(httpHelper, newTestSessionStore(), &stubAdministrativeScopesApiClient{client: tc.client}).
				ServeHTTP(httptest.NewRecorder(), req)

			require.NoError(t, httpHelper.err)
			require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
			bound := reflect.ValueOf(httpHelper.bind["client"])
			assert.Equal(t, tc.client.RememberConsent, bound.FieldByName("RememberConsent").Bool())
			assert.Equal(t, tc.client.IsPublic, bound.FieldByName("IsPublic").Bool())
		})
	}
}

// For a client public as the save loads it, the save sends rememberConsent as the checkbox was
// submitted in the body: on only for the checkbox's own value, and off when it is absent, as a
// browser submits an unticked checkbox, or only in the query, which is no submission of this form
// (#711 decision 8).
func TestHandleSettingsPost_SendsAPublicClientsRememberConsentFromTheBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stored bool
		form   url.Values
		query  string
		want   bool
	}{
		{name: "ticked", form: url.Values{"rememberConsent": {"on"}}, want: true},
		{name: "ticked while already on", stored: true, form: url.Values{"rememberConsent": {"on"}}, want: true},
		{name: "unticked", stored: true, form: url.Values{}, want: false},
		{name: "only in the query", form: url.Values{}, query: "rememberConsent=on", want: false},
		{name: "a value other than the checkbox's", form: url.Values{"rememberConsent": {"true"}}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &stubAdministrativeScopesApiClient{
				client: &api.ClientResponse{Id: 7, ClientIdentifier: "spa", IsPublic: true, RememberConsent: tc.stored}}
			form := tc.form
			form.Set("clientIdentifier", "spa")

			rec := postSettings(t, apiClient, &stubHttpHelper{}, form, tc.query)

			assert.Equal(t, http.StatusFound, rec.Code)
			require.NotNil(t, apiClient.sentSettings)
			require.NotNil(t, apiClient.sentSettings.RememberConsent, "a public client's save carries rememberConsent")
			assert.Equal(t, tc.want, *apiClient.sentSettings.RememberConsent)
		})
	}
}

// A confidential client's save carries no rememberConsent, whatever the body holds: the auth server
// keeps it on for a confidential client, and the tab draws no checkbox for it (#711 decision 8).
func TestHandleSettingsPost_SendsNoRememberConsentForAConfidentialClient(t *testing.T) {
	for _, form := range []url.Values{
		{"clientIdentifier": {"portal"}},
		{"clientIdentifier": {"portal"}, "rememberConsent": {"on"}},
	} {
		apiClient := &stubAdministrativeScopesApiClient{
			client: &api.ClientResponse{Id: 7, ClientIdentifier: "portal", RememberConsent: true}}

		rec := postSettings(t, apiClient, &stubHttpHelper{}, form, "")

		assert.Equal(t, http.StatusFound, rec.Code)
		require.NotNil(t, apiClient.sentSettings)
		assert.Nil(t, apiClient.sentSettings.RememberConsent, "form %v", form)
	}
}

// A refused save draws the checkbox again as submitted, so the administrator does not lose it.
func TestHandleSettingsPost_ARefusedSaveKeepsRememberConsentAsSubmitted(t *testing.T) {
	apiClient := &stubAdministrativeScopesApiClient{
		client:      &api.ClientResponse{Id: 7, ClientIdentifier: "spa", IsPublic: true},
		settingsErr: &apiclient.APIError{Code: "handler.client.website_url_invalid", Message: "Invalid website URL.", StatusCode: http.StatusBadRequest}}
	httpHelper := &stubHttpHelper{}

	postSettings(t, apiClient, httpHelper, url.Values{"clientIdentifier": {"spa"}, "rememberConsent": {"on"}, "websiteUrl": {"x"}}, "")

	require.NotNil(t, httpHelper.bind, "the refused save is drawn again")
	assert.True(t, reflect.ValueOf(httpHelper.bind["client"]).FieldByName("RememberConsent").Bool(), "drawn as submitted")
	assert.False(t, reflect.ValueOf(httpHelper.bind["storedClient"]).FieldByName("RememberConsent").Bool(), "compared with the stored value")
}

func brandIdPtr(id int64) *int64 { return &id }

// The brands as the auth server lists them, by name, the default marked: Autumn (4), Default (5)
// and Spring (6).
var testBrands = []api.BrandResponse{
	{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
	{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
	{Id: 6, Name: "Spring", Appearance: "light", Theme: "avocado"},
}

// The Brand select under Sign-in and consent pages (#812 decision 6): Default brand first, naming
// the current default, then every brand by name in the auth server's order, the client's own brand
// selected, or Default brand for a client with none of its own.
func TestHandleSettingsGet_BindsTheBrandSelect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		brandId *int64
		want    int64
	}{
		{"a client with no brand of its own", nil, 0},
		{"a client given a brand", brandIdPtr(6), 6},
		{"a client given the default brand itself", brandIdPtr(5), 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := &stubHttpHelper{}
			req := handlertest.Request(http.MethodGet, "/admin/clients/7/settings",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"))
			apiClient := &stubAdministrativeScopesApiClient{brands: testBrands,
				client: &api.ClientResponse{Id: 7, ClientIdentifier: "portal", BrandId: tc.brandId}}

			HandleSettingsGet(httpHelper, newTestSessionStore(), apiClient).ServeHTTP(httptest.NewRecorder(), req)

			require.NoError(t, httpHelper.err)
			require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
			assert.Equal(t, "Default", httpHelper.bind["defaultBrandName"])
			assert.Equal(t, []BrandOption{{Id: 4, Name: "Autumn"}, {Id: 5, Name: "Default"}, {Id: 6, Name: "Spring"}},
				httpHelper.bind["brands"])
			assert.Equal(t, tc.want, reflect.ValueOf(httpHelper.bind["client"]).FieldByName("BrandId").Int())
			assert.Equal(t, tc.want, reflect.ValueOf(httpHelper.bind["storedClient"]).FieldByName("BrandId").Int())
		})
	}
}

// The brand is saved by the tab's one Save, after the settings and only when the select differs
// from the client's stored brand (#812 decision 6): an empty value puts the client back on the
// default brand, sent as null, and a number gives it that brand. The default brand chosen by name
// is a brand of its own, apart from Default brand. A select that was not submitted, or a value it
// never sends, keeps the stored brand.
func TestHandleSettingsPost_WritesTheBrandOnlyWhenItChanged(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stored    *int64
		form      url.Values
		wantWrite bool
		wantSent  *int64
	}{
		{name: "left on the default", form: url.Values{"brandId": {""}}},
		{name: "given a brand", form: url.Values{"brandId": {"6"}}, wantWrite: true, wantSent: brandIdPtr(6)},
		{name: "given the default brand by name", form: url.Values{"brandId": {"5"}}, wantWrite: true, wantSent: brandIdPtr(5)},
		{name: "put back on the default", stored: brandIdPtr(6), form: url.Values{"brandId": {""}}, wantWrite: true},
		{name: "put back from the default brand by name", stored: brandIdPtr(5), form: url.Values{"brandId": {""}}, wantWrite: true},
		{name: "moved to another brand", stored: brandIdPtr(4), form: url.Values{"brandId": {"6"}}, wantWrite: true, wantSent: brandIdPtr(6)},
		{name: "left on its brand", stored: brandIdPtr(6), form: url.Values{"brandId": {"6"}}},
		{name: "the select not submitted", stored: brandIdPtr(6), form: url.Values{}},
		{name: "a value the select never sends", stored: brandIdPtr(6), form: url.Values{"brandId": {"autumn"}}},
		{name: "a brand id that is no id", stored: brandIdPtr(6), form: url.Values{"brandId": {"0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &stubAdministrativeScopesApiClient{brands: testBrands,
				client: &api.ClientResponse{Id: 7, ClientIdentifier: "portal", BrandId: tc.stored}}
			httpHelper := &stubHttpHelper{}
			cache := &invalidationRecorder{}

			rec := postSettingsDropping(t, apiClient, httpHelper, cache, tc.form, "")

			require.NoError(t, httpHelper.err)
			assert.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, consoleBaseURL+"/admin/clients/7/settings", rec.Header().Get("Location"))
			if !tc.wantWrite {
				assert.Zero(t, apiClient.brandWrites, "an unchanged brand is not written")
				assert.Equal(t, []string{"settings"}, apiClient.writes)
				return
			}
			assert.Equal(t, []string{"settings", "brand"}, apiClient.writes, "the brand is written once, after the settings")
			require.NotNil(t, apiClient.sentBrand)
			assert.Equal(t, tc.wantSent, apiClient.sentBrand.BrandId)
			assert.Equal(t, int64(7), apiClient.sentBrandTo)
			assert.Equal(t, handlertest.AccessToken, apiClient.sentBrandAs)
			assert.Zero(t, cache.invalidations, "another client's brand leaves the console's look alone")
		})
	}
}

// The select is read from the body alone, as the tab's other switches are: a brand in the URL is no
// submission of the form.
func TestHandleSettingsPost_IgnoresTheBrandInTheQuery(t *testing.T) {
	apiClient := &stubAdministrativeScopesApiClient{brands: testBrands,
		client: &api.ClientResponse{Id: 7, ClientIdentifier: "portal", BrandId: brandIdPtr(6)}}

	postSettings(t, apiClient, &stubHttpHelper{}, url.Values{}, "brandId=")

	assert.Zero(t, apiClient.brandWrites)
}

// A refused settings save writes no brand, and draws the tab again with the select as submitted,
// beside the brands it offers.
func TestHandleSettingsPost_ARefusedSettingsSaveWritesNoBrand(t *testing.T) {
	apiClient := &stubAdministrativeScopesApiClient{brands: testBrands,
		client:      &api.ClientResponse{Id: 7, ClientIdentifier: "portal"},
		settingsErr: &apiclient.APIError{Code: "handler.client.website_url_invalid", Message: "Invalid website URL.", StatusCode: http.StatusBadRequest}}
	httpHelper := &stubHttpHelper{}

	postSettings(t, apiClient, httpHelper, url.Values{"websiteUrl": {"x"}, "brandId": {"6"}}, "")

	require.NoError(t, httpHelper.err)
	assert.Zero(t, apiClient.brandWrites)
	require.NotNil(t, httpHelper.bind, "the refused save is drawn again")
	assert.Equal(t, int64(6), reflect.ValueOf(httpHelper.bind["client"]).FieldByName("BrandId").Int(), "drawn as submitted")
	assert.Equal(t, int64(0), reflect.ValueOf(httpHelper.bind["storedClient"]).FieldByName("BrandId").Int())
	assert.Equal(t, "Default", httpHelper.bind["defaultBrandName"])
	assert.Equal(t, []BrandOption{{Id: 4, Name: "Autumn"}, {Id: 5, Name: "Default"}, {Id: 6, Name: "Spring"}},
		httpHelper.bind["brands"])
}

// A brand deleted between loading the tab and saving it is refused after the settings were written:
// the tab is drawn again from the client as it now stands, saying the settings were saved, with the
// auth server's refusal on the select, which offers the brands as they now stand. Nothing is
// redirected and the console's look is left alone.
func TestHandleSettingsPost_ARefusedBrandLeavesTheSettingsSaved(t *testing.T) {
	const refusal = "The brand does not exist."
	apiClient := &stubAdministrativeScopesApiClient{brands: testBrands,
		client:   &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client", DisplayName: "Console", IsSystemLevelClient: true},
		updated:  &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client", DisplayName: "Admin console", IsSystemLevelClient: true},
		brandErr: &apiclient.APIError{Code: "handler.client_brand.brand_not_found", Message: refusal, StatusCode: http.StatusBadRequest},
	}
	httpHelper := &stubHttpHelper{}
	cache := &invalidationRecorder{}

	rec := postSettingsDropping(t, apiClient, httpHelper, cache, url.Values{"displayName": {"Admin console"}, "brandId": {"9"}}, "")

	require.NoError(t, httpHelper.err)
	assert.Equal(t, []string{"settings", "brand"}, apiClient.writes)
	require.NotNil(t, httpHelper.bind, "the settings page is rendered again")
	assert.Empty(t, rec.Header().Get("Location"))
	assert.Equal(t, refusal, httpHelper.bind["brandError"])
	assert.Equal(t, true, httpHelper.bind["savedSuccessfully"], "the settings were written before the refusal")
	assert.Nil(t, httpHelper.bind["error"], "the settings form's own error slot stays empty")
	bound := reflect.ValueOf(httpHelper.bind["client"])
	assert.Equal(t, "Admin console", bound.FieldByName("DisplayName").String(), "the client as it now stands")
	assert.Equal(t, int64(0), bound.FieldByName("BrandId").Int(), "the stored brand, not the refused one")
	assert.Equal(t, []BrandOption{{Id: 4, Name: "Autumn"}, {Id: 5, Name: "Default"}, {Id: 6, Name: "Spring"}},
		httpHelper.bind["brands"])
	assert.Zero(t, cache.invalidations, "a refused brand changed nothing")
}

// Saving the brand of the admin console's own client drops the console's cached copy of the public
// settings, so its pages take the brand at once (#812 decision 6); a save of that client that leaves
// its brand alone does not.
func TestHandleSettingsPost_TheConsolesOwnBrandDropsItsCachedSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		form url.Values
		want int
	}{
		{"given a brand", url.Values{"brandId": {"4"}}, 1},
		{"put back on the default", url.Values{"brandId": {""}}, 1},
		{"its brand left alone", url.Values{"brandId": {"6"}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &stubAdministrativeScopesApiClient{brands: testBrands,
				client: &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client", BrandId: brandIdPtr(6),
					AdministrativeScopesAllowed: true, IsSystemLevelClient: true}}
			cache := &invalidationRecorder{}

			rec := postSettingsDropping(t, apiClient, &stubHttpHelper{}, cache, tc.form, "")

			assert.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, tc.want, cache.invalidations)
		})
	}
}
