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
// from, the settings' write and the allowance's, each recording what it was sent.
type stubAdministrativeScopesApiClient struct {
	client *api.ClientResponse
	// updated is what the settings' write answers, the client as it then stands.
	updated *api.ClientResponse
	// settingsErr and updateErr are what the settings' write and the allowance's answer.
	settingsErr error
	updateErr   error

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
	_ *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	s.settingsWrites++
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
	s.sentAllowance = request
	s.sentAllowanceTo = clientId
	s.sentAllowanceAs = accessToken
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	return s.client, nil
}

// manageGrant is the scope an administrator holding authserver:manage was granted, the one scope the
// auth server lets switch the allowance.
const manageGrant = "openid authserver:manage"

// postSettings posts the Settings tab for client 7 with form, and with query on the URL when given,
// as an administrator granted scope.
func postSettings(t *testing.T, apiClient clientSettingsAPI, httpHelper *stubHttpHelper, form url.Values, query string, scope ...string) *httptest.ResponseRecorder {
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
		handlertest.WithRouteParam("clientId", "7"), handlertest.WithForm(form))
	rec := httptest.NewRecorder()
	HandleSettingsPost(httpHelper, newTestSessionStore(), apiClient, consoleBaseURL).ServeHTTP(rec, req)
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
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"))

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
			handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"))
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
