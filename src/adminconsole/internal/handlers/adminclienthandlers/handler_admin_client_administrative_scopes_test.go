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
	"github.com/leodip/goiabada/core/api"
)

// stubAdministrativeScopesApiClient implements the settings page's port and the allowance's: the
// client the page is drawn from, and the two writes, each recording what it was sent.
type stubAdministrativeScopesApiClient struct {
	client *api.ClientResponse
	// updateErr is what the allowance's write answers.
	updateErr error

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

// The allowance's form posts the switch alone, and the handler sends the API what it says: on is
// allowed, and a switch left off, which a browser does not submit at all, is not allowed. It is sent
// for the client the route names, with the administrator's own token, and the settings save is not
// touched.
func TestHandleAdministrativeScopesPost_SendsTheSwitchAsSubmitted(t *testing.T) {
	testCases := []struct {
		name        string
		form        url.Values
		wantAllowed bool
	}{
		{"switched on", url.Values{"administrativeScopesAllowed": {"on"}}, true},
		{"switched off", url.Values{}, false},
		// Only the checkbox's own value switches it on: anything else fails closed, as a
		// security switch should.
		{"a value the checkbox never sends", url.Values{"administrativeScopesAllowed": {"off"}}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &stubAdministrativeScopesApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool"}}
			httpHelper := &stubHttpHelper{}
			req := handlertest.Request(http.MethodPost, "/admin/clients/7/settings/administrative-scopes",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"),
				handlertest.WithForm(tc.form))
			rec := httptest.NewRecorder()

			HandleAdministrativeScopesPost(httpHelper, newTestSessionStore(), apiClient, consoleBaseURL).ServeHTTP(rec, req)

			require.NoError(t, httpHelper.err)
			require.Equal(t, 1, apiClient.allowanceWrites, "the allowance is written once")
			require.NotNil(t, apiClient.sentAllowance.Allowed, "allowed is always sent, never left for the server to refuse")
			assert.Equal(t, tc.wantAllowed, *apiClient.sentAllowance.Allowed)
			assert.Equal(t, int64(7), apiClient.sentAllowanceTo)
			assert.Equal(t, handlertest.AccessToken, apiClient.sentAllowanceAs)
			assert.Zero(t, apiClient.settingsWrites, "the settings save is a different form")

			assert.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, consoleBaseURL+"/admin/clients/7/settings", rec.Header().Get("Location"))
		})
	}
}

// The switch is read from the request body alone. A switch in the URL is not a submission of the
// form, so a POST whose body says nothing sends "not allowed", whatever the query says.
func TestHandleAdministrativeScopesPost_IgnoresTheSwitchInTheQuery(t *testing.T) {
	apiClient := &stubAdministrativeScopesApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool"}}
	req := handlertest.Request(http.MethodPost, "/admin/clients/7/settings/administrative-scopes?administrativeScopesAllowed=on",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"),
		handlertest.WithForm(url.Values{}))

	HandleAdministrativeScopesPost(&stubHttpHelper{}, newTestSessionStore(), apiClient, consoleBaseURL).
		ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, apiClient.sentAllowance)
	require.NotNil(t, apiClient.sentAllowance.Allowed)
	assert.False(t, *apiClient.sentAllowance.Allowed)
}

// A refusal the administrator can act on, such as switching the admin console's client off, comes
// back on the settings page beside the allowance's own Save, with the client as stored: the
// settings form is drawn from the client, not from what this form posted, and nothing is redirected.
func TestHandleAdministrativeScopesPost_ARefusalIsShownOnTheSettingsPage(t *testing.T) {
	const refusal = "The admin console's client is always allowed to request the administrative scopes."
	apiClient := &stubAdministrativeScopesApiClient{
		client: &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client", DisplayName: "Admin console",
			AdministrativeScopesAllowed: true, IsSystemLevelClient: true, ConsentRequired: false},
		updateErr: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: refusal, StatusCode: http.StatusBadRequest},
	}
	httpHelper := &stubHttpHelper{}
	req := handlertest.Request(http.MethodPost, "/admin/clients/7/settings/administrative-scopes",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"),
		handlertest.WithForm(url.Values{}))
	rec := httptest.NewRecorder()

	HandleAdministrativeScopesPost(httpHelper, newTestSessionStore(), apiClient, consoleBaseURL).ServeHTTP(rec, req)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the settings page is rendered again")
	assert.Equal(t, refusal, httpHelper.bind["administrativeScopesError"])
	assert.Nil(t, httpHelper.bind["error"], "the settings form's own error slot stays empty")
	assert.Empty(t, rec.Header().Get("Location"))

	bound := reflect.ValueOf(httpHelper.bind["client"])
	assert.Equal(t, "admin-console-client", bound.FieldByName("ClientIdentifier").String())
	assert.Equal(t, "Admin console", bound.FieldByName("DisplayName").String())
	assert.True(t, bound.FieldByName("AdministrativeScopesAllowed").Bool(), "the stored allowance, not the refused one")
	assert.True(t, bound.FieldByName("IsSystemLevelClient").Bool())
}

// A save that went through is announced beside the allowance's Save on the page the browser is
// sent back to, and not as a save of the settings form.
func TestHandleAdministrativeScopesPost_ASavedSwitchIsAnnouncedOnTheSettingsPage(t *testing.T) {
	store := newTestSessionStore()
	apiClient := &stubAdministrativeScopesApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "ops-tool"}}
	post := handlertest.Request(http.MethodPost, "/admin/clients/7/settings/administrative-scopes",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"),
		handlertest.WithForm(url.Values{"administrativeScopesAllowed": {"on"}}))
	postRec := httptest.NewRecorder()

	HandleAdministrativeScopesPost(&stubHttpHelper{}, store, apiClient, consoleBaseURL).ServeHTTP(postRec, post)
	require.Equal(t, http.StatusFound, postRec.Code)

	get := handlertest.Request(http.MethodGet, "/admin/clients/7/settings",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"))
	for _, cookie := range postRec.Result().Cookies() {
		get.AddCookie(cookie)
	}
	httpHelper := &stubHttpHelper{}
	HandleSettingsGet(httpHelper, store, apiClient).ServeHTTP(httptest.NewRecorder(), get)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind)
	assert.Equal(t, true, httpHelper.bind["administrativeScopesSaved"])
	assert.Equal(t, false, httpHelper.bind["savedSuccessfully"])
}
