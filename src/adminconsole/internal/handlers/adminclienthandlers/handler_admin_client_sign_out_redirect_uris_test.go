package adminclienthandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
)

// stubSignOutListAPI implements the Sign-out redirect URIs page's port, and nothing beyond it, so a
// call the port does not name does not compile.
type stubSignOutListAPI struct {
	updateErr error
	client    *api.ClientResponse
	settings  *api.SettingsGeneralResponse
	// sent and sentClientId are what the handler handed the API.
	sent         *api.UpdateClientPostLogoutRedirectURIsRequest
	sentClientId int64
}

func (s *stubSignOutListAPI) UpdateClientPostLogoutRedirectURIs(_ context.Context, _ string, clientId int64,
	request *api.UpdateClientPostLogoutRedirectURIsRequest) (*api.ClientResponse, error) {
	s.sent = request
	s.sentClientId = clientId
	return nil, s.updateErr
}

func (s *stubSignOutListAPI) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.client, nil
}

func (s *stubSignOutListAPI) GetSettingsGeneral(_ context.Context, _ string) (*api.SettingsGeneralResponse, error) {
	return s.settings, nil
}

// signOutListBind serves the tab for client 7 and returns the "client" value it bound.
func signOutListBind(t *testing.T, apiClient *stubSignOutListAPI) reflect.Value {
	t.Helper()
	httpHelper := &stubHttpHelper{}
	req := handlertest.Request(http.MethodGet, "/admin/clients/7/sign-out-redirect-uris",
		handlertest.WithAccessToken(),
		handlertest.WithPathValue("clientId", "7"),
	)
	HandleSignOutRedirectURIsGet(httpHelper, newTestSessionStore(), apiClient).ServeHTTP(httptest.NewRecorder(), req)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
	return reflect.ValueOf(httpHelper.bind["client"])
}

// The tab shows the client's sign-out redirect URIs, sorted, and none of its redirect URIs: the two
// lists are kept apart (#147 decision 6).
func TestHandleSignOutRedirectURIsGet_ListsTheSignOutList(t *testing.T) {
	client := signOutListBind(t, &stubSignOutListAPI{
		client: &api.ClientResponse{
			Id:                       7,
			ClientIdentifier:         "a-web-app",
			AuthorizationCodeEnabled: true,
			RedirectURIs: []api.RedirectURIResponse{
				{Id: 1, URI: "https://app.example.com/callback"},
			},
			PostLogoutRedirectURIs: []api.PostLogoutRedirectURIResponse{
				{Id: 4, URI: "https://app.example.com/signed-out"},
				{Id: 2, URI: "https://app.example.com/bye?state=fixed"},
			},
		},
		settings: &api.SettingsGeneralResponse{},
	})

	field := client.FieldByName("SignOutRedirectURIs")
	require.True(t, field.IsValid(), "the bind carries no SignOutRedirectURIs")
	assert.Equal(t, []string{"https://app.example.com/bye?state=fixed", "https://app.example.com/signed-out"}, field.Interface())
	assert.Equal(t, int64(7), client.FieldByName("ClientId").Int())
	assert.Equal(t, "a-web-app", client.FieldByName("ClientIdentifier").String())
}

// The admin console's own client is marked, so its save asks first; another client is not.
func TestHandleSignOutRedirectURIsGet_MarksTheSystemClient(t *testing.T) {
	for _, system := range []bool{true, false} {
		client := signOutListBind(t, &stubSignOutListAPI{
			client:   &api.ClientResponse{Id: 7, ClientIdentifier: "a-client", AuthorizationCodeEnabled: true, IsSystemLevelClient: system},
			settings: &api.SettingsGeneralResponse{},
		})
		field := client.FieldByName("IsSystemLevelClient")
		require.True(t, field.IsValid(), "the bind carries no IsSystemLevelClient")
		assert.Equal(t, system, field.Bool())
	}
}

// The tab is gated as the auth server's save is: the client must use the authorization code flow
// or the implicit flow, and implicit is a per-client override over a global default. The
// authorization code flow is off on the implicit rows, so a gate that ignored implicit fails them.
func TestHandleSignOutRedirectURIsGet_ResolvesRedirectFlows(t *testing.T) {

	testCases := []struct {
		name           string
		authCode       bool
		clientImplicit *bool
		globalImplicit bool
		wantCanManage  bool
	}{
		{name: "the authorization code flow", authCode: true, wantCanManage: true},
		{name: "implicit switched on for the client, global off", clientImplicit: boolPtr(true), wantCanManage: true},
		{name: "implicit inherited from a global that is on", globalImplicit: true, wantCanManage: true},
		{name: "implicit switched off over a global that is on", clientImplicit: boolPtr(false), globalImplicit: true, wantCanManage: false},
		{name: "neither redirect-based flow", wantCanManage: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := signOutListBind(t, &stubSignOutListAPI{
				client: &api.ClientResponse{
					Id:                       7,
					ClientIdentifier:         "an-app",
					AuthorizationCodeEnabled: tc.authCode,
					ImplicitGrantEnabled:     tc.clientImplicit,
				},
				settings: &api.SettingsGeneralResponse{ImplicitFlowEnabled: tc.globalImplicit},
			})

			field := client.FieldByName("CanManageSignOutRedirectURIs")
			require.True(t, field.IsValid(), "the bind carries no CanManageSignOutRedirectURIs")
			assert.Equal(t, tc.wantCanManage, field.Bool())
		})
	}
}

// The page posts the list it wants beside the list as it loaded it, and the handler hands both to
// the API's sign-out list save unchanged: [] stays [], and an absent loaded list stays null, which
// the API refuses, rather than defaulting to a list that would pass its check (#428).
func TestHandleSignOutRedirectURIsPost_SendsTheLoadedList(t *testing.T) {

	testCases := []struct {
		name         string
		body         string
		wantWanted   []string
		wantExpected []string
		wantWire     string
	}{
		{
			name:         "the loaded list passes through beside the wanted one",
			body:         `{"clientId":9,"signOutRedirectURIs":["https://a.example/bye","myapp:/signed-out"],"expectedSignOutRedirectURIs":["https://a.example/bye"]}`,
			wantWanted:   []string{"https://a.example/bye", "myapp:/signed-out"},
			wantExpected: []string{"https://a.example/bye"},
			wantWire:     `{"postLogoutRedirectURIs":["https://a.example/bye","myapp:/signed-out"],"expectedPostLogoutRedirectURIs":["https://a.example/bye"]}`,
		},
		{
			name:         "an empty loaded list stays an empty list",
			body:         `{"clientId":9,"signOutRedirectURIs":["https://a.example/bye"],"expectedSignOutRedirectURIs":[]}`,
			wantWanted:   []string{"https://a.example/bye"},
			wantExpected: []string{},
			wantWire:     `{"postLogoutRedirectURIs":["https://a.example/bye"],"expectedPostLogoutRedirectURIs":[]}`,
		},
		{
			name:         "an absent loaded list stays absent",
			body:         `{"clientId":9,"signOutRedirectURIs":["https://a.example/bye"]}`,
			wantWanted:   []string{"https://a.example/bye"},
			wantExpected: nil,
			wantWire:     `{"postLogoutRedirectURIs":["https://a.example/bye"],"expectedPostLogoutRedirectURIs":null}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := handlertest.Request(http.MethodPost, "/admin/clients/9/sign-out-redirect-uris",
				handlertest.WithAccessToken(),
				handlertest.WithBody(bytes.NewBufferString(tc.body)),
			)
			// The API refuses, so the handler returns before the nil session is touched; the
			// request it sent is what is under test.
			stub := &stubSignOutListAPI{updateErr: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "refused", StatusCode: http.StatusBadRequest}}
			HandleSignOutRedirectURIsPost(render.New(nil, nil), nil, stub).ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, stub.sent, "the handler sent nothing")
			assert.Equal(t, int64(9), stub.sentClientId)
			assert.Equal(t, tc.wantWanted, stub.sent.PostLogoutRedirectURIs)
			assert.Equal(t, tc.wantExpected, stub.sent.ExpectedPostLogoutRedirectURIs)

			wire, err := json.Marshal(stub.sent)
			require.NoError(t, err)
			assert.JSONEq(t, tc.wantWire, string(wire))
		})
	}
}

// A save the API takes answers Success, and the reloaded tab says the list was saved.
func TestHandleSignOutRedirectURIsPost_ASavedListIsSaidOnTheReloadedTab(t *testing.T) {
	sessions := newTestSessionStore()
	stub := &stubSignOutListAPI{
		client:   &api.ClientResponse{Id: 9, ClientIdentifier: "an-app", AuthorizationCodeEnabled: true},
		settings: &api.SettingsGeneralResponse{},
	}

	req := handlertest.Request(http.MethodPost, "/admin/clients/9/sign-out-redirect-uris",
		handlertest.WithAccessToken(),
		handlertest.WithBody(bytes.NewBufferString(`{"clientId":9,"signOutRedirectURIs":["https://a.example/bye"],"expectedSignOutRedirectURIs":[]}`)),
	)
	rec := httptest.NewRecorder()
	HandleSignOutRedirectURIsPost(render.New(nil, nil), sessions, stub).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"Success":true}`, rec.Body.String())

	httpHelper := &stubHttpHelper{}
	reload := handlertest.Request(http.MethodGet, "/admin/clients/9/sign-out-redirect-uris",
		handlertest.WithAccessToken(),
		handlertest.WithPathValue("clientId", "9"),
	)
	for _, cookie := range rec.Result().Cookies() {
		reload.AddCookie(cookie)
	}
	HandleSignOutRedirectURIsGet(httpHelper, sessions, stub).ServeHTTP(httptest.NewRecorder(), reload)
	require.NoError(t, httpHelper.err)
	assert.Equal(t, true, httpHelper.bind["savedSuccessfully"])
}

// A refusal from the API reaches the tab's status: a 400 names the entry refused and why, and a 409
// says the list changed since the page loaded it. A server fault stays a generic 500 (#122).
func TestHandleSignOutRedirectURIsPost_APIErrorReachesTheBrowser(t *testing.T) {

	const refusal = "Sign-out redirect URI must not use plain http on a host other than the loopback " +
		"interface (127.0.0.1, [::1] or localhost): http://app.example.com/bye"
	const generic = "An unexpected server error has occurred"

	testCases := []struct {
		name            string
		apiErr          error
		wantStatus      int
		wantError       string
		wantDescription string
	}{
		{
			name:            "a 400 is forwarded with its status and description",
			apiErr:          &apiclient.APIError{Code: "VALIDATION_ERROR", Message: refusal, StatusCode: http.StatusBadRequest},
			wantStatus:      http.StatusBadRequest,
			wantError:       "VALIDATION_ERROR",
			wantDescription: refusal,
		},
		{
			name:            "a 409 is forwarded with its status and description",
			apiErr:          &apiclient.APIError{Code: "CONCURRENT_UPDATE", Message: "The list was changed by another save after it was loaded.", StatusCode: http.StatusConflict},
			wantStatus:      http.StatusConflict,
			wantError:       "CONCURRENT_UPDATE",
			wantDescription: "The list was changed by another save after it was loaded.",
		},
		{
			name:            "a 500 from the API stays generic",
			apiErr:          &apiclient.APIError{Code: "SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError},
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
		{
			name:            "a transport error stays generic",
			apiErr:          errors.New("connection refused"),
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := handlertest.Request(http.MethodPost, "/admin/clients/1/sign-out-redirect-uris",
				handlertest.WithAccessToken(),
				handlertest.WithBody(bytes.NewBufferString(`{"clientId":1,"signOutRedirectURIs":["http://app.example.com/bye"],"expectedSignOutRedirectURIs":[]}`)),
			)
			rec := httptest.NewRecorder()

			// httpSession is nil: every case here returns before the session is touched.
			HandleSignOutRedirectURIsPost(render.New(nil, nil), nil, &stubSignOutListAPI{updateErr: tc.apiErr}).ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)
			var response map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
			assert.Equal(t, tc.wantError, response["error"])
			assert.Contains(t, response["error_description"], tc.wantDescription)
			if tc.wantStatus == http.StatusInternalServerError {
				assert.NotContains(t, response["error_description"], tc.apiErr.Error())
			}
		})
	}
}
