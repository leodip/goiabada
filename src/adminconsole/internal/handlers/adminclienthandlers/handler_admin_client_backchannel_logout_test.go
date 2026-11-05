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

// stubBackchannelLogoutAPI implements the Back-channel logout tab's port, and nothing beyond it, so a
// call the port does not name does not compile.
type stubBackchannelLogoutAPI struct {
	client    *api.ClientResponse
	settings  *api.SettingsGeneralResponse
	updateErr error

	// sent and sentClientId are what the save handed the API, and writes how many saves reached it.
	sent         *api.UpdateClientBackchannelLogoutRequest
	sentClientId int64
	writes       int
}

func (s *stubBackchannelLogoutAPI) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.client, nil
}

func (s *stubBackchannelLogoutAPI) GetSettingsGeneral(_ context.Context, _ string) (*api.SettingsGeneralResponse, error) {
	if s.settings == nil {
		return &api.SettingsGeneralResponse{}, nil
	}
	return s.settings, nil
}

func (s *stubBackchannelLogoutAPI) UpdateClientBackchannelLogout(_ context.Context, _ string, clientId int64,
	request *api.UpdateClientBackchannelLogoutRequest) (*api.ClientResponse, error) {
	s.writes++
	s.sent = request
	s.sentClientId = clientId
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	return s.client, nil
}

// backchannelLogoutBind serves the tab for client 7 and returns the "client" value it bound.
func backchannelLogoutBind(t *testing.T, apiClient *stubBackchannelLogoutAPI) reflect.Value {
	t.Helper()
	httpHelper := &stubHttpHelper{}
	req := handlertest.Request(http.MethodGet, "/admin/clients/7/backchannel-logout",
		handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"))
	HandleBackchannelLogoutGet(httpHelper, newTestSessionStore(), apiClient).ServeHTTP(httptest.NewRecorder(), req)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
	return reflect.ValueOf(httpHelper.bind["client"])
}

// postBackchannelLogout posts the tab for client 7 with form, and with query on the URL when given,
// as an administrator granted scope.
func postBackchannelLogout(t *testing.T, apiClient *stubBackchannelLogoutAPI, httpHelper *stubHttpHelper,
	form url.Values, query, scope string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/admin/clients/7/backchannel-logout"
	if query != "" {
		target += "?" + query
	}
	req := handlertest.Request(http.MethodPost, target,
		handlertest.WithJwtInfo(oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken, Scope: scope}}),
		handlertest.WithPathValue("clientId", "7"), handlertest.WithForm(form))
	rec := httptest.NewRecorder()
	HandleBackchannelLogoutPost(httpHelper, newTestSessionStore(), apiClient, consoleBaseURL).ServeHTTP(rec, req)
	return rec
}

// The tab shows the client's back-channel logout URI and whether it requires the session identifier,
// as the auth server answers them.
func TestHandleBackchannelLogoutGet_BindsBothSettings(t *testing.T) {
	for _, tc := range []struct {
		name            string
		uri             string
		sessionRequired bool
	}{
		{"a URI that requires the session identifier", "https://app.example.com/backchannel-logout?tenant=a", true},
		{"a URI that does not", "http://app:3000/backchannel-logout", false},
		{"none", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := backchannelLogoutBind(t, &stubBackchannelLogoutAPI{client: &api.ClientResponse{
				Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true,
				BackchannelLogoutURI: tc.uri, BackchannelLogoutSessionRequired: tc.sessionRequired}})

			assert.Equal(t, tc.uri, client.FieldByName("BackchannelLogoutURI").String())
			assert.Equal(t, tc.sessionRequired, client.FieldByName("BackchannelLogoutSessionRequired").Bool())
			assert.Equal(t, int64(7), client.FieldByName("ClientId").Int())
			assert.Equal(t, "a-web-app", client.FieldByName("ClientIdentifier").String())
		})
	}
}

// The tab is gated as the auth server's save is, and as its neighbour, the Sign-out redirect URIs
// tab: a URI is for a client that signs users in through the authorization code flow or the implicit
// flow, the implicit flow a per-client override over the global default (#784 decision 9).
func TestHandleBackchannelLogoutGet_ResolvesTheSignInFlows(t *testing.T) {
	for _, tc := range []struct {
		name           string
		authCode       bool
		clientImplicit *bool
		globalImplicit bool
		want           bool
	}{
		{name: "the authorization code flow", authCode: true, want: true},
		{name: "implicit switched on for the client, global off", clientImplicit: boolPtr(true), want: true},
		{name: "implicit inherited from a global that is on", globalImplicit: true, want: true},
		{name: "implicit switched off over a global that is on", clientImplicit: boolPtr(false), globalImplicit: true, want: false},
		{name: "neither flow that signs users in", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := backchannelLogoutBind(t, &stubBackchannelLogoutAPI{
				client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-client", ClientCredentialsEnabled: true,
					AuthorizationCodeEnabled: tc.authCode, ImplicitGrantEnabled: tc.clientImplicit},
				settings: &api.SettingsGeneralResponse{ImplicitFlowEnabled: tc.globalImplicit},
			})
			assert.Equal(t, tc.want, client.FieldByName("CanManageBackchannelLogout").Bool())
		})
	}
}

// A save sends both settings to the auth server's own route: the URI as typed, trimmed, an emptied
// field as empty, which clears it, and the checkbox on only for its own value in the body. A browser
// submits an unticked checkbox as nothing, and a value in the query is no submission of this form.
// The tab is then drawn again from the redirect, saying it was saved.
func TestHandleBackchannelLogoutPost_SendsBothSettings(t *testing.T) {
	for _, tc := range []struct {
		name                string
		form                url.Values
		query               string
		wantURI             string
		wantSessionRequired bool
	}{
		{name: "a URI requiring the session identifier",
			form:    url.Values{"backchannelLogoutUri": {"  https://app.example.com/backchannel-logout?tenant=a  "}, "backchannelLogoutSessionRequired": {"on"}},
			wantURI: "https://app.example.com/backchannel-logout?tenant=a", wantSessionRequired: true},
		{name: "a URI, the checkbox unticked",
			form:    url.Values{"backchannelLogoutUri": {"http://app:3000/backchannel-logout"}},
			wantURI: "http://app:3000/backchannel-logout"},
		{name: "an emptied field, which clears the URI",
			form: url.Values{"backchannelLogoutUri": {""}}},
		{name: "the checkbox only in the query",
			form: url.Values{"backchannelLogoutUri": {"https://app.example.com/bcl"}}, query: "backchannelLogoutSessionRequired=on",
			wantURI: "https://app.example.com/bcl"},
		{name: "a value the checkbox never sends",
			form:    url.Values{"backchannelLogoutUri": {"https://app.example.com/bcl"}, "backchannelLogoutSessionRequired": {"true"}},
			wantURI: "https://app.example.com/bcl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &stubBackchannelLogoutAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app",
				AuthorizationCodeEnabled: true, BackchannelLogoutURI: "https://old.example.com/bcl", BackchannelLogoutSessionRequired: true}}
			httpHelper := &stubHttpHelper{}

			rec := postBackchannelLogout(t, apiClient, httpHelper, tc.form, tc.query, manageGrant)

			require.NoError(t, httpHelper.err)
			require.Equal(t, 1, apiClient.writes, "the save reaches the API once")
			assert.Equal(t, int64(7), apiClient.sentClientId)
			require.NotNil(t, apiClient.sent.BackchannelLogoutURI, "the URI is always sent, so the API never reads a missing one")
			require.NotNil(t, apiClient.sent.BackchannelLogoutSessionRequired, "and so is the flag")
			assert.Equal(t, tc.wantURI, *apiClient.sent.BackchannelLogoutURI)
			assert.Equal(t, tc.wantSessionRequired, *apiClient.sent.BackchannelLogoutSessionRequired)
			assert.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, consoleBaseURL+"/admin/clients/7/backchannel-logout", rec.Header().Get("Location"))
		})
	}
}

// A field read from the query is no submission of this form, the URI included.
func TestHandleBackchannelLogoutPost_ReadsTheURIFromTheBodyAlone(t *testing.T) {
	apiClient := &stubBackchannelLogoutAPI{client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true}}

	postBackchannelLogout(t, apiClient, &stubHttpHelper{}, url.Values{}, "backchannelLogoutUri=https://evil.example.com/", manageGrant)

	require.Equal(t, 1, apiClient.writes)
	assert.Empty(t, *apiClient.sent.BackchannelLogoutURI)
}

// Each refusal the auth server answers for this save is drawn on the tab, beside the inputs as
// typed, and marks the field it is about: a URI breaking decision 6's rules and a URI on a client
// with no sign-in flow (#784 decisions 6 and 9).
func TestHandleBackchannelLogoutPost_ARefusalMarksItsField(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   string
		status int
	}{
		{"an invalid URI", "handler.client_backchannel_logout.uri_invalid", http.StatusBadRequest},
		{"a scheme other than http or https", "handler.client_backchannel_logout.uri_scheme_invalid", http.StatusBadRequest},
		{"a user name in the URI", "handler.client_backchannel_logout.uri_userinfo", http.StatusBadRequest},
		{"http on a public client", "handler.client_backchannel_logout.uri_http_public_client", http.StatusBadRequest},
		{"a URI too long", "handler.client_backchannel_logout.uri_too_long", http.StatusBadRequest},
		{"no flow that signs users in", "handler.client_backchannel_logout.no_sign_in_flow", http.StatusBadRequest},
		{"http on a self-registered client", "handler.client_backchannel_logout.uri_http_self_registered", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const refusal = "The auth server's sentence."
			apiClient := &stubBackchannelLogoutAPI{
				client:    &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true, BackchannelLogoutURI: "https://stored.example.com/bcl"},
				updateErr: &apiclient.APIError{Code: tc.code, Message: refusal, StatusCode: tc.status},
			}
			httpHelper := &stubHttpHelper{}

			rec := postBackchannelLogout(t, apiClient, httpHelper, url.Values{
				"backchannelLogoutUri": {"ftp://typed.example.com/bcl"}, "backchannelLogoutSessionRequired": {"on"}}, "", manageGrant)

			require.NoError(t, httpHelper.err)
			require.NotNil(t, httpHelper.bind, "the tab is drawn again")
			assert.Empty(t, rec.Header().Get("Location"))
			assert.Equal(t, refusal, httpHelper.bind["error"])
			assert.Equal(t, "backchannelLogoutUri", httpHelper.bind["errorField"])
			drawn := reflect.ValueOf(httpHelper.bind["client"])
			assert.Equal(t, "ftp://typed.example.com/bcl", drawn.FieldByName("BackchannelLogoutURI").String(), "the input keeps what was typed")
			assert.True(t, drawn.FieldByName("BackchannelLogoutSessionRequired").Bool(), "and so does the checkbox")
			assert.True(t, drawn.FieldByName("CanManageBackchannelLogout").Bool(), "the form is drawn, not the note")
		})
	}
}

// Setting or changing the URI takes authserver:manage (#784 decision 15). The auth server refuses an
// administrator without it 403 MANAGE_SCOPE_REQUIRED, and the tab draws that refusal on the URI in
// the console's own sentence, in the page's language, rather than the API's English one about
// administrators, or the 500 page another 403 gets.
func TestHandleBackchannelLogoutPost_TheManageCeilingIsShownOnTheURI(t *testing.T) {
	apiClient := &stubBackchannelLogoutAPI{
		client: &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true},
		updateErr: &apiclient.APIError{Code: "MANAGE_SCOPE_REQUIRED", StatusCode: http.StatusForbidden,
			Message: "Only a token with the authserver:manage scope may act on administrators or administrative permissions."},
	}
	httpHelper := &stubHttpHelper{}

	rec := postBackchannelLogout(t, apiClient, httpHelper,
		url.Values{"backchannelLogoutUri": {"http://10.0.0.5/bcl"}}, "", "openid authserver:manage-clients")

	require.NoError(t, httpHelper.err, "a manage refusal is no server error")
	require.NotNil(t, httpHelper.bind, "the tab is drawn again")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Only an administrator holding authserver:manage can set or change the back-channel logout URI. "+
		"You can still clear it, or change whether the session identifier is required.", httpHelper.bind["error"])
	assert.Equal(t, "backchannelLogoutUri", httpHelper.bind["errorField"])
	assert.Equal(t, "http://10.0.0.5/bcl", reflect.ValueOf(httpHelper.bind["client"]).FieldByName("BackchannelLogoutURI").String())
}

// Any other 403 is not this ceiling, and is a server error as on every other tab.
func TestHandleBackchannelLogoutPost_AnotherForbiddenIsAServerError(t *testing.T) {
	apiClient := &stubBackchannelLogoutAPI{
		client:    &api.ClientResponse{Id: 7, ClientIdentifier: "a-web-app", AuthorizationCodeEnabled: true},
		updateErr: &apiclient.APIError{Code: "INSUFFICIENT_SCOPE", StatusCode: http.StatusForbidden, Message: "Insufficient scope."},
	}
	httpHelper := &stubHttpHelper{}

	rec := postBackchannelLogout(t, apiClient, httpHelper, url.Values{"backchannelLogoutUri": {"https://app.example.com/bcl"}}, "", manageGrant)

	require.Error(t, httpHelper.err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
