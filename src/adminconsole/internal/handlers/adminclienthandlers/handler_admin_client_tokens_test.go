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

// stubClientTokensApiClient implements the Tokens tab's port: the client the tab is drawn from, the
// global token settings, the token settings' write and the DPoP requirement's, each write recording
// what it was sent.
type stubClientTokensApiClient struct {
	client *api.ClientResponse
	// updated is what the token settings' write answers, the client as it then stands.
	updated *api.ClientResponse
	// tokensErr and dpopErr are what the token settings' write and the requirement's answer.
	tokensErr error
	dpopErr   error

	tokensWrites int
	dpopWrites   int
	sentDPoP     *api.UpdateClientDPoPRequest
	sentDPoPTo   int64
	sentDPoPAs   string
}

func (s *stubClientTokensApiClient) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.client, nil
}

func (s *stubClientTokensApiClient) GetSettingsTokens(_ context.Context, _ string) (*api.SettingsTokensResponse, error) {
	return &api.SettingsTokensResponse{TokenExpirationInSeconds: 300}, nil
}

func (s *stubClientTokensApiClient) UpdateClientTokens(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	s.tokensWrites++
	if s.tokensErr != nil {
		return nil, s.tokensErr
	}
	if s.updated != nil {
		return s.updated, nil
	}
	return s.client, nil
}

func (s *stubClientTokensApiClient) UpdateClientDPoP(_ context.Context, accessToken string, clientId int64,
	request *api.UpdateClientDPoPRequest) (*api.ClientResponse, error) {
	s.dpopWrites++
	s.sentDPoP = request
	s.sentDPoPTo = clientId
	s.sentDPoPAs = accessToken
	if s.dpopErr != nil {
		return nil, s.dpopErr
	}
	return s.client, nil
}

// validTokensForm is a Tokens tab submission whose durations and choices the console accepts, with
// extra merged over it.
func validTokensForm(extra url.Values) url.Values {
	form := url.Values{
		"tokenExpirationInSeconds":                {"300"},
		"refreshTokenOfflineIdleTimeoutInSeconds": {"3600"},
		"refreshTokenOfflineMaxLifetimeInSeconds": {"86400"},
		"includeOpenIDConnectClaimsInAccessToken": {"default"},
		"includeOpenIDConnectClaimsInIdToken":     {"default"},
	}
	for k, v := range extra {
		form[k] = v
	}
	return form
}

// postTokens posts the Tokens tab for client 7 with form, and with query on the URL when given.
func postTokens(t *testing.T, apiClient clientTokensAPI, httpHelper *stubHttpHelper, form url.Values, query string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/admin/clients/7/tokens"
	if query != "" {
		target += "?" + query
	}
	req := handlertest.Request(http.MethodPost, target, handlertest.WithAccessToken(),
		handlertest.WithPathValue("clientId", "7"), handlertest.WithForm(form))
	rec := httptest.NewRecorder()
	HandleTokensPost(httpHelper, newTestSessionStore(), apiClient, consoleBaseURL).ServeHTTP(rec, req)
	return rec
}

// The tab draws "Require DPoP for token requests" from the client as the auth server answers it,
// with whether the client is the system-level one, which the page offers no switch for (#42
// decision 12).
func TestHandleTokensGet_BindsTheDPoPRequirement(t *testing.T) {
	testCases := []struct {
		name       string
		client     *api.ClientResponse
		wantDPoP   bool
		wantSystem bool
	}{
		{"a client requiring DPoP", &api.ClientResponse{Id: 7, ClientIdentifier: "spa", DPoPBoundAccessTokens: true}, true, false},
		{"a client that does not", &api.ClientResponse{Id: 7, ClientIdentifier: "portal"}, false, false},
		{"the admin console's client", &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client", IsSystemLevelClient: true}, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := &stubHttpHelper{}
			req := handlertest.Request(http.MethodGet, "/admin/clients/7/tokens",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"))

			HandleTokensGet(httpHelper, newTestSessionStore(), &stubClientTokensApiClient{client: tc.client}).
				ServeHTTP(httptest.NewRecorder(), req)

			require.NoError(t, httpHelper.err)
			require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
			assert.Equal(t, tc.wantDPoP, reflect.ValueOf(httpHelper.bind["settings"]).FieldByName("DPoPBoundAccessTokens").Bool())
			assert.Equal(t, tc.wantSystem, httpHelper.bind["client"].(*api.ClientResponse).IsSystemLevelClient)
		})
	}
}

// One Save stores the whole tab: the token settings, then the DPoP requirement through its own
// route, PUT /clients/{id}/dpop, and the requirement only when the switch differs from the stored
// one (#42 decision 12). Only the checkbox's own value switches it on.
func TestHandleTokensPost_WritesTheDPoPRequirementOnlyWhenItChanged(t *testing.T) {
	testCases := []struct {
		name      string
		stored    bool
		form      url.Values
		wantWrite bool
		wantOn    bool
	}{
		{"switched on", false, url.Values{"dpopBoundAccessTokens": {"on"}}, true, true},
		{"switched off, which a browser submits as nothing", true, url.Values{}, true, false},
		{"left off", false, url.Values{}, false, false},
		{"left on", true, url.Values{"dpopBoundAccessTokens": {"on"}}, false, false},
		{"a value the checkbox never sends, over a client requiring DPoP", true, url.Values{"dpopBoundAccessTokens": {"true"}}, true, false},
		{"a value the checkbox never sends, over a client that does not", false, url.Values{"dpopBoundAccessTokens": {"true"}}, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &stubClientTokensApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "spa",
				DPoPBoundAccessTokens: tc.stored}}
			httpHelper := &stubHttpHelper{}

			rec := postTokens(t, apiClient, httpHelper, validTokensForm(tc.form), "")

			require.NoError(t, httpHelper.err)
			assert.Equal(t, 1, apiClient.tokensWrites, "the token settings are written by every save")
			if !tc.wantWrite {
				assert.Zero(t, apiClient.dpopWrites, "an unchanged requirement is not written")
			} else {
				require.Equal(t, 1, apiClient.dpopWrites, "a changed requirement is written once")
				require.NotNil(t, apiClient.sentDPoP.DPoPBoundAccessTokens, "the value is always sent, never left for the server to refuse")
				assert.Equal(t, tc.wantOn, *apiClient.sentDPoP.DPoPBoundAccessTokens)
				assert.Equal(t, int64(7), apiClient.sentDPoPTo)
				assert.Equal(t, handlertest.AccessToken, apiClient.sentDPoPAs)
			}
			assert.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, consoleBaseURL+"/admin/clients/7/tokens", rec.Header().Get("Location"))
		})
	}
}

// The admin console's own client is not offered the requirement (#42 decision 12): the tab draws no
// switch for it, and a save never writes it, whatever the body says.
func TestHandleTokensPost_NeverWritesTheSystemLevelClientsRequirement(t *testing.T) {
	for _, form := range []url.Values{{}, {"dpopBoundAccessTokens": {"on"}}} {
		apiClient := &stubClientTokensApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "admin-console-client",
			IsSystemLevelClient: true}}

		rec := postTokens(t, apiClient, &stubHttpHelper{}, validTokensForm(form), "")

		assert.Equal(t, 1, apiClient.tokensWrites)
		assert.Zero(t, apiClient.dpopWrites, "form %v", form)
		assert.Equal(t, http.StatusFound, rec.Code)
	}
}

// The switch is read from the request body alone. A switch in the URL is no submission of the form,
// so it switches nothing on.
func TestHandleTokensPost_IgnoresTheDPoPSwitchInTheQuery(t *testing.T) {
	apiClient := &stubClientTokensApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "spa"}}

	postTokens(t, apiClient, &stubHttpHelper{}, validTokensForm(nil), "dpopBoundAccessTokens=on")

	assert.Zero(t, apiClient.dpopWrites, "the stored requirement is off and the body says off")
}

// A refused requirement comes after the token settings were written, so the tab is drawn again from
// the client as it now stands, saying the settings were saved, with the refusal beside the switch,
// and nothing is redirected.
func TestHandleTokensPost_ARefusedRequirementLeavesTheTokenSettingsSaved(t *testing.T) {
	const refusal = "The admin console's client can't require DPoP for token requests."
	apiClient := &stubClientTokensApiClient{
		client:  &api.ClientResponse{Id: 7, ClientIdentifier: "spa", TokenExpirationInSeconds: 300},
		updated: &api.ClientResponse{Id: 7, ClientIdentifier: "spa", TokenExpirationInSeconds: 600},
		dpopErr: &apiclient.APIError{Code: "handler.client_dpop.admin_console_not_allowed", Message: refusal,
			StatusCode: http.StatusBadRequest},
	}
	httpHelper := &stubHttpHelper{}

	rec := postTokens(t, apiClient, httpHelper, validTokensForm(url.Values{
		"tokenExpirationInSeconds": {"600"}, "dpopBoundAccessTokens": {"on"}}), "")

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the tokens page is rendered again")
	assert.Equal(t, refusal, httpHelper.bind["dpopError"])
	assert.Equal(t, true, httpHelper.bind["savedSuccessfully"], "the token settings were written before the refusal")
	assert.Nil(t, httpHelper.bind["error"], "the token settings' own error slot stays empty")
	assert.Empty(t, rec.Header().Get("Location"))
	assert.NotNil(t, httpHelper.bind["global"], "the global settings the choices name are drawn too")

	settings := reflect.ValueOf(httpHelper.bind["settings"])
	assert.Equal(t, "600", settings.FieldByName("TokenExpirationInSeconds").String(), "the client as it now stands")
	assert.False(t, settings.FieldByName("DPoPBoundAccessTokens").Bool(), "the stored requirement, not the refused one")
}

// A refused token settings save, by the console or by the auth server, writes no requirement, and
// draws the tab again with the switch as submitted, as every other input is.
func TestHandleTokensPost_ARefusedTokenSettingsSaveWritesNoRequirement(t *testing.T) {
	testCases := []struct {
		name       string
		form       url.Values
		tokensErr  error
		wantWrites int
	}{
		{"a duration the console refuses", url.Values{"tokenExpirationInSeconds": {"five"}}, nil, 0},
		{"a duration the auth server refuses", url.Values{"tokenExpirationInSeconds": {"-5"}},
			&apiclient.APIError{Code: "handler.client_tokens.token_expiration_out_of_range",
				Message: "Token lifetime must be between 0 and 160000000 seconds.", StatusCode: http.StatusBadRequest}, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &stubClientTokensApiClient{client: &api.ClientResponse{Id: 7, ClientIdentifier: "spa"},
				tokensErr: tc.tokensErr}
			httpHelper := &stubHttpHelper{}
			form := validTokensForm(tc.form)
			form.Set("dpopBoundAccessTokens", "on")

			postTokens(t, apiClient, httpHelper, form, "")

			require.NoError(t, httpHelper.err)
			assert.Equal(t, tc.wantWrites, apiClient.tokensWrites)
			assert.Zero(t, apiClient.dpopWrites)
			require.NotNil(t, httpHelper.bind)
			assert.NotEmpty(t, httpHelper.bind["error"])
			assert.True(t, reflect.ValueOf(httpHelper.bind["settings"]).FieldByName("DPoPBoundAccessTokens").Bool(),
				"the switch as submitted")
		})
	}
}
