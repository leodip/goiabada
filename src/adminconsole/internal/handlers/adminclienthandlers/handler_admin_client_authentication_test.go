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

	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// stubAuthenticationAPIClient answers the Authentication tab's reads: the client from GET
// /clients/{id}, which carries no secret, and the secret from GET /clients/{id}/secret, the one
// route that does (#402 decision 8).
type stubAuthenticationAPIClient struct {
	client *api.ClientResponse
	secret string
	// secretReadFor is every client id the secret was read for.
	secretReadFor []int64
	// updates is every authentication write the handler asked for.
	updates []*api.UpdateClientAuthenticationRequest
}

func (s *stubAuthenticationAPIClient) GetClientByID(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.client, nil
}

func (s *stubAuthenticationAPIClient) GetClientSecret(_ context.Context, _ string, clientID int64) (string, error) {
	s.secretReadFor = append(s.secretReadFor, clientID)
	return s.secret, nil
}

func (s *stubAuthenticationAPIClient) UpdateClientAuthentication(_ context.Context, _ string, _ int64,
	request *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error) {
	s.updates = append(s.updates, request)
	return nil, nil
}

func authenticationTabBind(t *testing.T, apiClient *stubAuthenticationAPIClient) reflect.Value {
	t.Helper()
	httpHelper := &stubHTTPHelper{}
	req := handlertest.Request(http.MethodGet, "/admin/clients/7/authentication",
		handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"))

	HandleAuthenticationGet(httpHelper, newTestSessionStore(), apiClient).ServeHTTP(httptest.NewRecorder(), req)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
	return reflect.ValueOf(httpHelper.bind["client"])
}

// A confidential client's secret is shown from the secret route, the client detail having none.
func TestHandleAuthenticationGet_ShowsTheSecretReadFromTheSecretRoute(t *testing.T) {
	apiClient := &stubAuthenticationAPIClient{
		client: &api.ClientResponse{ID: 7, ClientIdentifier: "portal", IsPublic: false},
		secret: "the-secret-from-its-route",
	}

	bound := authenticationTabBind(t, apiClient)

	assert.Equal(t, "the-secret-from-its-route", bound.FieldByName("ClientSecret").String())
	assert.Equal(t, []int64{7}, apiClient.secretReadFor, "the secret is read once, for this client")
}

// A public client has no secret, so none is read and none is recorded as viewed.
func TestHandleAuthenticationGet_APublicClientReadsNoSecret(t *testing.T) {
	apiClient := &stubAuthenticationAPIClient{
		client: &api.ClientResponse{ID: 7, ClientIdentifier: "spa", IsPublic: true},
		secret: "never-read",
	}

	bound := authenticationTabBind(t, apiClient)

	assert.Empty(t, bound.FieldByName("ClientSecret").String())
	assert.Empty(t, apiClient.secretReadFor)
}

// The tab is drawn with the method the auth server holds the client to, each of the two, and with
// none for a client not held to one (#708 decision 5).
func TestHandleAuthenticationGet_DrawsTheMethodTheClientIsHeldTo(t *testing.T) {
	for _, held := range []string{"client_secret_basic", "client_secret_post", ""} {
		t.Run("held to "+held, func(t *testing.T) {
			apiClient := &stubAuthenticationAPIClient{
				client: &api.ClientResponse{ID: 7, ClientIdentifier: "dcr_a3f9", CreatedViaDCR: true,
					TokenEndpointAuthMethod: held},
				secret: "the-secret",
			}

			bound := authenticationTabBind(t, apiClient)

			assert.Equal(t, held, bound.FieldByName("TokenEndpointAuthMethod").String())
		})
	}
}

// A hand-made save with no valid client type is answered with the tab again and a page-level
// refusal, rather than the 500 page (#632 decision 6). The tab is drawn as stored, the secret typed
// beside the bad type included, since there is no type to draw a submission under; no field is
// marked, and nothing is saved.
func TestHandleAuthenticationPost_RefusesAClientTypeThatIsNeither(t *testing.T) {
	for _, form := range []url.Values{
		{"clientSecret": {"a-secret-typed-by-hand"}},
		{"publicConfidential": {""}, "clientSecret": {"a-secret-typed-by-hand"}},
		{"publicConfidential": {"PUBLIC"}, "clientSecret": {"a-secret-typed-by-hand"}},
		{"publicConfidential": {"both"}, "clientSecret": {"a-secret-typed-by-hand"}},
	} {
		t.Run("publicConfidential="+form.Get("publicConfidential"), func(t *testing.T) {
			apiClient := &stubAuthenticationAPIClient{
				client: &api.ClientResponse{ID: 7, ClientIdentifier: "portal", IsPublic: false},
				secret: "the-stored-secret",
			}
			httpHelper := &stubHTTPHelper{}
			req := handlertest.Request(http.MethodPost, "/admin/clients/7/authentication",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"),
				handlertest.WithForm(form))
			recorder := httptest.NewRecorder()

			HandleAuthenticationPost(httpHelper, newTestSessionStore(), apiClient, consoleBaseURL).
				ServeHTTP(recorder, req)

			require.NoError(t, httpHelper.err)
			require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.Equal(t, "Choose the client type: public or confidential.", httpHelper.bind["error"])
			assert.Empty(t, httpHelper.bind["errorField"], "the refusal is about the request, not a field")

			stored := ClientAuthentication{
				ClientID:         7,
				ClientIdentifier: "portal",
				IsPublic:         false,
				ClientSecret:     "the-stored-secret",
			}
			assert.Equal(t, stored, httpHelper.bind["client"], "the inputs show the client as stored")
			assert.Equal(t, stored, httpHelper.bind["storedClient"])
			assert.Empty(t, apiClient.updates, "nothing is saved")
		})
	}
}

// A refused save draws the tab again with the method the stored client is held to, which the tab
// names from the client as stored (#708 decision 5).
func TestHandleAuthenticationPost_ARefusedSaveStillDrawsTheMethodTheClientIsHeldTo(t *testing.T) {
	apiClient := &stubAuthenticationAPIClient{
		client: &api.ClientResponse{ID: 7, ClientIdentifier: "dcr_a3f9", CreatedViaDCR: true,
			TokenEndpointAuthMethod: "client_secret_post"},
		secret: "the-stored-secret",
	}
	httpHelper := &stubHTTPHelper{}
	req := handlertest.Request(http.MethodPost, "/admin/clients/7/authentication",
		handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"),
		handlertest.WithForm(url.Values{"publicConfidential": {"neither"}}))

	HandleAuthenticationPost(httpHelper, newTestSessionStore(), apiClient, consoleBaseURL).
		ServeHTTP(httptest.NewRecorder(), req)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
	stored := reflect.ValueOf(httpHelper.bind["storedClient"])
	assert.Equal(t, "client_secret_post", stored.FieldByName("TokenEndpointAuthMethod").String())
}

// A public client holds no secret, so its refused tab reads none, as its first draw reads none.
func TestHandleAuthenticationPost_ARefusedPublicClientReadsNoSecret(t *testing.T) {
	apiClient := &stubAuthenticationAPIClient{
		client: &api.ClientResponse{ID: 7, ClientIdentifier: "spa", IsPublic: true},
		secret: "never-read",
	}
	httpHelper := &stubHTTPHelper{}
	req := handlertest.Request(http.MethodPost, "/admin/clients/7/authentication",
		handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"),
		handlertest.WithForm(url.Values{"publicConfidential": {"neither"}}))

	HandleAuthenticationPost(httpHelper, newTestSessionStore(), apiClient, consoleBaseURL).
		ServeHTTP(httptest.NewRecorder(), req)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
	assert.Equal(t, ClientAuthentication{ClientID: 7, ClientIdentifier: "spa", IsPublic: true}, httpHelper.bind["client"])
	assert.Empty(t, apiClient.secretReadFor)
	assert.Empty(t, apiClient.updates)
}
