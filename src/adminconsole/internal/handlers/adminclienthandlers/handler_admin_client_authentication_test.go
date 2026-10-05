package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// stubAuthenticationApiClient answers the Authentication tab's reads: the client from GET
// /clients/{id}, which carries no secret, and the secret from GET /clients/{id}/secret, the one
// route that does (#402 decision 8).
type stubAuthenticationApiClient struct {
	client *api.ClientResponse
	secret string
	// secretReadFor is every client id the secret was read for.
	secretReadFor []int64
}

func (s *stubAuthenticationApiClient) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.client, nil
}

func (s *stubAuthenticationApiClient) GetClientSecret(_ context.Context, _ string, clientId int64) (string, error) {
	s.secretReadFor = append(s.secretReadFor, clientId)
	return s.secret, nil
}

func (s *stubAuthenticationApiClient) UpdateClientAuthentication(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error) {
	return nil, nil
}

func authenticationTabBind(t *testing.T, apiClient *stubAuthenticationApiClient) reflect.Value {
	t.Helper()
	httpHelper := &stubHttpHelper{}
	req := handlertest.Request(http.MethodGet, "/admin/clients/7/authentication",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"))

	HandleAuthenticationGet(httpHelper, newTestSessionStore(), apiClient).ServeHTTP(httptest.NewRecorder(), req)

	require.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the handler rendered nothing")
	return reflect.ValueOf(httpHelper.bind["client"])
}

// A confidential client's secret is shown from the secret route, the client detail having none.
func TestHandleAuthenticationGet_ShowsTheSecretReadFromTheSecretRoute(t *testing.T) {
	apiClient := &stubAuthenticationApiClient{
		client: &api.ClientResponse{Id: 7, ClientIdentifier: "portal", IsPublic: false},
		secret: "the-secret-from-its-route",
	}

	bound := authenticationTabBind(t, apiClient)

	assert.Equal(t, "the-secret-from-its-route", bound.FieldByName("ClientSecret").String())
	assert.Equal(t, []int64{7}, apiClient.secretReadFor, "the secret is read once, for this client")
}

// A public client has no secret, so none is read and none is recorded as viewed.
func TestHandleAuthenticationGet_APublicClientReadsNoSecret(t *testing.T) {
	apiClient := &stubAuthenticationApiClient{
		client: &api.ClientResponse{Id: 7, ClientIdentifier: "spa", IsPublic: true},
		secret: "never-read",
	}

	bound := authenticationTabBind(t, apiClient)

	assert.Empty(t, bound.FieldByName("ClientSecret").String())
	assert.Empty(t, apiClient.secretReadFor)
}
