package adminuserhandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// connectedClientsAPIClient holds one user with the connected clients it is given, records each
// disconnect as its user id and client id, and answers each with disconnectErr: the whole of
// userConnectedClientsAPI.
type connectedClientsAPIClient struct {
	clients       []api.ConnectedClientResponse
	disconnectErr error

	disconnected [][2]int64
}

func (c *connectedClientsAPIClient) GetUserByID(_ context.Context, _ string, userID int64) (*api.UserResponse, error) {
	return &api.UserResponse{ID: userID, Email: "jdoe@example.com"}, nil
}

func (c *connectedClientsAPIClient) GetUserConnectedClients(_ context.Context, _ string, _ int64) ([]api.ConnectedClientResponse, error) {
	return c.clients, nil
}

func (c *connectedClientsAPIClient) DisconnectUserClient(_ context.Context, _ string, userID, clientID int64) error {
	c.disconnected = append(c.disconnected, [2]int64{userID, clientID})
	return c.disconnectErr
}

// The tab lists every connected client the Admin API answers for the user, a consent beside the
// grants where there is one and none where there is not, and the current client marked.
// renderintegration renders a bind the test wrote, so this is the case that holds the handler to
// handing the page what the API said (#135 decisions 4, 5 and 7).
func TestHandleConnectedClientsGet_BindsTheUserAndEveryConnectedClient(t *testing.T) {
	grantedAt := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	httpHelper := handlersmocks.NewHTTPHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_connected_clients.html").Once()

	apiClient := &connectedClientsAPIClient{clients: []api.ConnectedClientResponse{
		{ClientID: 4, ClientIdentifier: "portal", ClientName: "Customer portal", ClientDescription: "Orders",
			Consent:    &api.ConnectedClientConsentResponse{ID: 11, Scope: "openid email", GrantedAt: &grantedAt},
			GrantScope: "openid"},
		{ClientID: 9, ClientIdentifier: "payroll", ClientName: "Payroll", GrantScope: "openid profile"},
		{ClientID: 1, ClientIdentifier: "admin-console-client", ClientName: "Admin console", GrantScope: "openid",
			IsCurrent: true},
	}}

	req := handlertest.Request(http.MethodGet, "/admin/users/42/connected-clients?page=3&query=jd",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "42"))
	HandleConnectedClientsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)
	user, ok := bind["user"].(*api.UserResponse)
	require.True(t, ok, "the bind carries no *UserResponse")
	assert.Equal(t, int64(42), user.ID)
	assert.Equal(t, "3", bind["page"])
	assert.Equal(t, "jd", bind["query"])

	clients, ok := bind["clients"].([]render.ConnectedClientInfo)
	require.True(t, ok, "the bind carries no []ConnectedClientInfo")
	assert.Equal(t, []render.ConnectedClientInfo{
		{ClientID: 4, Client: "portal", ClientName: "Customer portal", ClientDescription: "Orders",
			HasConsent: true, ConsentScope: "openid email", GrantedAt: &grantedAt, GrantScope: "openid"},
		{ClientID: 9, Client: "payroll", ClientName: "Payroll", GrantScope: "openid profile"},
		{ClientID: 1, Client: "admin-console-client", ClientName: "Admin console", GrantScope: "openid", IsCurrent: true},
	}, clients)
}

func disconnectClient(t *testing.T, apiClient *connectedClientsAPIClient, userID, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := handlertest.Request(http.MethodPost, "/admin/users/"+userID+"/connected-clients",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
		handlertest.WithBody(strings.NewReader(body)),
		handlertest.WithContentType("application/json"))
	recorder := httptest.NewRecorder()

	// The real writer, because what is under test is the answer on the wire and the log it does
	// or does not leave, and both are the writer's.
	HandleConnectedClientsDisconnectPost(render.New(fstest.MapFS{}, nil), apiClient).ServeHTTP(recorder, req)
	return recorder
}

// A row's Disconnect posts the client's numeric id, and the handler disconnects that client from
// the user the page is about, and answers the success row-actions.js reads.
func TestHandleConnectedClientsDisconnectPost_DisconnectsTheRowsClientFromThePagesUser(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	apiClient := &connectedClientsAPIClient{}

	recorder := disconnectClient(t, apiClient, "42", `{"clientId":9}`)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.JSONEq(t, `{"Success":true}`, recorder.Body.String())
	assert.Equal(t, [][2]int64{{42, 9}}, apiClient.disconnected, "user 42 from client 9")
	assert.Empty(t, logs.Records())
}

// A disconnect the auth server answers 404 is a stale page: the user, or another administrator,
// ended what the client held after this page loaded, so there was nothing left to end (#135
// decision 2). It is answered as the 404 JSONNotFound gives every such id, with nothing logged,
// rather than a 500 with a stack (#440 decision 6).
func TestHandleConnectedClientsDisconnectPost_NothingLeftToEndIs404WithNothingLogged(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	apiClient := &connectedClientsAPIClient{disconnectErr: &apiclient.APIError{
		Code: "NOT_FOUND", Message: "Not found", StatusCode: http.StatusNotFound}}

	recorder := disconnectClient(t, apiClient, "42", `{"clientId":9}`)

	assert.Equal(t, http.StatusNotFound, recorder.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "not_found", body["error"])
	assert.Empty(t, logs.Records(), "a stale page is not a server fault")
}

// An id beyond float64's exact integers reaches the auth server unchanged: a float decode would
// round it to a neighbouring id, which can name another client.
func TestHandleConnectedClientsDisconnectPost_ALargeIDReachesTheAuthServerExactly(t *testing.T) {
	apiClient := &connectedClientsAPIClient{}

	recorder := disconnectClient(t, apiClient, "42", `{"clientId":9007199254740993}`)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, [][2]int64{{42, 9007199254740993}}, apiClient.disconnected)
}

// A body naming no client is refused before anything is asked of the auth server: a missing id, a
// zero, a negative id, a fraction (which a float decode would truncate to another client's id), a
// string, the consent id the old tab posted, and a body that is not JSON.
func TestHandleConnectedClientsDisconnectPost_ABodyNamingNoClientIsRefused(t *testing.T) {
	for _, body := range []string{`{}`, `{"clientId":0}`, `{"clientId":-9}`, `{"clientId":9.5}`, `{"clientId":"9"}`, `{"consentId":9}`, `not json`} {
		t.Run(body, func(t *testing.T) {
			apiClient := &connectedClientsAPIClient{}

			recorder := disconnectClient(t, apiClient, "42", body)

			assert.Equal(t, http.StatusBadRequest, recorder.Code)
			var answer map[string]string
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &answer))
			assert.Equal(t, "invalid_request_body", answer["error"])
			assert.Empty(t, apiClient.disconnected, "nothing is disconnected")
		})
	}
}

// A user id that does not parse names no user, so nothing is disconnected and the answer is 404.
func TestHandleConnectedClientsDisconnectPost_AnUnparsableUserIDIsNotFound(t *testing.T) {
	apiClient := &connectedClientsAPIClient{}

	recorder := disconnectClient(t, apiClient, "abc", `{"clientId":9}`)

	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.Empty(t, apiClient.disconnected, "nothing is disconnected")
}
