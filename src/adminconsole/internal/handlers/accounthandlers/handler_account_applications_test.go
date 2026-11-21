package accounthandlers

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

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// accountApplicationsAPIClient answers the list the Applications page reads and records each
// disconnect its row buttons ask for, which is the whole of accountApplicationsAPI.
type accountApplicationsAPIClient struct {
	clients []api.ConnectedClientResponse

	disconnected []int64
}

func (c *accountApplicationsAPIClient) GetAccountConnectedClients(_ context.Context, _ string) ([]api.ConnectedClientResponse, error) {
	return c.clients, nil
}

func (c *accountApplicationsAPIClient) DisconnectAccountClient(_ context.Context, _ string, clientID int64) error {
	c.disconnected = append(c.disconnected, clientID)
	return nil
}

// The page lists every connected client the API answers, a consent beside the grants where there
// is one and none where there is not, and the current application marked. renderintegration renders
// a bind the test wrote, so this is the case that holds the handler to handing the page what the
// API said (#135 decisions 4, 5 and 7).
func TestHandleApplicationsGet_BindsEveryConnectedClient(t *testing.T) {
	grantedAt := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	httpHelper := handlersmocks.NewHTTPHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_applications.html").Once()

	apiClient := &accountApplicationsAPIClient{clients: []api.ConnectedClientResponse{
		{ClientID: 4, ClientIdentifier: "portal", ClientName: "Customer portal",
			Consent:    &api.ConnectedClientConsentResponse{ID: 11, Scope: "openid email", GrantedAt: &grantedAt},
			GrantScope: "openid"},
		{ClientID: 9, ClientIdentifier: "payroll", ClientName: "Payroll", GrantScope: "openid profile"},
		{ClientID: 1, ClientIdentifier: "admin-console-client", ClientName: "Admin console", GrantScope: "openid",
			IsCurrent: true},
	}}

	req := handlertest.Request(http.MethodGet, "/account/applications", handlertest.WithAccessToken())
	HandleApplicationsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	clients, ok := handlertest.Bind(t, httpHelper)["clients"].([]render.ConnectedClientInfo)
	require.True(t, ok, "the bind carries no []ConnectedClientInfo")
	assert.Equal(t, []render.ConnectedClientInfo{
		{ClientID: 4, Client: "portal", ClientName: "Customer portal", HasConsent: true, ConsentScope: "openid email",
			GrantedAt: &grantedAt, GrantScope: "openid"},
		{ClientID: 9, Client: "payroll", ClientName: "Payroll", GrantScope: "openid profile"},
		{ClientID: 1, Client: "admin-console-client", ClientName: "Admin console", GrantScope: "openid", IsCurrent: true},
	}, clients)
}

func disconnectApplication(t *testing.T, apiClient *accountApplicationsAPIClient, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := handlertest.Request(http.MethodPost, "/account/applications",
		handlertest.WithAccessToken(), handlertest.WithBody(strings.NewReader(body)),
		handlertest.WithContentType("application/json"))
	recorder := httptest.NewRecorder()

	// The real writer, because what is under test is the answer on the wire.
	HandleApplicationsDisconnectPost(render.New(fstest.MapFS{}, nil), apiClient).ServeHTTP(recorder, req)
	return recorder
}

// A row's Disconnect posts the client's numeric id, and the handler disconnects that client and
// answers the success row-actions.js reads.
func TestHandleApplicationsDisconnectPost_DisconnectsTheClientTheRowNames(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	apiClient := &accountApplicationsAPIClient{}

	recorder := disconnectApplication(t, apiClient, `{"clientId":9}`)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.JSONEq(t, `{"Success":true}`, recorder.Body.String())
	assert.Equal(t, []int64{9}, apiClient.disconnected)
	assert.Empty(t, logs.Records())
}

// An id beyond float64's exact integers reaches the auth server unchanged: a float decode would
// round it to a neighbouring id, which can name another client.
func TestHandleApplicationsDisconnectPost_ALargeIDReachesTheAuthServerExactly(t *testing.T) {
	apiClient := &accountApplicationsAPIClient{}

	recorder := disconnectApplication(t, apiClient, `{"clientId":9007199254740993}`)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, []int64{9007199254740993}, apiClient.disconnected)
}

// A body naming no client is refused before anything is asked of the auth server: a missing id,
// a zero, a negative id, a fraction (which a float decode would truncate to another client's id),
// a string and a body that is not JSON.
func TestHandleApplicationsDisconnectPost_ABodyNamingNoClientIsRefused(t *testing.T) {
	for _, body := range []string{`{}`, `{"clientId":0}`, `{"clientId":-9}`, `{"clientId":9.5}`, `{"clientId":"9"}`, `{"consentId":9}`, `not json`} {
		t.Run(body, func(t *testing.T) {
			apiClient := &accountApplicationsAPIClient{}

			recorder := disconnectApplication(t, apiClient, body)

			assert.Equal(t, http.StatusBadRequest, recorder.Code)
			var answer map[string]string
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &answer))
			assert.Equal(t, "invalid_request_body", answer["error"])
			assert.Empty(t, apiClient.disconnected, "nothing is disconnected")
		})
	}
}
