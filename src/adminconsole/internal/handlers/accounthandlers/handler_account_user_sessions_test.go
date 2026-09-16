package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

// accountSessionsApiClient answers the one read this page performs. Its other methods come from
// the embedded nil interface, so a fetch this page has no business making panics.
type accountSessionsApiClient struct {
	apiclient.ApiClient
	sessions []api.EnhancedUserSessionResponse
}

func (c *accountSessionsApiClient) GetAccountSessions(accessToken string) ([]api.EnhancedUserSessionResponse, error) {
	return c.sessions, nil
}

// The Device cell's tooltip is the raw header, and this handler is the hop that has to put it on
// the view type. rendertest proves the template renders a UserAgent it is handed; it is handed a
// bind the test wrote, so deleting the copy here would leave that case green with every tooltip
// empty (#281 decision 6).
func TestHandleAccountSessionsGet_BindsTheRawUserAgent(t *testing.T) {
	const header = `Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0`

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_user_sessions.html").Maybe()

	apiClient := &accountSessionsApiClient{
		sessions: []api.EnhancedUserSessionResponse{
			{Id: 1, DeviceName: "Chrome 120", DeviceType: "Desktop", DeviceOS: "Linux", UserAgent: header},
			// A legacy row: the labels the old parser left behind, and no header at all.
			{Id: 2, DeviceName: "Chrome 119.0.0.0", DeviceType: "Desktop", DeviceOS: "Linux x86_64"},
		},
	}

	req := handlertest.Request(http.MethodGet, "/account/sessions", handlertest.WithAccessToken())

	HandleAccountSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)

	sessions, ok := bind["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 2)

	// Sorted by id descending, so the legacy row comes first.
	assert.Equal(t, int64(2), sessions[0].UserSessionId)
	assert.Equal(t, "", sessions[0].UserAgent, "a legacy row has no header to show")

	assert.Equal(t, int64(1), sessions[1].UserSessionId)
	assert.Equal(t, header, sessions[1].UserAgent)
}
