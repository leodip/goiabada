package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/oauth"
)

// accountSessionsApiClient answers the read this page performs and the delete its row buttons
// perform. Its other methods come from the embedded nil interface, so a call this page has no
// business making panics. Deletes are recorded rather than counted, so a case can say which
// session was deleted and a case expecting none can say so by asserting the slice is empty.
type accountSessionsApiClient struct {
	apiclient.ApiClient
	sessions    []api.UserSessionDetailResponse
	sessionsErr error

	deleted []int64
}

func (c *accountSessionsApiClient) GetAccountSessions(_ context.Context, accessToken string) ([]api.UserSessionDetailResponse, error) {
	return c.sessions, c.sessionsErr
}

func (c *accountSessionsApiClient) DeleteAccountSession(_ context.Context, accessToken string, sessionId int64) error {
	c.deleted = append(c.deleted, sessionId)
	return nil
}

// The Device cell's tooltip is the raw header, and this handler is the hop that has to put it on
// the view type. rendertest proves the template renders a UserAgent it is handed; it is handed a
// bind the test wrote, so deleting the copy here would leave that case green with every tooltip
// empty (#281 decision 6).
func TestHandleAccountSessionsGet_BindsTheRawUserAgent(t *testing.T) {
	const header = `Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0`

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_user_sessions.html").Maybe()

	apiClient := &accountSessionsApiClient{
		sessions: []api.UserSessionDetailResponse{
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

// The page formats the two timestamps itself now, which it can only do if the handler hands it the
// instants. rendertest renders a bind the test wrote, so without this case a handler that dropped
// the copy would leave both cells empty on a live page with every render case still green (#373).
func TestHandleAccountSessionsGet_BindsTheSessionInstants(t *testing.T) {
	started := time.Date(2026, 9, 14, 21, 3, 0, 0, time.UTC)
	lastAccessed := time.Date(2026, 9, 17, 8, 45, 0, 0, time.UTC)

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_user_sessions.html").Maybe()

	apiClient := &accountSessionsApiClient{
		sessions: []api.UserSessionDetailResponse{
			{Id: 1, Started: &started, LastAccessed: &lastAccessed},
		},
	}

	req := handlertest.Request(http.MethodGet, "/account/sessions", handlertest.WithAccessToken())

	HandleAccountSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 1)
	require.NotNil(t, sessions[0].Started)
	require.NotNil(t, sessions[0].LastAccessed)
	assert.Equal(t, started, *sessions[0].Started)
	assert.Equal(t, lastAccessed, *sessions[0].LastAccessed)
}

// This page always believed the field; the other two do now. Written here as well so the trio is
// symmetric: the copy is made by hand in three files, and a case in two of them cannot see the
// third going wrong (#373 decision 1).
func TestHandleAccountSessionsGet_BindsIsCurrentFromTheResponse(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_user_sessions.html").Maybe()

	apiClient := &accountSessionsApiClient{
		sessions: []api.UserSessionDetailResponse{
			{UserSessionResponse: api.UserSessionResponse{Id: 1, SessionIdentifier: "sid-one"}},
			{UserSessionResponse: api.UserSessionResponse{Id: 2, SessionIdentifier: "sid-two"}, IsCurrent: true},
		},
	}

	req := handlertest.Request(http.MethodGet, "/account/sessions", handlertest.WithAccessToken())

	HandleAccountSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 2)

	assert.Equal(t, int64(2), sessions[0].UserSessionId)
	assert.True(t, sessions[0].IsCurrent)
	assert.False(t, sessions[1].IsCurrent)
}

// Deleting a session from one of the three session pages has two outcomes, and the handler picks
// between them by deciding whether the row being deleted is the caller's own: another session is
// deleted through the API and the row goes, while the caller's own session cannot simply be
// deleted behind their back -- the browser is sent through the logout flow, which is the only
// path that ends a session at the auth server and clears the console's cookie together.
//
// Each of the three handlers used to decide it by lifting the sid claim off the console's own
// access token and comparing it against every row's sessionIdentifier. The auth server publishes
// isCurrent on every row now, computed from the sid of the very token the console forwards, so
// there is one place left that decides it and these cases pin that this handler believes the
// field. Two rows do that on their own: a row whose identifier matches the console's claim is not
// current unless the field says so, and a row the field marks current is current even when the
// claim names another. A handler that went back to reading the claim answers both backwards
// (#373).
func TestHandleAccountSessionsEndSesssionPost_TheAnswerFollowsIsCurrentOnTheRow(t *testing.T) {
	const deleting = 5

	testCases := []struct {
		name string
		// sid, when set, is the claim on the console's own parsed access token. Without it the
		// request carries the bearer alone and no parsed token at all, which is what
		// WithAccessToken builds and what a handler reading the claim would find nothing in.
		sid         string
		sessions    []api.UserSessionDetailResponse
		wantCurrent bool
	}{
		{
			name: "the row being deleted is the caller's own",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting}, IsCurrent: true},
				{UserSessionResponse: api.UserSessionResponse{Id: 6}},
			},
			wantCurrent: true,
		},
		{
			name: "another row is the caller's own",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting}},
				{UserSessionResponse: api.UserSessionResponse{Id: 6}, IsCurrent: true},
			},
		},
		{
			name: "no row is the caller's own, which is what a token carrying no sid produces",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting}},
				{UserSessionResponse: api.UserSessionResponse{Id: 6}},
			},
		},
		{
			name: "the row's identifier matches the console's own claim and the field says no",
			sid:  "sid-one",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting, SessionIdentifier: "sid-one"}},
			},
		},
		{
			name: "the field says yes and the console's own claim names another session",
			sid:  "sid-elsewhere",
			sessions: []api.UserSessionDetailResponse{
				{UserSessionResponse: api.UserSessionResponse{Id: deleting, SessionIdentifier: "sid-one"},
					IsCurrent: true},
			},
			wantCurrent: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			handlertest.ExpectEncodeJson(httpHelper).Once()

			apiClient := &accountSessionsApiClient{sessions: testCase.sessions}

			opts := []handlertest.Option{
				handlertest.WithBody(strings.NewReader(`{"userSessionId": 5}`)),
			}
			if testCase.sid == "" {
				opts = append(opts, handlertest.WithAccessToken())
			} else {
				opts = append(opts, handlertest.WithJwtInfo(oauth.JwtInfo{
					TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken},
					AccessToken:   &oauth.JwtToken{Claims: jwt.MapClaims{"sid": testCase.sid}},
				}))
			}

			req := handlertest.Request(http.MethodPost, "/account/sessions", opts...)

			HandleAccountSessionsEndSesssionPost(httpHelper, apiClient).
				ServeHTTP(httptest.NewRecorder(), req)

			answer := handlertest.Encoded(t, httpHelper)
			assert.Equal(t, true, answer["Success"])

			if testCase.wantCurrent {
				assert.Equal(t, true, answer["IsCurrentSession"],
					"the browser has to be sent through the logout flow")
				assert.Empty(t, apiClient.deleted,
					"the logout flow ends the session; deleting it here would end it twice")
				return
			}
			assert.NotContains(t, answer, "IsCurrentSession",
				"a row that is not the caller's own is deleted in place")
			assert.Equal(t, []int64{deleting}, apiClient.deleted)
		})
	}
}

// The list read is what the answer above turns on, so a list this handler cannot read is answered
// rather than swallowed. Deleting without it would destroy the caller's own session while telling
// the browser it had deleted somebody else's: no logout, and a console holding a session the auth
// server has already forgotten. It swallowed the failure until #373, because the read was made
// only to compare against a claim rather than to decide the answer.
func TestHandleAccountSessionsEndSesssionPost_AListTheApiCannotReadStopsTheDelete(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	var captured error
	httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured, _ = args.Get(2).(error)
		}).Return().Once()

	apiClient := &accountSessionsApiClient{
		sessionsErr: &apiclient.APIError{
			Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire",
			StatusCode: http.StatusInternalServerError,
		},
	}

	req := handlertest.Request(http.MethodPost, "/account/sessions",
		handlertest.WithAccessToken(),
		handlertest.WithBody(strings.NewReader(`{"userSessionId": 5}`)),
	)

	HandleAccountSessionsEndSesssionPost(httpHelper, apiClient).
		ServeHTTP(httptest.NewRecorder(), req)

	httpHelper.AssertExpectations(t)
	require.NotNil(t, captured, "the handler answered nothing")
	assert.Empty(t, apiClient.deleted, "nothing may be deleted on an answer the handler cannot make")
}
