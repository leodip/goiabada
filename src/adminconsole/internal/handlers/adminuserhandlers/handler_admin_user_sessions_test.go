package adminuserhandlers

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

// userSessionsApiClient answers the two reads this page performs and the delete its row buttons
// perform, and nothing else. Deletes are recorded rather than counted, so a case can say which
// session was deleted and a case expecting none can say so by asserting the slice is empty.
type userSessionsApiClient struct {
	apiclient.ApiClient
	user        *api.UserResponse
	sessions    []api.UserSessionDetailResponse
	sessionsErr error

	deleted []int64
}

func (c *userSessionsApiClient) GetUserById(_ context.Context, accessToken string, userId int64) (*api.UserResponse, error) {
	return c.user, nil
}

func (c *userSessionsApiClient) GetUserSessionsByUserId(_ context.Context, accessToken string,
	userId int64) ([]api.UserSessionDetailResponse, error) {
	return c.sessions, c.sessionsErr
}

func (c *userSessionsApiClient) DeleteUserSessionById(_ context.Context, accessToken string, sessionId int64) error {
	c.deleted = append(c.deleted, sessionId)
	return nil
}

// The admin-side twin of the account page's case: this handler also rebuilds SessionInfo by hand,
// so the copy has to be pinned here too. A guard added at one of three call sites and absent from
// its siblings is exactly the shape a change like this ships with (#281 decision 6).
func TestHandleAdminUserSessionsGet_BindsTheRawUserAgent(t *testing.T) {
	const header = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15`

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_sessions.html").Maybe()

	apiClient := &userSessionsApiClient{
		user: &api.UserResponse{Id: 7},
		sessions: []api.UserSessionDetailResponse{
			{Id: 1, DeviceName: "Safari 17", DeviceType: "Desktop", DeviceOS: "macOS", UserAgent: header},
		},
	}

	req := handlertest.Request(http.MethodGet, "/admin/users/7/sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
	)

	HandleAdminUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)

	sessions, ok := bind["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 1)
	assert.Equal(t, header, sessions[0].UserAgent)
}

// The admin-side twin of the account page's instants case, for the same reason the user-agent case
// is written three times: this is the second of three hand-built SessionInfo literals, and a copy
// dropped from one of them is invisible to every render case (#373).
func TestHandleAdminUserSessionsGet_BindsTheSessionInstants(t *testing.T) {
	started := time.Date(2026, 9, 14, 21, 3, 0, 0, time.UTC)
	lastAccessed := time.Date(2026, 9, 17, 8, 45, 0, 0, time.UTC)

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_sessions.html").Maybe()

	apiClient := &userSessionsApiClient{
		user: &api.UserResponse{Id: 7},
		sessions: []api.UserSessionDetailResponse{
			{Id: 1, Started: &started, LastAccessed: &lastAccessed},
		},
	}

	req := handlertest.Request(http.MethodGet, "/admin/users/7/sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
	)

	HandleAdminUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 1)
	require.NotNil(t, sessions[0].Started)
	require.NotNil(t, sessions[0].LastAccessed)
	assert.Equal(t, started, *sessions[0].Started)
	assert.Equal(t, lastAccessed, *sessions[0].LastAccessed)
}

// The two admin pages used to compute IsCurrent themselves, comparing each row's
// sessionIdentifier against the sid the console lifted off its own access token onto the request
// context. The auth server reads that same claim now, so the page must believe the response and
// nothing else: a page still recomputing would answer false here, because this request carries no
// session identifier on its context at all (#373 decision 1).
func TestHandleAdminUserSessionsGet_BindsIsCurrentFromTheResponse(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_sessions.html").Maybe()

	apiClient := &userSessionsApiClient{
		user: &api.UserResponse{Id: 7},
		sessions: []api.UserSessionDetailResponse{
			{UserSessionResponse: api.UserSessionResponse{Id: 1, SessionIdentifier: "sid-one"}},
			{UserSessionResponse: api.UserSessionResponse{Id: 2, SessionIdentifier: "sid-two"}, IsCurrent: true},
		},
	}

	req := handlertest.Request(http.MethodGet, "/admin/users/7/sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
	)

	HandleAdminUserSessionsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	sessions, ok := handlertest.Bind(t, httpHelper)["sessions"].([]SessionInfo)
	require.True(t, ok, "the bind carries no []SessionInfo")
	require.Len(t, sessions, 2)

	// Sorted by id descending, so the current one is first.
	assert.Equal(t, int64(2), sessions[0].UserSessionId)
	assert.True(t, sessions[0].IsCurrent)
	assert.False(t, sessions[1].IsCurrent)
}

// The admin-side twin of the account page's case, written here for the reason every case in this
// trio is written three times: the comparison is made by hand in three files, and a case in two of
// them cannot see the third going wrong. An administrator viewing their own user row can delete
// their own session from this page, which is the outcome the answer below turns on (#373).
func TestHandleAdminUserSessionsPost_TheAnswerFollowsIsCurrentOnTheRow(t *testing.T) {
	const deleting = 5

	testCases := []struct {
		name string
		// sid, when set, is the claim on the console's own parsed access token. Without it the
		// request carries the bearer alone and no parsed token at all.
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
			name: "no row is the caller's own, which is what a client credentials token produces",
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

			apiClient := &userSessionsApiClient{
				user:     &api.UserResponse{Id: 7},
				sessions: testCase.sessions,
			}

			opts := []handlertest.Option{
				handlertest.WithRouteParam("userId", "7"),
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

			req := handlertest.Request(http.MethodPost, "/admin/users/7/sessions", opts...)

			HandleAdminUserSessionsPost(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

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
// rather than swallowed. It swallowed the failure until #373, because the read was made only to
// compare against a claim rather than to decide the answer.
func TestHandleAdminUserSessionsPost_AListTheApiCannotReadStopsTheDelete(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	var captured error
	httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured, _ = args.Get(2).(error)
		}).Return().Once()

	apiClient := &userSessionsApiClient{
		user: &api.UserResponse{Id: 7},
		sessionsErr: &apiclient.APIError{
			Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire",
			StatusCode: http.StatusInternalServerError,
		},
	}

	req := handlertest.Request(http.MethodPost, "/admin/users/7/sessions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
		handlertest.WithBody(strings.NewReader(`{"userSessionId": 5}`)),
	)

	HandleAdminUserSessionsPost(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	httpHelper.AssertExpectations(t)
	require.NotNil(t, captured, "the handler answered nothing")
	assert.Empty(t, apiClient.deleted, "nothing may be deleted on an answer the handler cannot make")
}
