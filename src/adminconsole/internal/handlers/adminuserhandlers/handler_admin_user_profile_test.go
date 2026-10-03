package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// userProfileRecorder answers the user read with a fresh copy of the stored user on every call, so
// an echo written onto one call's answer cannot leak into the next, and records every update the
// handler forwards and every user it reads.
type userProfileRecorder struct {
	updateErr error
	updates   []*api.UpdateUserProfileRequest
	updateIds []int64
	reads     []int64
	tokens    []string
}

func storedUserProfile(userId int64) *api.UserResponse {
	birthDate := time.Date(1970, time.January, 2, 0, 0, 0, 0, time.UTC)
	return &api.UserResponse{
		Id:                  userId,
		Email:               "stored@example.com",
		Username:            "stored-username",
		GivenName:           "Stored",
		MiddleName:          "S",
		FamilyName:          "Profile",
		Nickname:            "stored",
		Website:             "https://stored.example",
		Gender:              "female",
		BirthDate:           &birthDate,
		ZoneInfoCountryName: "Portugal",
		ZoneInfo:            "Europe/Lisbon",
		Locale:              "en-US",
	}
}

func (c *userProfileRecorder) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	c.reads = append(c.reads, userId)
	return storedUserProfile(userId), nil
}

func (c *userProfileRecorder) UpdateUserProfile(_ context.Context, accessToken string, userId int64,
	request *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	c.tokens = append(c.tokens, accessToken)
	c.updateIds = append(c.updateIds, userId)
	c.updates = append(c.updates, request)
	if c.updateErr != nil {
		return nil, c.updateErr
	}
	return storedUserProfile(userId), nil
}

// A refusal from the API redraws the admin user profile page with what the administrator typed
// rather than what is stored, the API's sentence, and the list position the page was opened from
// (#440 decision 7).
func TestHandleAdminUserProfilePost_ARefusalRedrawsThePageWithTheSubmittedValues(t *testing.T) {
	httpHelper := mocks_handlers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_profile.html").Once()

	apiClient := &userProfileRecorder{updateErr: &apiclient.APIError{
		Code: "INVALID_WEBSITE", Message: "The website is not valid.", StatusCode: http.StatusBadRequest,
	}}
	form := url.Values{
		"username":    {" jane-doe "},
		"givenName":   {"Jane"},
		"middleName":  {"Q"},
		"familyName":  {"Doe"},
		"nickname":    {"JD"},
		"website":     {"https://jane.example"},
		"gender":      {"2"},
		"dateOfBirth": {"1990-05-17"},
		"zoneInfo":    {"Brazil___America/Sao_Paulo"},
		"locale":      {"pt-BR"},
	}

	rr := httptest.NewRecorder()
	HandleAdminUserProfilePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(http.MethodPost,
		"/admin/users/7/profile?page=3&query=jane", handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"), handlertest.WithForm(form)))

	require.Len(t, apiClient.updates, 1)
	assert.Equal(t, []string{handlertest.AccessToken}, apiClient.tokens)
	assert.Equal(t, []int64{7}, apiClient.updateIds)
	assert.Equal(t, &api.UpdateUserProfileRequest{
		Username:            "jane-doe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "https://jane.example",
		Gender:              "2",
		DateOfBirth:         "1990-05-17",
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
	}, apiClient.updates[0])
	assert.Equal(t, []int64{7}, apiClient.reads, "the page is redrawn over the user the URL names")

	bind := handlertest.Bind(t, httpHelper)
	birthDate := time.Date(1990, time.May, 17, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, &api.UserResponse{
		Id:                  7,
		Email:               "stored@example.com",
		Username:            "jane-doe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "https://jane.example",
		Gender:              "other",
		BirthDate:           &birthDate,
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
	}, bind["user"], "the page redraws what is stored instead of what the administrator typed")
	assert.Equal(t, "The website is not valid.", bind["error"])
	assert.Equal(t, "3", bind["page"])
	assert.Equal(t, "jane", bind["query"])
	assert.NotEmpty(t, bind["timezones"])
	assert.NotEmpty(t, bind["locales"])
}

// The time-zone select only ever posts a country and a zone joined once by ___. Anything else is a
// hand-edited request, which keeps today's 500 and neither reads nor updates the user (#440
// decision 7).
func TestHandleAdminUserProfilePost_AMalformedZoneAnswers500AndUpdatesNothing(t *testing.T) {
	for _, zoneInfo := range []string{"America/Sao_Paulo", "Brazil___America___Sao_Paulo"} {
		t.Run(zoneInfo, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			apiClient := &userProfileRecorder{}
			form := url.Values{"username": {"jane-doe"}, "zoneInfo": {zoneInfo}}

			rr := httptest.NewRecorder()
			HandleAdminUserProfilePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(http.MethodPost,
				"/admin/users/7/profile", handlertest.WithAccessToken(),
				handlertest.WithRouteParam("userId", "7"), handlertest.WithForm(form)))

			assert.Empty(t, apiClient.updates, "a malformed zone reached the API")
			assert.Empty(t, apiClient.reads)
			httpHelper.AssertNotCalled(t, "RenderTemplate",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
