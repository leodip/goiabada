package accounthandlers

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
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// accountProfileRecorder answers the profile read with a fresh copy of the stored profile on every
// call, so an echo written onto one call's answer cannot leak into the next, and records every
// update the handler forwards.
type accountProfileRecorder struct {
	updateErr error
	updates   []*api.UpdateUserProfileRequest
	tokens    []string
}

func storedAccountProfile() *api.UserResponse {
	birthDate := time.Date(1970, time.January, 2, 0, 0, 0, 0, time.UTC)
	return &api.UserResponse{
		Id:                  7,
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

func (c *accountProfileRecorder) GetAccountProfile(_ context.Context, _ string) (*api.UserResponse, error) {
	return storedAccountProfile(), nil
}

func (c *accountProfileRecorder) UpdateAccountProfile(_ context.Context, accessToken string,
	request *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	c.tokens = append(c.tokens, accessToken)
	c.updates = append(c.updates, request)
	if c.updateErr != nil {
		return nil, c.updateErr
	}
	return storedAccountProfile(), nil
}

// submittedAccountProfile is every field the profile form posts, each different from the stored
// profile, so a value that came from the store rather than from the form is told apart.
var submittedAccountProfile = url.Values{
	"username":    {" jane-doe "},
	"givenName":   {"Jane"},
	"middleName":  {"Q"},
	"familyName":  {"Doe"},
	"nickname":    {"JD"},
	"website":     {"https://jane.example"},
	"gender":      {"1"},
	"dateOfBirth": {"1990-05-17"},
	"zoneInfo":    {"Brazil___America/Sao_Paulo"},
	"locale":      {"pt-BR"},
}

// A refusal from the API redraws the account profile page with what the user typed rather than what
// is stored, and the API's sentence, so nothing the user entered is lost (#440 decision 7).
func TestHandleProfilePost_ARefusalRedrawsThePageWithTheSubmittedValues(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_profile.html").Once()

	apiClient := &accountProfileRecorder{updateErr: &apiclient.APIError{
		Code: "INVALID_WEBSITE", Message: "The website is not valid.", StatusCode: http.StatusBadRequest,
	}}

	rr := httptest.NewRecorder()
	HandleProfilePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(http.MethodPost,
		"/account/profile", handlertest.WithAccessToken(), handlertest.WithForm(submittedAccountProfile)))

	require.Len(t, apiClient.updates, 1)
	assert.Equal(t, []string{handlertest.AccessToken}, apiClient.tokens)
	assert.Equal(t, &api.UpdateUserProfileRequest{
		Username:            "jane-doe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "https://jane.example",
		Gender:              "1",
		DateOfBirth:         "1990-05-17",
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
	}, apiClient.updates[0])

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
		Gender:              "male",
		BirthDate:           &birthDate,
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
	}, bind["user"], "the page redraws what is stored instead of what the user typed")
	assert.Equal(t, "The website is not valid.", bind["error"])
	assert.NotEmpty(t, bind["timezones"])
	assert.NotEmpty(t, bind["locales"])
}

// The time-zone select only ever posts a country and a zone joined once by ___. Anything else is a
// hand-edited request, which keeps today's 500 and forwards nothing (#440 decision 7).
func TestHandleProfilePost_AMalformedZoneAnswers500AndUpdatesNothing(t *testing.T) {
	for _, zoneInfo := range []string{"America/Sao_Paulo", "Brazil___America___Sao_Paulo"} {
		t.Run(zoneInfo, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			apiClient := &accountProfileRecorder{}
			form := url.Values{"username": {"jane-doe"}, "zoneInfo": {zoneInfo}}

			rr := httptest.NewRecorder()
			HandleProfilePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(http.MethodPost,
				"/account/profile", handlertest.WithAccessToken(), handlertest.WithForm(form)))

			assert.Empty(t, apiClient.updates, "a malformed zone reached the API")
			httpHelper.AssertNotCalled(t, "RenderTemplate",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
