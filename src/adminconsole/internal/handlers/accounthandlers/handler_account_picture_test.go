package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/errs"
)

// The account picture page dropped a failed picture read and drew the account as having no
// picture, so a broken API looked exactly like an empty profile. An account with no picture is a
// 200 from the API with HasPicture false, so every error here is a real one, and it now goes
// through the classifier (#425).
type accountPictureApiClient struct {
	picture *apiclient.ProfilePictureInfo
	err     error
}

func (c *accountPictureApiClient) GetAccountProfilePicture(_ context.Context, accessToken string) (*apiclient.ProfilePictureInfo, error) {
	return c.picture, c.err
}

func TestHandleAccountPictureGet_AnswersAFailedPictureRead(t *testing.T) {
	testCases := []struct {
		name         string
		picture      *apiclient.ProfilePictureInfo
		err          error
		wantNotFound bool
		wantError    bool
		// wantUrlPrefix is what profilePictureUrl must start with; empty means it must be empty.
		wantUrlPrefix string
	}{
		{
			name:         "a 404 from the API renders the 404 page",
			err:          &apiclient.APIError{Code: "NOT_FOUND", Message: "User not found", StatusCode: http.StatusNotFound},
			wantNotFound: true,
		},
		{
			name:      "a 500 from the API renders the 500 page",
			err:       &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError},
			wantError: true,
		},
		{
			name:      "a transport error renders the 500 page",
			err:       errs.New("connection refused"),
			wantError: true,
		},
		{
			name:          "a picture renders the page with its address",
			picture:       &apiclient.ProfilePictureInfo{HasPicture: true, PictureUrl: "https://auth.example/account/picture"},
			wantUrlPrefix: "https://auth.example/account/picture?t=",
		},
		{
			name:    "no picture renders the page without one",
			picture: &apiclient.ProfilePictureInfo{HasPicture: false},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			switch {
			case testCase.wantNotFound:
				httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			case testCase.wantError:
				httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
			default:
				handlertest.RefuseInternalServerError(t, httpHelper)
				handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_picture.html").Once()
			}

			HandleAccountPictureGet(httpHelper, &accountPictureApiClient{picture: testCase.picture, err: testCase.err}).
				ServeHTTP(httptest.NewRecorder(),
					handlertest.Request(http.MethodGet, "/account/picture", handlertest.WithAccessToken()))

			httpHelper.AssertExpectations(t)
			if testCase.wantNotFound || testCase.wantError {
				httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything)
				return
			}

			url, _ := handlertest.Bind(t, httpHelper)["profilePictureUrl"].(string)
			if testCase.wantUrlPrefix == "" {
				assert.Empty(t, url)
			} else {
				assert.True(t, strings.HasPrefix(url, testCase.wantUrlPrefix), "got %q", url)
			}
		})
	}
}
