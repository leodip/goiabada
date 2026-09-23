package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// The picture page dropped a failed picture read and drew the user as having no picture, so a
// broken API looked exactly like an empty profile. A user with no picture is a 200 from the API
// with HasPicture false, so every error here is a real one, and it now goes through the classifier
// like the user read above it (#425).
type userPictureApiClient struct {
	picture *apiclient.ProfilePictureInfo
	err     error
}

func (c *userPictureApiClient) GetUserById(_ context.Context, accessToken string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId}, nil
}

func (c *userPictureApiClient) GetUserProfilePicture(_ context.Context, accessToken string, userId int64) (*apiclient.ProfilePictureInfo, error) {
	return c.picture, c.err
}

func TestHandleAdminUserPictureGet_AnswersAFailedPictureRead(t *testing.T) {
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
			picture:       &apiclient.ProfilePictureInfo{HasPicture: true, PictureUrl: "https://auth.example/picture/42"},
			wantUrlPrefix: "https://auth.example/picture/42?t=",
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
				handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_picture.html").Once()
			}

			router := chi.NewRouter()
			router.Get("/admin/users/{userId}/picture", HandleAdminUserPictureGet(httpHelper,
				&userPictureApiClient{picture: testCase.picture, err: testCase.err}))
			router.ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/users/42/picture", handlertest.WithAccessToken()))

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
