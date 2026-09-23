package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// The email form hand-rolled its own 400 arm and sent everything else to the classifier's other
// arms, so the 409 the auth server answers when another account took the address between its check
// and its write (#414, #425) reached the 500 page and the administrator lost the form. It now goes
// through HandleAPIErrorWithCallback, which sends a 400 and a 409 back to the form and the rest
// where they always went.
type userEmailApiClient struct {
	updateErr error
}

func (c *userEmailApiClient) GetUserById(_ context.Context, accessToken string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Email: "before@example.com"}, nil
}

func (c *userEmailApiClient) UpdateUserEmail(_ context.Context, accessToken string, userId int64,
	request *api.UpdateUserEmailRequest) (*api.UserResponse, error) {
	return nil, c.updateErr
}

func TestHandleAdminUserEmailPost_AnswersAFailedWrite(t *testing.T) {
	testCases := []struct {
		name         string
		err          error
		wantNotFound bool
		wantError    bool
		// wantMessage is the sentence the re-rendered form must carry.
		wantMessage string
	}{
		{
			name: "a 409 re-renders the form with the API's sentence",
			err: &apiclient.APIError{Code: "EMAIL_ALREADY_EXISTS", Message: "This email address is already registered",
				StatusCode: http.StatusConflict},
			wantMessage: "This email address is already registered",
		},
		{
			name: "a 400 re-renders the form with the API's sentence",
			err: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "Please enter a valid email address.",
				StatusCode: http.StatusBadRequest},
			wantMessage: "Please enter a valid email address.",
		},
		{
			name:         "a 404 renders the 404 page",
			err:          &apiclient.APIError{Code: "NOT_FOUND", Message: "User not found", StatusCode: http.StatusNotFound},
			wantNotFound: true,
		},
		{
			name: "a 500 renders the 500 page",
			err: &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire",
				StatusCode: http.StatusInternalServerError},
			wantError: true,
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
				handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_email.html").Once()
			}

			router := chi.NewRouter()
			// The session store is nil: every row fails before the success path reaches it.
			router.Post("/admin/users/{userId}/email", HandleAdminUserEmailPost(httpHelper, nil,
				&userEmailApiClient{updateErr: testCase.err}))
			router.ServeHTTP(httptest.NewRecorder(), handlertest.Request(http.MethodPost,
				"/admin/users/42/email?page=2&query=bob", handlertest.WithAccessToken(),
				handlertest.WithForm(url.Values{"email": {" Taken@Example.com "}, "emailVerified": {"on"}})))

			httpHelper.AssertExpectations(t)
			if testCase.wantNotFound || testCase.wantError {
				httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything)
				return
			}

			// The form comes back as the administrator submitted it, with the API's sentence.
			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, testCase.wantMessage, bind["error"])
			assert.Equal(t, "taken@example.com", bind["email"])
			assert.Equal(t, true, bind["emailVerified"])
			assert.Equal(t, "2", bind["page"])
			assert.Equal(t, "bob", bind["query"])
		})
	}
}
