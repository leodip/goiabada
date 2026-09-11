package admingrouphandlers

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
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// Decision 11 at a form that submits through the API, and the row that makes it worth its own test:
// what a broad catch does to the two statuses it was never meant to hold.
//
// The guard here used to be errors.As(err, &apiErr) followed by renderError(apiErr.Message), with
// no look at the status at all. That is right for the 400 and wrong for everything else, and wrong
// in the direction nothing notices: a group deleted in another tab came back as HTTP 200 with
// "Group not found" drawn in the form's validation slot, and an auth server that was actually
// broken came back as HTTP 200 with its sentence in the same place and no log line anywhere. Both
// statuses were reported to the administrator as "the value you typed is not acceptable".
//
// HandleAPIErrorWithCallback is what tells them apart, and the three rows below are the three
// answers it has to give.
type attributesAddApiClient struct {
	apiclient.ApiClient
	err error
}

func (c *attributesAddApiClient) GetGroupById(accessToken string, groupId int64) (*models.Group, int, error) {
	return &models.Group{Id: groupId, GroupIdentifier: "some-group"}, 0, nil
}

func (c *attributesAddApiClient) CreateGroupAttribute(accessToken string, request *api.CreateGroupAttributeRequest) (*models.GroupAttribute, error) {
	return nil, c.err
}

func TestGroupAttributesAddPost_TellsTheApisStatusesApart(t *testing.T) {
	const (
		answerRenderForm = "render"
		answerNotFound   = "not-found"
		answer500        = "internal"
	)

	testCases := []struct {
		name   string
		apiErr error
		want   string
	}{
		{
			name: "a value the API refused, which the form redraws",
			apiErr: &apiclient.APIError{
				Code:       "VALIDATION_ERROR",
				Message:    "The attribute key is not valid",
				StatusCode: http.StatusBadRequest,
			},
			want: answerRenderForm,
		},
		{
			name: "a group deleted while the form was open",
			apiErr: &apiclient.APIError{
				Code:       "NOT_FOUND",
				Message:    "Group not found",
				StatusCode: http.StatusNotFound,
			},
			want: answerNotFound,
		},
		{
			name: "a server fault, which belongs in the log rather than in the form",
			apiErr: &apiclient.APIError{
				Code:       "INTERNAL_SERVER_ERROR",
				Message:    "the database is on fire",
				StatusCode: http.StatusInternalServerError,
			},
			want: answer500,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handler_helpers.NewHttpHelper(t)
			var renderedError any
			switch testCase.want {
			case answerRenderForm:
				httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						bind, _ := args.Get(4).(map[string]interface{})
						renderedError = bind["error"]
					}).Return(nil).Once()
			case answerNotFound:
				httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			case answer500:
				httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
					Return().Once()
			}

			req := httptest.NewRequest(http.MethodPost, "/admin/groups/7/attributes/add",
				strings.NewReader("attributeKey=k&attributeValue=v"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

			router := chi.NewRouter()
			router.Post("/admin/groups/{groupId}/attributes/add",
				HandleAdminGroupAttributesAddPost(httpHelper,
					&attributesAddApiClient{err: testCase.apiErr}))
			router.ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			if testCase.want == answerRenderForm {
				assert.Equal(t, "The attribute key is not valid", renderedError,
					"the API's own sentence is what tells the administrator what to change")
			}
		})
	}
}
