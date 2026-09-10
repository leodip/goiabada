package adminuserhandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// Decision 11 answered for an AJAX request, at this handler group's seam. Stage 8 gave the page
// handlers 404 for a stale or malformed URL and left the AJAX ones at 500, because NotFound renders
// a page and these answer JSON. The rule this pins is that the status does not depend on the media
// type: an AJAX request has the same relationship to its target URI as the page beside it, so the
// three conditions RFC 9110 section 15.5.5 covers -- an id the router never bound, one that does
// not parse, an entity that is gone -- answer 404 either way, and only the representation differs.
//
// The last two rows are what keeps the sweep honest, and both would pass if 404 had simply been
// applied to everything: a missing JWT context is an invariant the JWT middleware holds, and a 500
// from the API is a server fault. Both stay 500, with the stack and the request id.
//
// attributesApiClient answers only the calls these handlers make and embeds the interface, so
// reaching for anything else panics rather than returning a helpful zero value.
type attributesApiClient struct {
	apiclient.ApiClient
	user       *models.User
	userErr    error
	attributes []models.UserAttribute
}

func (c *attributesApiClient) GetUserById(accessToken string, userId int64) (*models.User, error) {
	return c.user, c.userErr
}

func (c *attributesApiClient) GetUserAttributesByUserId(accessToken string, userId int64) ([]models.UserAttribute, error) {
	return c.attributes, nil
}

func (c *attributesApiClient) DeleteUserAttribute(accessToken string, attributeId int64) error {
	return nil
}

func TestUserAttributesRemove_StaleOrMalformedUrlAnswers404AsJson(t *testing.T) {
	const routePattern = "/admin/users/{userId}/attributes/{attributeId}/remove"

	present := &models.User{Id: 42}
	gone := &apiclient.APIError{Code: "NOT_FOUND", Message: "User not found", StatusCode: http.StatusNotFound}
	broken := &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError}
	attributes := []models.UserAttribute{{Id: 7}}

	testCases := []struct {
		name string
		// target is the URL. When routed is false the handler runs without a chi route context,
		// which is how an unbound URL parameter reads from inside chi.URLParam.
		target     string
		routed     bool
		withJwt    bool
		user       *models.User
		userErr    error
		attributes []models.UserAttribute
		// wantStatus is the HTTP status the handler must choose; 0 means it must take JsonError's
		// generic 500 arm instead, with a bare error rather than an *ErrorDetail.
		wantStatus int
	}{
		{
			name:       "a user id that does not parse",
			target:     "/admin/users/not-a-number/attributes/7/remove",
			routed:     true,
			withJwt:    true,
			user:       present,
			attributes: attributes,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "a user id the router never bound",
			target:     "/admin/users/42/attributes/7/remove",
			routed:     false,
			withJwt:    true,
			user:       present,
			attributes: attributes,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "an attribute id that does not parse",
			target:     "/admin/users/42/attributes/not-a-number/remove",
			routed:     true,
			withJwt:    true,
			user:       present,
			attributes: attributes,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "a user the API says is gone",
			target:     "/admin/users/42/attributes/7/remove",
			routed:     true,
			withJwt:    true,
			userErr:    gone,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "an attribute that is no longer on the user",
			target:     "/admin/users/42/attributes/7/remove",
			routed:     true,
			withJwt:    true,
			user:       present,
			attributes: []models.UserAttribute{{Id: 99}},
			wantStatus: http.StatusNotFound,
		},
		{
			name:    "no JWT info in context, which is a middleware invariant and stays a 500",
			target:  "/admin/users/42/attributes/7/remove",
			routed:  true,
			withJwt: false,
			user:    present,
		},
		{
			name:    "a 500 from the API, which is a server fault and stays a 500",
			target:  "/admin/users/42/attributes/7/remove",
			routed:  true,
			withJwt: true,
			userErr: broken,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handler_helpers.NewHttpHelper(t)
			var captured error
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			req := httptest.NewRequest(http.MethodPost, testCase.target, nil)
			if testCase.withJwt {
				req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
					oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))
			}

			apiClient := &attributesApiClient{
				user:       testCase.user,
				userErr:    testCase.userErr,
				attributes: testCase.attributes,
			}
			handler := HandleAdminUserAttributesRemovePost(httpHelper, apiClient)
			w := httptest.NewRecorder()

			if testCase.routed {
				router := chi.NewRouter()
				router.Post(routePattern, handler)
				router.ServeHTTP(w, req)
			} else {
				handler.ServeHTTP(w, req)
			}

			httpHelper.AssertExpectations(t)
			require.NotNil(t, captured, "the handler answered nothing")

			var detail *customerrors.ErrorDetail
			if testCase.wantStatus == 0 {
				assert.False(t, errors.As(captured, &detail),
					"expected JsonError's generic 500 arm, got a status-carrying %v", captured)
				return
			}
			require.True(t, errors.As(captured, &detail),
				"expected an *ErrorDetail carrying a status, got %v", captured)
			assert.Equal(t, testCase.wantStatus, detail.GetHttpStatusCode())
		})
	}
}

// TestUserConsents_MalformedBodyAnswers400AsJson is decision 12 at this seam, in both its shapes. A
// body that does not decode and a body that decodes without the field the endpoint acts on are the
// same condition -- the request the console's own script sent is not one this endpoint can act on
// -- and RFC 9110 section 15.5.1 covers it: "malformed request syntax". Both answered 500 with a
// stack before #279. Decision 12 named only the decode failure; pinning only that one would let
// the other drift back, since they are separate branches.
func TestUserConsents_MalformedBodyAnswers400AsJson(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{name: "a body that is not JSON at all", body: "{this is not json"},
		{name: "a body that parses but carries no consentId", body: "{\"somethingElse\": 1}"},
		{name: "a body whose consentId is not a number", body: "{\"consentId\": \"seven\"}"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handler_helpers.NewHttpHelper(t)
			var captured error
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			req := httptest.NewRequest(http.MethodPost, "/admin/users/42/consents",
				strings.NewReader(testCase.body))
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

			router := chi.NewRouter()
			router.Post("/admin/users/{userId}/consents",
				HandleAdminUserConsentsPost(httpHelper, &attributesApiClient{user: &models.User{Id: 42}}))
			router.ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			var detail *customerrors.ErrorDetail
			require.True(t, errors.As(captured, &detail),
				"expected an *ErrorDetail carrying 400, got %v", captured)
			assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
			assert.Equal(t, "invalid_request_body", detail.GetCode())
		})
	}
}
