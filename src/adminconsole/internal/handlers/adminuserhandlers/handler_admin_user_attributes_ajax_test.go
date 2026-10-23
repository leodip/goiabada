package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
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
// attributesApiClient answers only the calls these handlers make. The rest of the ports it is
// passed to panic, rather than return a helpful zero value.
type attributesApiClient struct {
	user       *api.UserResponse
	userErr    error
	attributes []api.UserAttributeResponse
}

func (c *attributesApiClient) GetUserById(_ context.Context, accessToken string, userId int64) (*api.UserResponse, error) {
	return c.user, c.userErr
}

func (c *attributesApiClient) GetUserAttributesByUserId(_ context.Context, accessToken string, userId int64) ([]api.UserAttributeResponse, error) {
	return c.attributes, nil
}

func (c *attributesApiClient) DeleteUserAttribute(_ context.Context, accessToken string, attributeId int64) error {
	return nil
}

// The rest of the ports attributesApiClient is passed to, which no test here reaches.

func (*attributesApiClient) DeleteUserConsent(context.Context, string, int64) error {
	panic("unexpected call to DeleteUserConsent")
}

func (*attributesApiClient) GetUserConsents(context.Context, string, int64) ([]api.UserConsentResponse, error) {
	panic("unexpected call to GetUserConsents")
}

func TestUserAttributesRemove_StaleOrMalformedUrlAnswers404AsJson(t *testing.T) {
	present := &api.UserResponse{Id: 42}
	gone := &apiclient.APIError{Code: "NOT_FOUND", Message: "User not found", StatusCode: http.StatusNotFound}
	broken := &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError}
	attributes := []api.UserAttributeResponse{{Id: 7}}

	testCases := []struct {
		name string
		// target is the URL. userId and attributeId are the path values the route binds from it,
		// both empty for a request the router never bound, which is how an unbound parameter reads
		// from r.PathValue.
		target      string
		userId      string
		attributeId string
		withJwt     bool
		user        *api.UserResponse
		userErr     error
		attributes  []api.UserAttributeResponse
		// wantStatus is the HTTP status the handler must choose; 0 means it must take JSONError's
		// generic 500 arm instead, with a bare error rather than an *ErrorDetail.
		wantStatus int
	}{
		{
			name:        "a user id that does not parse",
			target:      "/admin/users/not-a-number/attributes/7/remove",
			userId:      "not-a-number",
			attributeId: "7",
			withJwt:     true,
			user:        present,
			attributes:  attributes,
			wantStatus:  http.StatusNotFound,
		},
		{
			name:       "a user id the router never bound",
			target:     "/admin/users/42/attributes/7/remove",
			withJwt:    true,
			user:       present,
			attributes: attributes,
			wantStatus: http.StatusNotFound,
		},
		{
			name:        "an attribute id that does not parse",
			target:      "/admin/users/42/attributes/not-a-number/remove",
			userId:      "42",
			attributeId: "not-a-number",
			withJwt:     true,
			user:        present,
			attributes:  attributes,
			wantStatus:  http.StatusNotFound,
		},
		{
			name:        "a user the API says is gone",
			target:      "/admin/users/42/attributes/7/remove",
			userId:      "42",
			attributeId: "7",
			withJwt:     true,
			userErr:     gone,
			wantStatus:  http.StatusNotFound,
		},
		{
			name:        "an attribute that is no longer on the user",
			target:      "/admin/users/42/attributes/7/remove",
			userId:      "42",
			attributeId: "7",
			withJwt:     true,
			user:        present,
			attributes:  []api.UserAttributeResponse{{Id: 99}},
			wantStatus:  http.StatusNotFound,
		},
		{
			name:        "no JWT info in context, which is a middleware invariant and stays a 500",
			target:      "/admin/users/42/attributes/7/remove",
			userId:      "42",
			attributeId: "7",
			withJwt:     false,
			user:        present,
		},
		{
			name:        "a 500 from the API, which is a server fault and stays a 500",
			target:      "/admin/users/42/attributes/7/remove",
			userId:      "42",
			attributeId: "7",
			withJwt:     true,
			userErr:     broken,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			var captured error
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			var opts []handlertest.Option
			if testCase.withJwt {
				opts = append(opts, handlertest.WithAccessToken())
			}
			if testCase.userId != "" {
				opts = append(opts,
					handlertest.WithPathValue("userId", testCase.userId),
					handlertest.WithPathValue("attributeId", testCase.attributeId))
			}
			req := handlertest.Request(http.MethodPost, testCase.target, opts...)

			apiClient := &attributesApiClient{
				user:       testCase.user,
				userErr:    testCase.userErr,
				attributes: testCase.attributes,
			}
			handler := HandleAttributesRemovePost(httpHelper, apiClient)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			httpHelper.AssertExpectations(t)
			require.Error(t, captured, "the handler answered nothing")

			var detail *oauth.ErrorDetail
			if testCase.wantStatus == 0 {
				assert.NotErrorAs(t, captured, &detail,
					"expected JSONError's generic 500 arm, got a status-carrying %v", captured)
				return
			}
			require.ErrorAs(t, captured, &detail,
				"expected an *ErrorDetail carrying a status, got %v", captured)
			assert.Equal(t, testCase.wantStatus, detail.HTTPStatus())
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
			httpHelper := handlersmocks.NewHttpHelper(t)
			var captured error
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			req := handlertest.Request(http.MethodPost, "/admin/users/42/consents",
				handlertest.WithAccessToken(),
				handlertest.WithPathValue("userId", "42"),
				handlertest.WithBody(strings.NewReader(testCase.body)),
			)

			HandleConsentsPost(httpHelper, &attributesApiClient{user: &api.UserResponse{Id: 42}}).
				ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			var detail *oauth.ErrorDetail
			require.ErrorAs(t, captured, &detail,
				"expected an *ErrorDetail carrying 400, got %v", captured)
			assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
			assert.Equal(t, "invalid_request_body", detail.Code())
		})
	}
}
