package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// hostileSearch is a search term carrying every character that meant something else when pasted
// into a query string unescaped: & began a parameter, # a fragment, = a value, % an escape, + a
// space, and a space is not allowed in a URL at all.
const hostileSearch = "tom & jerry #2 a=b 100% c+d"

func TestWithListPosition_EscapesThePageAndTheSearch(t *testing.T) {
	testCases := []struct {
		name  string
		page  string
		query string
	}{
		{name: "every reserved character", page: "3", query: hostileSearch},
		{name: "a page that is not a number", page: "2&query=forged", query: "x"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			from := httptest.NewRequest(http.MethodPost, "/admin/users/7/email?"+url.Values{
				"page": {testCase.page}, "query": {testCase.query},
			}.Encode(), nil)

			returnURL := withListPosition("/admin/users/7/email", from)

			parsed, err := url.Parse(returnURL)
			require.NoError(t, err)
			assert.Empty(t, parsed.Fragment, "part of the search became a fragment")
			assert.Equal(t, "/admin/users/7/email", parsed.Path)
			assert.Equal(t, url.Values{"page": {testCase.page}, "query": {testCase.query}}, parsed.Query(),
				"the list reopens on something other than what the administrator left")
		})
	}
}

// A plain page and search, and none at all, are what almost every redirect carries, and they come
// out exactly as the fmt.Sprintf this replaced wrote them.
func TestWithListPosition_RendersPlainValuesAsBefore(t *testing.T) {
	testCases := []struct {
		name   string
		target string
		want   string
	}{
		{name: "a page and a search", target: "/admin/users/7/email?page=2&query=john", want: "page=2&query=john"},
		{name: "neither", target: "/admin/users/7/email", want: "page=&query="},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			from := httptest.NewRequest(http.MethodPost, testCase.target, nil)

			assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/users/7/email?"+testCase.want,
				withListPosition("/admin/users/7/email", from))
		})
	}
}

// returnURLStubApiClient answers every call the ten saving handlers make on their way to the
// redirect, each as a success for user 7. Anything else reaches the nil embedded interface and
// panics, which names the call.
type returnURLStubApiClient struct {
	apiclient.ApiClient
}

func (returnURLStubApiClient) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Email: "someone@example.com"}, nil
}

func (returnURLStubApiClient) UpdateUserAddress(_ context.Context, _ string, userId int64,
	_ *api.UpdateUserAddressRequest) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId}, nil
}

func (returnURLStubApiClient) CreateUserAttribute(_ context.Context, _ string,
	request *api.CreateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	return &api.UserAttributeResponse{Id: 3, UserId: request.UserId}, nil
}

func (returnURLStubApiClient) GetUserAttributeById(_ context.Context, _ string,
	attributeId int64) (*api.UserAttributeResponse, error) {
	return &api.UserAttributeResponse{Id: attributeId, UserId: 7, Key: "k"}, nil
}

func (returnURLStubApiClient) UpdateUserAttribute(_ context.Context, _ string, attributeId int64,
	_ *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	return &api.UserAttributeResponse{Id: attributeId, UserId: 7}, nil
}

func (returnURLStubApiClient) DeleteUser(_ context.Context, _ string, _ int64) error {
	return nil
}

func (returnURLStubApiClient) UpdateUserEnabled(_ context.Context, _ string, userId int64,
	_ bool) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId}, nil
}

func (returnURLStubApiClient) UpdateUserEmail(_ context.Context, _ string, userId int64,
	_ *api.UpdateUserEmailRequest) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId}, nil
}

func (returnURLStubApiClient) CreateUserAdmin(_ context.Context, _ string,
	_ *api.CreateUserAdminRequest) (*api.UserResponse, error) {
	return &api.UserResponse{Id: 7}, nil
}

func (returnURLStubApiClient) GetPhoneCountries(_ context.Context, _ string) ([]api.PhoneCountryResponse, error) {
	return []api.PhoneCountryResponse{}, nil
}

func (returnURLStubApiClient) UpdateUserPhone(_ context.Context, _ string, userId int64,
	_ *api.UpdateUserPhoneRequest) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId}, nil
}

func (returnURLStubApiClient) UpdateUserProfile(_ context.Context, _ string, userId int64,
	_ *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId}, nil
}

// Each of the ten handlers that return to the user list after a save, driven to that redirect with
// a search the list could not have survived unescaped.
func TestUserPageSaves_ReturnToTheListPositionEscaped(t *testing.T) {
	stub := returnURLStubApiClient{}
	store := newFlashTestStore()

	testCases := []struct {
		name     string
		handler  func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc
		form     url.Values
		options  []handlertest.Option
		wantPath string
	}{
		{
			name: "address",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserAddressPost(helper, store, stub)
			},
			wantPath: "/admin/users/7/address",
		},
		{
			name: "attributes add",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserAttributesAddPost(helper, stub)
			},
			form:     url.Values{"attributeKey": {"k"}},
			wantPath: "/admin/users/7/attributes",
		},
		{
			name: "attributes edit",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserAttributesEditPost(helper, stub)
			},
			form:     url.Values{"attributeKey": {"k"}},
			options:  []handlertest.Option{handlertest.WithRouteParam("attributeId", "3")},
			wantPath: "/admin/users/7/attributes",
		},
		{
			name: "authentication",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserAuthenticationPost(helper, store, stub)
			},
			wantPath: "/admin/users/7/authentication",
		},
		{
			name: "delete",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserDeletePost(helper, stub)
			},
			wantPath: "/admin/users/",
		},
		{
			name: "details",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserDetailsPost(helper, store, stub)
			},
			wantPath: "/admin/users/7/details",
		},
		{
			name: "email",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserEmailPost(helper, store, stub)
			},
			form:     url.Values{"email": {"someone@example.com"}},
			wantPath: "/admin/users/7/email",
		},
		{
			name: "new",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserNewPost(helper, store, stub)
			},
			form:     url.Values{"email": {"someone@example.com"}, "password": {"a password"}},
			options:  []handlertest.Option{handlertest.WithSettings(&api.PublicSettingsResponse{})},
			wantPath: "/admin/users/7/details",
		},
		{
			name: "phone",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserPhonePost(helper, store, stub)
			},
			wantPath: "/admin/users/7/phone",
		},
		{
			name: "profile",
			handler: func(helper *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
				return HandleAdminUserProfilePost(helper, store, stub)
			},
			wantPath: "/admin/users/7/profile",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)

			options := append([]handlertest.Option{
				handlertest.WithAccessToken(),
				handlertest.WithRouteParam("userId", "7"),
				handlertest.WithForm(testCase.form),
			}, testCase.options...)
			req := handlertest.Request(http.MethodPost,
				fmt.Sprintf("%v?%v", testCase.wantPath, url.Values{"page": {"3"}, "query": {hostileSearch}}.Encode()),
				options...)
			rec := httptest.NewRecorder()

			testCase.handler(httpHelper).ServeHTTP(rec, req)

			require.Equal(t, http.StatusFound, rec.Code, "the save did not reach its redirect")
			location := rec.Header().Get("Location")
			parsed, err := url.Parse(location)
			require.NoError(t, err)
			assert.Equal(t, config.GetAdminConsole().BaseURL+testCase.wantPath,
				(&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path}).String())
			assert.Empty(t, parsed.Fragment, "part of the search became a fragment")
			assert.Equal(t, url.Values{"page": {"3"}, "query": {hostileSearch}}, parsed.Query(), "Location: %s", location)
		})
	}
}
