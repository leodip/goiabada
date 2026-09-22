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
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// Seam 4 for the two user-phone calls stage 10 moved (#386). See accounthandlers' file of the same
// name for what this owns and why the context is the assertion.
//
// getPhoneCountriesWithCache has a case of its own below, because it is the one call in this half
// that is not made from a handler body: the 24-hour cache sits between, and a context that stopped
// at the cache would be invisible to a handler test.

type userCtxMarkerKey struct{}

type ctxRecordingApiClient struct {
	apiclient.ApiClient
	seen []context.Context
}

func (s *ctxRecordingApiClient) UpdateUserPhone(ctx context.Context, _ string, _ int64, _ *api.UpdateUserPhoneRequest) (*api.UserResponse, error) {
	s.seen = append(s.seen, ctx)
	return nil, errs.New("the auth server refused")
}

func (s *ctxRecordingApiClient) GetPhoneCountries(ctx context.Context, _ string) ([]api.PhoneCountryResponse, error) {
	s.seen = append(s.seen, ctx)
	return nil, errs.New("the auth server refused")
}

// GetUserById is reached first and is stage 12's, so it still has no context and only has to
// succeed for the phone write below it to happen at all.
func (s *ctxRecordingApiClient) GetUserById(_ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Username: "jdoe"}, nil
}

func TestAdminUserHandlers_ThePhoneWriteCarriesTheRequestsContext(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(nil).Maybe()

	// The 24-hour cache is a package variable, so a value left by another test would skip the
	// fetch this case is about. Emptying it is what makes the call happen.
	resetPhoneCountriesCache()

	apiClient := &ctxRecordingApiClient{}

	request := handlertest.Request(http.MethodPost, "/admin/users/42/phone",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", "42"),
		handlertest.WithForm(url.Values{"phoneCountryUniqueId": {"BRA_0"}, "phoneNumber": {"5551234"}}))
	marked := request.WithContext(context.WithValue(request.Context(), userCtxMarkerKey{}, "phone"))

	HandleAdminUserPhonePost(httpHelper, nil, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

	require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
	for i, seen := range apiClient.seen {
		assert.Equal(t, "phone", seen.Value(userCtxMarkerKey{}),
			"call %d carried a context that is not the request's", i)
	}
}

// The cache is the one hop between a handler and the auth server in this package, so it is the one
// place a context could be dropped without a handler test noticing.
func TestGetPhoneCountriesWithCache_CarriesTheCallersContextThroughAMiss(t *testing.T) {
	resetPhoneCountriesCache()

	apiClient := &ctxRecordingApiClient{}
	ctx := context.WithValue(context.Background(), userCtxMarkerKey{}, "cache-miss")

	_, err := getPhoneCountriesWithCache(ctx, apiClient, "an-access-token")
	require.Error(t, err)

	require.Len(t, apiClient.seen, 1)
	assert.Equal(t, "cache-miss", apiClient.seen[0].Value(userCtxMarkerKey{}))
}

func resetPhoneCountriesCache() {
	phoneCountriesCache.mutex.Lock()
	defer phoneCountriesCache.mutex.Unlock()

	phoneCountriesCache.data = nil
	phoneCountriesCache.timestamp = time.Time{}
}
