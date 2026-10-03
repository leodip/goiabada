package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// countingPhoneApiClient answers the phone page's two reads and counts the country list's.
type countingPhoneApiClient struct {
	countryReads int
}

func (c *countingPhoneApiClient) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Username: "jdoe"}, nil
}

func (c *countingPhoneApiClient) GetPhoneCountries(_ context.Context, _ string) ([]api.PhoneCountryResponse, error) {
	c.countryReads++
	return []api.PhoneCountryResponse{{UniqueId: "BRA_0", CallingCode: "+55", Name: "Brazil"}}, nil
}

func (c *countingPhoneApiClient) UpdateUserPhone(_ context.Context, _ string, _ int64, _ *api.UpdateUserPhoneRequest) (*api.UserResponse, error) {
	return nil, nil
}

// The page asks the auth server for the country list on every request, as the account phone page
// does, rather than serving a copy a package variable kept for a day. The list is static, so a
// viewer sees nothing different; what the test holds is that no state outlives a request between
// the page and the API, so a second request is a second call (#440). The handler is built once and
// serves both, as the router's does, so a copy kept in its closure would be caught as well.
func TestHandlePhoneGet_TwoRequestsAskForTheCountriesTwice(t *testing.T) {
	apiClient := &countingPhoneApiClient{}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_phone.html").Twice()

	handler := HandlePhoneGet(httpHelper, newFlashTestStore(), apiClient)
	for range 2 {
		req := handlertest.Request(http.MethodGet, "/admin/users/42/phone",
			handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", "42"))
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	assert.Equal(t, 2, apiClient.countryReads, "each request asks the auth server for the list")
}
