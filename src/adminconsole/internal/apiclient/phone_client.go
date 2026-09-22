package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) UpdateUserPhone(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserPhoneRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/phone",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

func (c *AuthServerClient) GetPhoneCountries(ctx context.Context, accessToken string) ([]api.PhoneCountryResponse, error) {
	response, err := execute[api.GetPhoneCountriesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/phone-countries",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.PhoneCountries, nil
}
