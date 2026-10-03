package apiclient

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

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
