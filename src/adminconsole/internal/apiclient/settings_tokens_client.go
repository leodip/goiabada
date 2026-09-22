package apiclient

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetSettingsTokens(ctx context.Context, accessToken string) (*api.SettingsTokensResponse, error) {
	return execute[api.SettingsTokensResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/settings/tokens",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) UpdateSettingsTokens(ctx context.Context, accessToken string, request *api.UpdateSettingsTokensRequest) (*api.SettingsTokensResponse, error) {
	return execute[api.SettingsTokensResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/settings/tokens",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}
