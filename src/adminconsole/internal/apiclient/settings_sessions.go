package apiclient

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetSettingsSessions(ctx context.Context, accessToken string) (*api.SettingsSessionsResponse, error) {
	return execute[api.SettingsSessionsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/settings/sessions",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) UpdateSettingsSessions(ctx context.Context, accessToken string, request *api.UpdateSettingsSessionsRequest) (*api.SettingsSessionsResponse, error) {
	return execute[api.SettingsSessionsResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/settings/sessions",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}
