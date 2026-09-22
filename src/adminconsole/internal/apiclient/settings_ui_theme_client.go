package apiclient

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetSettingsUITheme(ctx context.Context, accessToken string) (*api.SettingsUIThemeResponse, error) {
	return execute[api.SettingsUIThemeResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/settings/ui-theme",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) UpdateSettingsUITheme(ctx context.Context, accessToken string, request *api.UpdateSettingsUIThemeRequest) (*api.SettingsUIThemeResponse, error) {
	return execute[api.SettingsUIThemeResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/settings/ui-theme",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}
