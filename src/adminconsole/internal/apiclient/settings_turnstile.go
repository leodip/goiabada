package apiclient

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetSettingsTurnstile(ctx context.Context, accessToken string) (*api.SettingsTurnstileResponse, error) {
	return execute[api.SettingsTurnstileResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/settings/turnstile",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) UpdateSettingsTurnstile(ctx context.Context, accessToken string, request *api.UpdateSettingsTurnstileRequest) (*api.SettingsTurnstileResponse, error) {
	return execute[api.SettingsTurnstileResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/settings/turnstile",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}
