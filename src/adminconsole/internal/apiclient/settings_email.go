package apiclient

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetSettingsEmail(ctx context.Context, accessToken string) (*api.SettingsEmailResponse, error) {
	return execute[api.SettingsEmailResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/settings/email",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) UpdateSettingsEmail(ctx context.Context, accessToken string, request *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	return execute[api.SettingsEmailResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/settings/email",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// SendTestEmail answers whether the test email went over TLS.
func (c *AuthServerClient) SendTestEmail(ctx context.Context, accessToken string, request *api.SendTestEmailRequest) (*api.SendTestEmailResponse, error) {
	return execute[api.SendTestEmailResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/admin/settings/email/send-test",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
		sendsMail:     true,
	})
}
