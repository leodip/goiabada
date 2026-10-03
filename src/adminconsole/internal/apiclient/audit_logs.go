package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetSettingsAuditLogs(ctx context.Context, accessToken string) (*api.SettingsAuditLogsResponse, error) {
	return execute[api.SettingsAuditLogsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/settings/audit-logs",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) UpdateSettingsAuditLogs(ctx context.Context, accessToken string, request *api.UpdateSettingsAuditLogsRequest) (*api.SettingsAuditLogsResponse, error) {
	return execute[api.SettingsAuditLogsResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/settings/audit-logs",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) GetAuditLogsPaginated(ctx context.Context, accessToken string, page, pageSize int, auditEvent string,
	requestId string) (*api.GetAuditLogsResponse, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/audit-logs?page=%d&size=%d", c.baseURL, page, pageSize)
	// Both filters are escaped. The request id is whatever the client put in X-Request-Id, so it
	// can carry an & or a # and would otherwise be read as another parameter or truncate the
	// query; auditEvent rides along on the same rule, since a filter built by hand from a string
	// is where that mistake gets made next, even though its values come from a fixed list (#328).
	if auditEvent != "" {
		fullURL += fmt.Sprintf("&auditEvent=%s", url.QueryEscape(auditEvent))
	}
	if requestId != "" {
		fullURL += fmt.Sprintf("&requestId=%s", url.QueryEscape(requestId))
	}

	return execute[api.GetAuditLogsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fullURL,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// GetAuditEventTypes fetches the catalog of audit event names the auth server can write, which
// is what the viewer's filter dropdown offers. The admin console holds no audit event name of
// its own: a name compiled in here would be one the two binaries could disagree about after a
// partial upgrade, offering a filter value the server never writes (#351).
func (c *AuthServerClient) GetAuditEventTypes(ctx context.Context, accessToken string) (*api.GetAuditEventTypesResponse, error) {
	return execute[api.GetAuditEventTypesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/audit-logs/event-types",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}
