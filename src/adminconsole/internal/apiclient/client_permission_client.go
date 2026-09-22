package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
)

// GetClientPermissions retrieves client and its permissions, two values out of one envelope.
func (c *AuthServerClient) GetClientPermissions(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, []api.PermissionResponse, error) {
	// No Content-Type: this request carries no body and has never set the header.
	response, err := execute[api.GetClientPermissionsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/permissions",
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, nil, err
	}
	return &response.Client, response.Permissions, nil
}

// UpdateClientPermissions replaces the set of permissions assigned to a client.
func (c *AuthServerClient) UpdateClientPermissions(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientPermissionsRequest) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/permissions",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}
