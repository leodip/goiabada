package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
)

// GetClientIntrospectionResources retrieves a client and the resources whose tokens it may
// introspect, two values out of one envelope.
func (c *AuthServerClient) GetClientIntrospectionResources(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, []api.ResourceResponse, error) {
	response, err := execute[api.GetClientIntrospectionResourcesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/introspection-resources",
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, nil, err
	}
	return &response.Client, response.Resources, nil
}

// UpdateClientIntrospectionResources replaces the list of resources whose tokens a client may
// introspect.
func (c *AuthServerClient) UpdateClientIntrospectionResources(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientIntrospectionResourcesRequest) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/introspection-resources",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}
