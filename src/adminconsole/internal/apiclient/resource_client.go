package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

// CreateResource creates a new resource via the auth server admin API
func (c *AuthServerClient) CreateResource(ctx context.Context, accessToken string, request *api.CreateResourceRequest) (*api.ResourceResponse, error) {
	response, err := execute[api.CreateResourceResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           fmt.Sprintf("%s/api/v1/admin/resources", c.baseURL),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusCreated,
	})
	if err != nil {
		return nil, err
	}
	return &response.Resource, nil
}

// GetResourceById retrieves a single resource by ID via the auth server admin API
func (c *AuthServerClient) GetResourceById(ctx context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error) {
	response, err := execute[api.GetResourceResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/resources/%d", c.baseURL, resourceId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Resource, nil
}

// UpdateResource updates an existing resource via the auth server admin API
func (c *AuthServerClient) UpdateResource(ctx context.Context, accessToken string, resourceId int64, request *api.UpdateResourceRequest) (*api.ResourceResponse, error) {
	response, err := execute[api.UpdateResourceResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/resources/%d", c.baseURL, resourceId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Resource, nil
}

// DeleteResource deletes a resource via the auth server admin API
func (c *AuthServerClient) DeleteResource(ctx context.Context, accessToken string, resourceId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           fmt.Sprintf("%s/api/v1/admin/resources/%d", c.baseURL, resourceId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}
