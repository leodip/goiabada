package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/api"
)

// GetUserPermissions retrieves user permissions from the auth server, two values out of one
// envelope: the user the endpoint resolved and the permissions it holds.
func (c *AuthServerClient) GetUserPermissions(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, []api.PermissionResponse, error) {
	response, err := execute[api.GetUserPermissionsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/users/%d/permissions", c.baseURL, userId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, nil, err
	}
	return &response.User, response.Permissions, nil
}

// UpdateUserPermissions updates user permissions via the auth server
func (c *AuthServerClient) UpdateUserPermissions(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserPermissionsRequest) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/users/%d/permissions", c.baseURL, userId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}

// GetAllResources retrieves all resources from the auth server
func (c *AuthServerClient) GetAllResources(ctx context.Context, accessToken string) ([]api.ResourceResponse, error) {
	response, err := execute[api.GetResourcesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/resources", c.baseURL),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Resources, nil
}

// GetPermissionsByResource retrieves permissions for a specific resource from the auth server
func (c *AuthServerClient) GetPermissionsByResource(ctx context.Context, accessToken string, resourceId int64) ([]api.PermissionResponse, error) {
	response, err := execute[api.GetPermissionsByResourceResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/resources/%d/permissions", c.baseURL, resourceId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Permissions, nil
}

// UpdateResourcePermissions replaces the full set of permission definitions for a resource
func (c *AuthServerClient) UpdateResourcePermissions(ctx context.Context, accessToken string, resourceId int64, request *api.UpdateResourcePermissionsRequest) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/resources/%d/permissions", c.baseURL, resourceId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}

// GetUsersByPermission retrieves users that have the given permission with pagination
func (c *AuthServerClient) GetUsersByPermission(ctx context.Context, accessToken string, permissionId int64, page, size int) ([]api.UserResponse, int, error) {
	response, err := execute[api.GetUsersByPermissionResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/permissions/%d/users?page=%d&size=%d", c.baseURL, permissionId, page, size),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, 0, err
	}
	return response.Users, response.Total, nil
}

// SearchUsersWithPermissionAnnotation searches users and annotates with HasPermission for a permissionId
func (c *AuthServerClient) SearchUsersWithPermissionAnnotation(ctx context.Context, accessToken string, permissionId int64, query string, page, size int) ([]api.UserWithPermissionResponse, int, error) {
	base := fmt.Sprintf("%s/api/v1/admin/users/search?annotatePermissionId=%d&page=%d&size=%d", c.baseURL, permissionId, page, size)
	if query != "" {
		base = base + "&query=" + url.QueryEscape(query)
	}

	// No Content-Type: this request carries no body and has never set the header.
	response, err := execute[api.SearchUsersWithPermissionAnnotationResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           base,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, 0, err
	}
	return response.Users, response.Total, nil
}
