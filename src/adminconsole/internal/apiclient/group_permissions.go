package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

// GetGroupPermissions answers two values out of one envelope: the group the endpoint resolved and
// the permissions it holds.
func (c *AuthServerClient) GetGroupPermissions(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, []api.PermissionResponse, error) {
	response, err := execute[api.GetGroupPermissionsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/%d/permissions", c.baseURL, groupId),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, nil, err
	}
	return &response.Group, response.Permissions, nil
}

func (c *AuthServerClient) UpdateGroupPermissions(ctx context.Context, accessToken string, groupId int64, request *api.UpdateGroupPermissionsRequest) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/%d/permissions", c.baseURL, groupId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}
