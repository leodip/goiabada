package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetAllGroups(ctx context.Context, accessToken string) ([]api.GroupResponse, error) {
	// No Content-Type: this request carries no body and has never set the header.
	response, err := execute[api.GetGroupsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/groups", c.baseURL),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Groups, nil
}

func (c *AuthServerClient) CreateGroup(ctx context.Context, accessToken string, request *api.CreateGroupRequest) (*api.GroupResponse, error) {
	response, err := execute[api.CreateGroupResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           fmt.Sprintf("%s/api/v1/admin/groups", c.baseURL),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusCreated,
	})
	if err != nil {
		return nil, err
	}
	return &response.Group, nil
}

// The member count used to be a second return value, because the models.Group this rebuilt did
// not carry one. api.GroupResponse does, filled by the same handler from the same query, so the
// delete page reads it off the response like every other field (#350).
func (c *AuthServerClient) GetGroupById(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, error) {
	response, err := execute[api.GetGroupResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Group, nil
}

func (c *AuthServerClient) UpdateGroup(ctx context.Context, accessToken string, groupId int64, request *api.UpdateGroupRequest) (*api.GroupResponse, error) {
	response, err := execute[api.UpdateGroupResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Group, nil
}

func (c *AuthServerClient) DeleteGroup(ctx context.Context, accessToken string, groupId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId),
		successStatus: http.StatusOK,
	})
	return err
}

// GetUserGroups answers two values out of one envelope: the user the endpoint resolved and the
// groups it holds. UpdateUserGroups below returns the same envelope for the same reason.
func (c *AuthServerClient) GetUserGroups(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, []api.GroupResponse, error) {
	response, err := execute[api.GetUserGroupsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/users/%d/groups", c.baseURL, userId),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, nil, err
	}
	return &response.User, response.Groups, nil
}

func (c *AuthServerClient) GetGroupMembers(ctx context.Context, accessToken string, groupId int64, page, size int) ([]api.UserResponse, int, error) {
	response, err := execute[api.GetGroupMembersResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/%d/members?page=%d&size=%d", c.baseURL, groupId, page, size),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, 0, err
	}
	return response.Members, response.Total, nil
}

func (c *AuthServerClient) AddUserToGroup(ctx context.Context, accessToken string, groupId int64, userId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "POST",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/%d/members", c.baseURL, groupId),
		jsonBody:      api.AddGroupMemberRequest{UserId: userId},
		contentType:   contentTypeJSON,
		successStatus: http.StatusCreated,
	})
	return err
}

func (c *AuthServerClient) RemoveUserFromGroup(ctx context.Context, accessToken string, groupId int64, userId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/%d/members/%d", c.baseURL, groupId, userId),
		successStatus: http.StatusOK,
	})
	return err
}

func (c *AuthServerClient) SearchUsersWithGroupAnnotation(ctx context.Context, accessToken, query string, groupId int64, page, size int) ([]api.UserWithGroupMembershipResponse, int, error) {
	response, err := execute[api.SearchUsersWithGroupAnnotationResponse](ctx, c, accessToken, apiRequest{
		method: "GET",
		url: fmt.Sprintf("%s/api/v1/admin/users/search?query=%s&annotateGroupMembership=%d&page=%d&size=%d",
			c.baseURL, url.QueryEscape(query), groupId, page, size),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, 0, err
	}
	return response.Users, response.Total, nil
}

// SearchGroupsWithPermissionAnnotation queries groups with a HasPermission flag
// for the given permissionId, using server-side pagination.
func (c *AuthServerClient) SearchGroupsWithPermissionAnnotation(ctx context.Context, accessToken string, permissionId int64, page, size int) ([]api.GroupWithPermissionResponse, int, error) {
	response, err := execute[api.SearchGroupsWithPermissionAnnotationResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/groups/search?annotatePermissionId=%d&page=%d&size=%d", c.baseURL, permissionId, page, size),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, 0, err
	}
	return response.Groups, response.Total, nil
}

func (c *AuthServerClient) UpdateUserGroups(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserGroupsRequest) (*api.UserResponse, []api.GroupResponse, error) {
	response, err := execute[api.GetUserGroupsResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/users/%d/groups", c.baseURL, userId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, nil, err
	}
	return &response.User, response.Groups, nil
}
