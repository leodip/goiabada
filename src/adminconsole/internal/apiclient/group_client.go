package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

func (c *AuthServerClient) GetAllGroups(accessToken string) ([]api.GroupResponse, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups", c.baseURL)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, errs.Errorf("failed to unmarshal response: %w", err)
	}

	return apiResp.Groups, nil
}

func (c *AuthServerClient) CreateGroup(accessToken string, request *api.CreateGroupRequest) (*api.GroupResponse, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups", c.baseURL)
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, parseAPIError(resp, respBody)
	}

	var createResp api.CreateGroupResponse
	if err := json.Unmarshal(respBody, &createResp); err != nil {
		return nil, errs.Errorf("failed to unmarshal response: %w", err)
	}

	return &createResp.Group, nil
}

// The member count used to be a second return value, because the models.Group this rebuilt did
// not carry one. api.GroupResponse does, filled by the same handler from the same query, so the
// delete page reads it off the response like every other field (#350).
func (c *AuthServerClient) GetGroupById(accessToken string, groupId int64) (*api.GroupResponse, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var getResp api.GetGroupResponse
	if err := json.Unmarshal(respBody, &getResp); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &getResp.Group, nil
}

func (c *AuthServerClient) UpdateGroup(accessToken string, groupId int64, request *api.UpdateGroupRequest) (*api.GroupResponse, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId)

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var updateResp api.UpdateGroupResponse
	if err := json.Unmarshal(respBody, &updateResp); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &updateResp.Group, nil
}

func (c *AuthServerClient) DeleteGroup(accessToken string, groupId int64) error {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId)

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, respBody)
	}

	return nil
}

func (c *AuthServerClient) GetUserGroups(accessToken string, userId int64) (*api.UserResponse, []api.GroupResponse, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/users/%d/groups", c.baseURL, userId)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetUserGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, nil, errs.Errorf("failed to unmarshal response: %w", err)
	}

	return &apiResp.User, apiResp.Groups, nil
}

func (c *AuthServerClient) GetGroupMembers(accessToken string, groupId int64, page, size int) ([]api.UserResponse, int, error) {

	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d/members?page=%d&size=%d", c.baseURL, groupId, page, size)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, 0, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, 0, parseAPIError(resp, respBody)
	}

	var apiResp api.GetGroupMembersResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, 0, errs.Errorf("failed to unmarshal response: %w", err)
	}

	return apiResp.Members, apiResp.Total, nil
}

func (c *AuthServerClient) AddUserToGroup(accessToken string, groupId int64, userId int64) error {

	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d/members", c.baseURL, groupId)

	request := api.AddGroupMemberRequest{
		UserId: userId,
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return parseAPIError(resp, respBody)
	}

	return nil
}

func (c *AuthServerClient) RemoveUserFromGroup(accessToken string, groupId int64, userId int64) error {

	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d/members/%d", c.baseURL, groupId, userId)

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, respBody)
	}

	return nil
}

func (c *AuthServerClient) SearchUsersWithGroupAnnotation(accessToken, query string, groupId int64, page, size int) ([]api.UserWithGroupMembershipResponse, int, error) {

	fullURL := fmt.Sprintf("%s/api/v1/admin/users/search?query=%s&annotateGroupMembership=%d&page=%d&size=%d",
		c.baseURL, url.QueryEscape(query), groupId, page, size)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, 0, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, 0, parseAPIError(resp, respBody)
	}

	var apiResp api.SearchUsersWithGroupAnnotationResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, 0, errs.Errorf("failed to unmarshal response: %w", err)
	}

	return apiResp.Users, apiResp.Total, nil
}

// SearchGroupsWithPermissionAnnotation queries groups with a HasPermission flag
// for the given permissionId, using server-side pagination.
func (c *AuthServerClient) SearchGroupsWithPermissionAnnotation(accessToken string, permissionId int64, page, size int) ([]api.GroupWithPermissionResponse, int, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/search?annotatePermissionId=%d&page=%d&size=%d", c.baseURL, permissionId, page, size)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, 0, errs.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, errs.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, parseAPIError(resp, body)
	}

	var apiResp api.SearchGroupsWithPermissionAnnotationResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, 0, errs.Errorf("failed to unmarshal response: %w", err)
	}

	return apiResp.Groups, apiResp.Total, nil
}

func (c *AuthServerClient) UpdateUserGroups(accessToken string, userId int64, request *api.UpdateUserGroupsRequest) (*api.UserResponse, []api.GroupResponse, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/users/%d/groups", c.baseURL, userId)

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetUserGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, nil, errs.Errorf("failed to unmarshal response: %w", err)
	}

	return &apiResp.User, apiResp.Groups, nil
}
