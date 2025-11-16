package apiclient

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/models"
)

func (c *AuthServerClient) GetAllGroups(accessToken string) ([]models.Group, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups", c.baseURL)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	groups := make([]models.Group, len(apiResp.Groups))
	for i, groupResp := range apiResp.Groups {
		group := models.Group{
			Id:                   groupResp.Id,
			GroupIdentifier:      groupResp.GroupIdentifier,
			Description:          groupResp.Description,
			IncludeInIdToken:     groupResp.IncludeInIdToken,
			IncludeInAccessToken: groupResp.IncludeInAccessToken,
			MemberCount:          groupResp.MemberCount,
		}

		if groupResp.CreatedAt != nil {
			group.CreatedAt = sql.NullTime{Time: *groupResp.CreatedAt, Valid: true}
		}
		if groupResp.UpdatedAt != nil {
			group.UpdatedAt = sql.NullTime{Time: *groupResp.UpdatedAt, Valid: true}
		}

		groups[i] = group
	}

	return groups, nil
}

func (c *AuthServerClient) CreateGroup(accessToken string, request *api.CreateGroupRequest) (*models.Group, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups", c.baseURL)
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, parseAPIError(resp, respBody)
	}

	var createResp api.CreateGroupResponse
	if err := json.Unmarshal(respBody, &createResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Convert response to model
	group := models.Group{
		Id:                   createResp.Group.Id,
		GroupIdentifier:      createResp.Group.GroupIdentifier,
		Description:          createResp.Group.Description,
		IncludeInIdToken:     createResp.Group.IncludeInIdToken,
		IncludeInAccessToken: createResp.Group.IncludeInAccessToken,
	}

	if createResp.Group.CreatedAt != nil {
		group.CreatedAt = sql.NullTime{Time: *createResp.Group.CreatedAt, Valid: true}
	}
	if createResp.Group.UpdatedAt != nil {
		group.UpdatedAt = sql.NullTime{Time: *createResp.Group.UpdatedAt, Valid: true}
	}

	return &group, nil
}

func (c *AuthServerClient) GetGroupById(accessToken string, groupId int64) (*models.Group, int, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, 0, parseAPIError(resp, respBody)
	}

	var getResp api.GetGroupResponse
	if err := json.Unmarshal(respBody, &getResp); err != nil {
		return nil, 0, fmt.Errorf("failed to decode response: %w", err)
	}

	group := models.Group{
		Id:                   getResp.Group.Id,
		GroupIdentifier:      getResp.Group.GroupIdentifier,
		Description:          getResp.Group.Description,
		IncludeInIdToken:     getResp.Group.IncludeInIdToken,
		IncludeInAccessToken: getResp.Group.IncludeInAccessToken,
	}

	if getResp.Group.CreatedAt != nil {
		group.CreatedAt = sql.NullTime{Time: *getResp.Group.CreatedAt, Valid: true}
	}
	if getResp.Group.UpdatedAt != nil {
		group.UpdatedAt = sql.NullTime{Time: *getResp.Group.UpdatedAt, Valid: true}
	}

	return &group, getResp.Group.MemberCount, nil
}

func (c *AuthServerClient) UpdateGroup(accessToken string, groupId int64, request *api.UpdateGroupRequest) (*models.Group, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId)

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}


	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var updateResp api.UpdateGroupResponse
	if err := json.Unmarshal(respBody, &updateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	group := models.Group{
		Id:                   updateResp.Group.Id,
		GroupIdentifier:      updateResp.Group.GroupIdentifier,
		Description:          updateResp.Group.Description,
		IncludeInIdToken:     updateResp.Group.IncludeInIdToken,
		IncludeInAccessToken: updateResp.Group.IncludeInAccessToken,
	}

	if updateResp.Group.CreatedAt != nil {
		group.CreatedAt = sql.NullTime{Time: *updateResp.Group.CreatedAt, Valid: true}
	}
	if updateResp.Group.UpdatedAt != nil {
		group.UpdatedAt = sql.NullTime{Time: *updateResp.Group.UpdatedAt, Valid: true}
	}

	return &group, nil
}

func (c *AuthServerClient) DeleteGroup(accessToken string, groupId int64) error {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d", c.baseURL, groupId)


	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, respBody)
	}

	return nil
}

func (c *AuthServerClient) GetUserGroups(accessToken string, userId int64) (*models.User, []models.Group, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/users/%d/groups", c.baseURL, userId)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetUserGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	user := apiResp.User.ToUser()
	groups := make([]models.Group, len(apiResp.Groups))
	for i, groupResp := range apiResp.Groups {
		group := models.Group{
			Id:                   groupResp.Id,
			GroupIdentifier:      groupResp.GroupIdentifier,
			Description:          groupResp.Description,
			IncludeInIdToken:     groupResp.IncludeInIdToken,
			IncludeInAccessToken: groupResp.IncludeInAccessToken,
		}

		if groupResp.CreatedAt != nil {
			group.CreatedAt = sql.NullTime{Time: *groupResp.CreatedAt, Valid: true}
		}
		if groupResp.UpdatedAt != nil {
			group.UpdatedAt = sql.NullTime{Time: *groupResp.UpdatedAt, Valid: true}
		}

		groups[i] = group
	}

	return user, groups, nil
}

func (c *AuthServerClient) GetGroupMembers(accessToken string, groupId int64, page, size int) ([]models.User, int, error) {

	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d/members?page=%d&size=%d", c.baseURL, groupId, page, size)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}


	if resp.StatusCode != http.StatusOK {
		return nil, 0, parseAPIError(resp, respBody)
	}

	var apiResp api.GetGroupMembersResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	members := make([]models.User, len(apiResp.Members))
	for i, memberResp := range apiResp.Members {
		if user := memberResp.ToUser(); user != nil {
			members[i] = *user
		}
	}

	return members, apiResp.Total, nil
}

func (c *AuthServerClient) AddUserToGroup(accessToken string, groupId int64, userId int64) error {

	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d/members", c.baseURL, groupId)

	request := api.AddGroupMemberRequest{
		UserId: userId,
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
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
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
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
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}


	if resp.StatusCode != http.StatusOK {
		return nil, 0, parseAPIError(resp, respBody)
	}

	var apiResp api.SearchUsersWithGroupAnnotationResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return apiResp.Users, apiResp.Total, nil
}

// SearchGroupsWithPermissionAnnotation queries groups with a HasPermission flag
// for the given permissionId, using server-side pagination.
func (c *AuthServerClient) SearchGroupsWithPermissionAnnotation(accessToken string, permissionId int64, page, size int) ([]api.GroupWithPermissionResponse, int, error) {
    fullURL := fmt.Sprintf("%s/api/v1/admin/groups/search?annotatePermissionId=%d&page=%d&size=%d", c.baseURL, permissionId, page, size)

    req, err := http.NewRequest("GET", fullURL, nil)
    if err != nil {
        return nil, 0, fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, 0, fmt.Errorf("failed to make request: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, 0, fmt.Errorf("failed to read response body: %w", err)
    }
    if resp.StatusCode != http.StatusOK {
        return nil, 0, parseAPIError(resp, body)
    }

    var apiResp api.SearchGroupsWithPermissionAnnotationResponse
    if err := json.Unmarshal(body, &apiResp); err != nil {
        return nil, 0, fmt.Errorf("failed to unmarshal response: %w", err)
    }

    return apiResp.Groups, apiResp.Total, nil
}

func (c *AuthServerClient) UpdateUserGroups(accessToken string, userId int64, request *api.UpdateUserGroupsRequest) (*models.User, []models.Group, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/users/%d/groups", c.baseURL, userId)

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetUserGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	user := apiResp.User.ToUser()
	groups := make([]models.Group, len(apiResp.Groups))
	for i, groupResp := range apiResp.Groups {
		group := models.Group{
			Id:                   groupResp.Id,
			GroupIdentifier:      groupResp.GroupIdentifier,
			Description:          groupResp.Description,
			IncludeInIdToken:     groupResp.IncludeInIdToken,
			IncludeInAccessToken: groupResp.IncludeInAccessToken,
		}

		if groupResp.CreatedAt != nil {
			group.CreatedAt = sql.NullTime{Time: *groupResp.CreatedAt, Valid: true}
		}
		if groupResp.UpdatedAt != nil {
			group.UpdatedAt = sql.NullTime{Time: *groupResp.UpdatedAt, Valid: true}
		}

		groups[i] = group
	}

	return user, groups, nil
}
