package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetGroupAttributesByGroupId(ctx context.Context, accessToken string, groupId int64) ([]api.GroupAttributeResponse, error) {
	response, err := execute[api.GetGroupAttributesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/groups/" + strconv.FormatInt(groupId, 10) + "/attributes",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Attributes, nil
}

func (c *AuthServerClient) GetGroupAttributeById(ctx context.Context, accessToken string, attributeId int64) (*api.GroupAttributeResponse, error) {
	response, err := execute[api.GetGroupAttributeResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attributeId, 10),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Attribute, nil
}

func (c *AuthServerClient) CreateGroupAttribute(ctx context.Context, accessToken string, request *api.CreateGroupAttributeRequest) (*api.GroupAttributeResponse, error) {
	response, err := execute[api.CreateGroupAttributeResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/admin/group-attributes",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusCreated,
	})
	if err != nil {
		return nil, err
	}
	return &response.Attribute, nil
}

func (c *AuthServerClient) UpdateGroupAttribute(ctx context.Context, accessToken string, attributeId int64, request *api.UpdateGroupAttributeRequest) (*api.GroupAttributeResponse, error) {
	response, err := execute[api.UpdateGroupAttributeResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attributeId, 10),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Attribute, nil
}

func (c *AuthServerClient) DeleteGroupAttribute(ctx context.Context, accessToken string, attributeId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attributeId, 10),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}
