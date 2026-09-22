package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetUserAttributesByUserId(ctx context.Context, accessToken string, userId int64) ([]api.UserAttributeResponse, error) {
	response, err := execute[api.GetUserAttributesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/attributes",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Attributes, nil
}

func (c *AuthServerClient) GetUserAttributeById(ctx context.Context, accessToken string, attributeId int64) (*api.UserAttributeResponse, error) {
	response, err := execute[api.GetUserAttributeResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Attribute, nil
}

func (c *AuthServerClient) CreateUserAttribute(ctx context.Context, accessToken string, request *api.CreateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	response, err := execute[api.CreateUserAttributeResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/admin/user-attributes",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusCreated,
	})
	if err != nil {
		return nil, err
	}
	return &response.Attribute, nil
}

func (c *AuthServerClient) UpdateUserAttribute(ctx context.Context, accessToken string, attributeId int64, request *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	response, err := execute[api.UpdateUserAttributeResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Attribute, nil
}

func (c *AuthServerClient) DeleteUserAttribute(ctx context.Context, accessToken string, attributeId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}
