package apiclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/leodip/goiabada/core/api"
)

// ProfilePictureUploadResponse is defined in account_client.go

func (c *AuthServerClient) SearchUsersPaginated(ctx context.Context, accessToken, query string, page, pageSize int) ([]api.UserResponse, int, error) {
	// url.Values.Encode sorts its keys, so the query this endpoint has always been sent is
	// page, then query, then size, whatever order they are added in.
	params := url.Values{}
	params.Add("page", strconv.Itoa(page))
	params.Add("size", strconv.Itoa(pageSize))
	if query != "" {
		params.Add("query", query)
	}

	response, err := execute[api.SearchUsersResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/users/search?" + params.Encode(),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, 0, err
	}
	return response.Users, response.Total, nil
}

func (c *AuthServerClient) GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error) {
	response, err := execute[api.GetUserResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

func (c *AuthServerClient) UpdateUserEnabled(ctx context.Context, accessToken string, userId int64, enabled bool) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/enabled",
		jsonBody:      api.UpdateUserEnabledRequest{Enabled: enabled},
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

func (c *AuthServerClient) UpdateUserProfile(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/profile",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

func (c *AuthServerClient) UpdateUserAddress(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserAddressRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/address",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

func (c *AuthServerClient) UpdateUserEmail(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserEmailRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/email",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

func (c *AuthServerClient) UpdateUserPassword(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserPasswordRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/password",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

func (c *AuthServerClient) UpdateUserOTP(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserOTPRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/otp",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

func (c *AuthServerClient) CreateUserAdmin(ctx context.Context, accessToken string, request *api.CreateUserAdminRequest) (*api.UserResponse, error) {
	response, err := execute[api.CreateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/admin/users/create",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusCreated,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

// ProfilePictureInfo contains profile picture metadata
type ProfilePictureInfo struct {
	HasPicture bool   `json:"hasPicture"`
	PictureUrl string `json:"pictureUrl,omitempty"`
}

func (c *AuthServerClient) GetUserProfilePicture(ctx context.Context, accessToken string, userId int64) (*ProfilePictureInfo, error) {
	return execute[ProfilePictureInfo](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/profile-picture",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// UploadUserProfilePicture uploads a profile picture for a user (admin)
func (c *AuthServerClient) UploadUserProfilePicture(ctx context.Context, accessToken string, userId int64, pictureData []byte, filename string) (*ProfilePictureUploadResponse, error) {
	body, contentType, err := multipartPicture(filename, pictureData)
	if err != nil {
		return nil, err
	}

	return execute[ProfilePictureUploadResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/profile-picture",
		rawBody:       body,
		contentType:   contentType,
		successStatus: http.StatusOK,
	})
}

// DeleteUserProfilePicture deletes a user's profile picture (admin)
func (c *AuthServerClient) DeleteUserProfilePicture(ctx context.Context, accessToken string, userId int64) error {
	// No Content-Type: this request carries no body, and the header it never set is left unset.
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/profile-picture",
		successStatus: http.StatusOK,
	})
	return err
}

func (c *AuthServerClient) DeleteUser(ctx context.Context, accessToken string, userId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}
