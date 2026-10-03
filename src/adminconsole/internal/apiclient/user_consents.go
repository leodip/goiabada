package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetUserConsents(ctx context.Context, accessToken string, userId int64) ([]api.UserConsentResponse, error) {
	response, err := execute[api.GetUserConsentsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/users/%d/consents", c.baseURL, userId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Consents, nil
}

func (c *AuthServerClient) DeleteUserConsent(ctx context.Context, accessToken string, consentId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           fmt.Sprintf("%s/api/v1/admin/user-consents/%d", c.baseURL, consentId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}
