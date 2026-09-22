package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

func (c *AuthServerClient) GetUserSessionsByUserId(ctx context.Context, accessToken string, userId int64) ([]api.UserSessionDetailResponse, error) {
	response, err := execute[api.GetUserSessionsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/sessions",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Sessions, nil
}

// DeleteUserSessionById returns only an error and still decodes: a 200 carrying `success:false` is
// refused. The same is true of DeleteAccountSession below, and of no other method in this package.
func (c *AuthServerClient) DeleteUserSessionById(ctx context.Context, accessToken string, sessionId int64) error {
	response, err := execute[api.SuccessResponse](ctx, c, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(sessionId, 10),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return err
	}
	if !response.Success {
		return errs.Errorf("API returned success=false")
	}
	return nil
}

// GetClientSessionsByClientId answers the whole envelope rather than the sessions alone: this
// endpoint is the only one listing sessions across users, and it returns their owners so the
// caller does not read them back one at a time (#373).
func (c *AuthServerClient) GetClientSessionsByClientId(ctx context.Context, accessToken string, clientId int64, page, size int) (*api.GetClientSessionsResponse, error) {
	// Pagination is defaulted at the caller, so a non-positive page or size is left off the query
	// entirely rather than sent as a zero.
	fullURL := c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/sessions"
	if page > 0 || size > 0 {
		q := "?"
		if page > 0 {
			q += "page=" + strconv.Itoa(page)
		}
		if size > 0 {
			if page > 0 {
				q += "&"
			}
			q += "size=" + strconv.Itoa(size)
		}
		fullURL += q
	}

	return execute[api.GetClientSessionsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fullURL,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) GetAccountSessions(ctx context.Context, accessToken string) ([]api.UserSessionDetailResponse, error) {
	response, err := execute[api.GetUserSessionsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/account/sessions",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Sessions, nil
}

func (c *AuthServerClient) DeleteAccountSession(ctx context.Context, accessToken string, sessionId int64) error {
	response, err := execute[api.SuccessResponse](ctx, c, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/account/sessions/" + strconv.FormatInt(sessionId, 10),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return err
	}
	if !response.Success {
		return errs.Errorf("API returned success=false")
	}
	return nil
}

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
