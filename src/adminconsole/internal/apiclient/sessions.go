package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

func (c *AuthServerClient) GetUserSessionsByUserID(ctx context.Context, accessToken string, userID int64) ([]api.UserSessionDetailResponse, error) {
	response, err := execute[api.GetUserSessionsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userID, 10) + "/sessions",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Sessions, nil
}

// DeleteUserSessionByID returns only an error and still decodes: a 200 carrying `success:false` is
// refused. The same is true of DeleteAccountSession below, and of no other method in this package.
func (c *AuthServerClient) DeleteUserSessionByID(ctx context.Context, accessToken string, sessionID int64) error {
	response, err := execute[api.SuccessResponse](ctx, c, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(sessionID, 10),
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

// GetClientSessionsByClientID answers the whole envelope rather than the sessions alone: this
// endpoint is the only one listing sessions across users, and it returns their owners so the
// caller does not read them back one at a time (#373).
func (c *AuthServerClient) GetClientSessionsByClientID(ctx context.Context, accessToken string, clientID int64, page, size int) (*api.GetClientSessionsResponse, error) {
	// Pagination is defaulted at the caller, so a non-positive page or size is left off the query
	// entirely rather than sent as a zero.
	fullURL := c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientID, 10) + "/sessions"
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

func (c *AuthServerClient) DeleteAccountSession(ctx context.Context, accessToken string, sessionID int64) error {
	response, err := execute[api.SuccessResponse](ctx, c, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/account/sessions/" + strconv.FormatInt(sessionID, 10),
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
