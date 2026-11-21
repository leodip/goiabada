package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// GetUserConnectedClients retrieves the clients a user is connected to: each one the user holds a
// stored consent with or a live refresh token with.
func (c *AuthServerClient) GetUserConnectedClients(ctx context.Context, accessToken string, userID int64) ([]api.ConnectedClientResponse, error) {
	response, err := execute[api.GetConnectedClientsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/users/%d/connected-clients", c.baseURL, userID),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Clients, nil
}

// DisconnectUserClient disconnects a user from a client, ending everything the user holds with
// it, its stored consent included.
func (c *AuthServerClient) DisconnectUserClient(ctx context.Context, accessToken string, userID, clientID int64) error {
	response, err := execute[api.SuccessResponse](ctx, c, accessToken, apiRequest{
		method:        "DELETE",
		url:           fmt.Sprintf("%s/api/v1/admin/users/%d/connected-clients/%d", c.baseURL, userID, clientID),
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
