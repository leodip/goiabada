package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
)

// ClientLogoInfo contains client logo metadata
type ClientLogoInfo struct {
	HasLogo bool   `json:"hasLogo"`
	LogoUrl string `json:"logoUrl,omitempty"`
}

// ClientLogoUploadResponse represents the response from uploading a client logo
type ClientLogoUploadResponse struct {
	Success    bool   `json:"success"`
	PictureUrl string `json:"pictureUrl"`
}

// The ten methods below accept the whole 2xx range rather than one status, which is how they were
// written and what their characterization rows record. The rest of the client names the single
// status it expects; these keep the range because narrowing one would refuse an answer the auth
// server is free to give today.

func (c *AuthServerClient) GetAllClients(ctx context.Context, accessToken string) ([]api.ClientResponse, error) {
	response, err := execute[api.GetClientsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/clients",
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return response.Clients, nil
}

func (c *AuthServerClient) GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error) {
	response, err := execute[api.GetClientResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10),
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

func (c *AuthServerClient) CreateClient(ctx context.Context, accessToken string, request *api.CreateClientRequest) (*api.ClientResponse, error) {
	response, err := execute[api.CreateClientResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/admin/clients",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

func (c *AuthServerClient) UpdateClient(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	response, err := execute[api.UpdateClientResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

func (c *AuthServerClient) UpdateClientAuthentication(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error) {
	response, err := execute[api.UpdateClientResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/authentication",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

func (c *AuthServerClient) UpdateClientOAuth2Flows(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientOAuth2FlowsRequest) (*api.ClientResponse, error) {
	response, err := execute[api.UpdateClientResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/oauth2-flows",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

// UpdateClientRedirectURIs updates the full set of redirect URIs for a client.
func (c *AuthServerClient) UpdateClientRedirectURIs(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientRedirectURIsRequest) (*api.ClientResponse, error) {
	response, err := execute[api.UpdateClientResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/redirect-uris",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

// UpdateClientWebOrigins updates the full set of web origins for a client.
func (c *AuthServerClient) UpdateClientWebOrigins(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientWebOriginsRequest) (*api.ClientResponse, error) {
	response, err := execute[api.UpdateClientResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/web-origins",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

// UpdateClientTokens updates token-related settings for a client.
func (c *AuthServerClient) UpdateClientTokens(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	response, err := execute[api.UpdateClientResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/tokens",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

func (c *AuthServerClient) DeleteClient(ctx context.Context, accessToken string, clientId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10),
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	return err
}

// The three logo methods are the exception in this file: each accepts 200 alone, as it was
// written.

func (c *AuthServerClient) GetClientLogo(ctx context.Context, accessToken string, clientId int64) (*ClientLogoInfo, error) {
	// Decoded straight into ClientLogoInfo: this endpoint answers the object itself rather than
	// wrapping it in an envelope.
	return execute[ClientLogoInfo](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/logo",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) UploadClientLogo(ctx context.Context, accessToken string, clientId int64, logoData []byte, filename string) (*ClientLogoUploadResponse, error) {
	body, contentType, err := multipartPicture(filename, logoData)
	if err != nil {
		return nil, err
	}

	return execute[ClientLogoUploadResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/logo",
		rawBody:       body,
		contentType:   contentType,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) DeleteClientLogo(ctx context.Context, accessToken string, clientId int64) error {
	// No Content-Type: this request carries no body and has never set the header.
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/logo",
		successStatus: http.StatusOK,
	})
	return err
}
