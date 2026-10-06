package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
)

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

// GetClientSecret reads a client's secret, decrypted, from the one route that answers it; the
// client detail carries none (#403). It accepts 200 alone, as the methods written since the range
// above do.
func (c *AuthServerClient) GetClientSecret(ctx context.Context, accessToken string, clientId int64) (string, error) {
	response, err := execute[api.GetClientSecretResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/secret",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return "", err
	}
	return response.ClientSecret, nil
}

// UpdateClientAdministrativeScopes switches whether a client may request the administrative
// authserver scopes, on the one route that changes it, and answers the client as it now is (#499
// decision 5). It accepts 200 alone, as GetClientSecret above does.
func (c *AuthServerClient) UpdateClientAdministrativeScopes(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error) {
	response, err := execute[api.UpdateClientResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/administrative-scopes",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Client, nil
}

// The three logo methods are the exception in this file: each accepts 200 alone, as it was
// written.

func (c *AuthServerClient) GetClientLogo(ctx context.Context, accessToken string, clientId int64) (*api.ClientLogoInfoResponse, error) {
	// Decoded straight into api.ClientLogoInfoResponse: this endpoint answers the object itself
	// rather than wrapping it in an envelope.
	return execute[api.ClientLogoInfoResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/logo",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) UploadClientLogo(ctx context.Context, accessToken string, clientId int64, logoData []byte, filename string) (*api.ClientLogoUploadResponse, error) {
	body, contentType, err := multipartPicture(filename, logoData)
	if err != nil {
		return nil, err
	}

	return execute[api.ClientLogoUploadResponse](ctx, c, accessToken, apiRequest{
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
