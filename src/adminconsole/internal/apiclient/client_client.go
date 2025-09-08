package apiclient

import (
    "encoding/json"
    "fmt"
    "io"
    "bytes"
    "net/http"
    "strconv"

    "github.com/leodip/goiabada/core/api"
)

func (c *AuthServerClient) GetAllClients(accessToken string) ([]api.ClientResponse, error) {
	// Build URL
	fullURL := c.baseURL + "/api/v1/admin/clients"

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle non-2xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp, body)
	}

	// Parse response
	var response api.GetClientsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response.Clients, nil
}

func (c *AuthServerClient) GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error) {
	// Build URL
	fullURL := c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10)

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle non-2xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp, body)
	}

	// Parse response
	var response api.GetClientResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response.Client, nil
}

func (c *AuthServerClient) CreateClient(accessToken string, request *api.CreateClientRequest) (*api.ClientResponse, error) {
    // Build URL
    fullURL := c.baseURL + "/api/v1/admin/clients"

    // Marshal request body
    bodyBytes, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    // Create request
    req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(bodyBytes))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    // Set headers
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    // Make request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    // Handle non-2xx responses
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return nil, parseAPIError(resp, body)
    }

    // Parse response
    var response api.CreateClientResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }

    return &response.Client, nil
}

func (c *AuthServerClient) UpdateClient(accessToken string, clientId int64, request *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
    // Build URL
    fullURL := c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10)

    // Marshal request body
    bodyBytes, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    // Create request
    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(bodyBytes))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    // Set headers
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    // Make request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    // Handle non-2xx responses
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return nil, parseAPIError(resp, body)
    }

    // Parse response
    var response api.UpdateClientResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }

    return &response.Client, nil
}

func (c *AuthServerClient) UpdateClientAuthentication(accessToken string, clientId int64, request *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error) {
    // Build URL
    fullURL := c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/authentication"

    // Marshal request body
    bodyBytes, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    // Create request
    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(bodyBytes))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    // Set headers
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    // Make request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    // Handle non-2xx responses
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return nil, parseAPIError(resp, body)
    }

    // Parse response
    var response api.UpdateClientResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }

    return &response.Client, nil
}

func (c *AuthServerClient) UpdateClientOAuth2Flows(accessToken string, clientId int64, request *api.UpdateClientOAuth2FlowsRequest) (*api.ClientResponse, error) {
    // Build URL
    fullURL := c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/oauth2-flows"

    // Marshal request body
    bodyBytes, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    // Create request
    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(bodyBytes))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    // Set headers
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    // Make request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    // Handle non-2xx responses
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return nil, parseAPIError(resp, body)
    }

    // Parse response
    var response api.UpdateClientResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }

    return &response.Client, nil
}

func (c *AuthServerClient) DeleteClient(accessToken string, clientId int64) error {
    // Build URL
    fullURL := c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10)

    // Create request
    req, err := http.NewRequest("DELETE", fullURL, nil)
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    // Set headers
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    // Make request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read response body: %w", err)
    }

    // Handle non-2xx responses
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return parseAPIError(resp, body)
    }

    return nil
}
