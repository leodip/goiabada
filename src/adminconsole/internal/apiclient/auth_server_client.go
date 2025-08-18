package apiclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
)

type ApiClient interface {
	SearchUsersPaginated(accessToken, query string, page, pageSize int) ([]models.User, int, error)
}

type AuthServerClient struct {
	baseURL    string
	httpClient *http.Client
}

type UsersSearchResponse struct {
	Users []models.User `json:"users"`
	Total int           `json:"total"`
	Page  int           `json:"page"`
	Size  int           `json:"size"`
	Query string        `json:"query"`
}

func NewAuthServerClient() *AuthServerClient {
	authServerBaseURL := config.GetAuthServer().BaseURL

	return &AuthServerClient{
		baseURL:    authServerBaseURL,
		httpClient: &http.Client{},
	}
}

func (c *AuthServerClient) SearchUsersPaginated(accessToken, query string, page, pageSize int) ([]models.User, int, error) {
	// Build URL with query parameters
	fullURL := c.baseURL + "/api/v1/admin/users/search"
	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse URL: %w", err)
	}

	params := url.Values{}
	params.Add("page", strconv.Itoa(page))
	params.Add("size", strconv.Itoa(pageSize))
	if query != "" {
		params.Add("query", query)
	}
	u.RawQuery = params.Encode()

	// Create request
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response UsersSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, 0, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Users, response.Total, nil
}
