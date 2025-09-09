package apiclient

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"

    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/models"
)

// GetAccountProfile retrieves the current user's profile
func (c *AuthServerClient) GetAccountProfile(accessToken string) (*models.User, error) {
    fullURL := c.baseURL + "/api/v1/account/profile"

    req, err := http.NewRequest("GET", fullURL, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var response api.GetUserResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return response.User.ToUser(), nil
}

// UpdateAccountProfile updates the current user's profile
func (c *AuthServerClient) UpdateAccountProfile(accessToken string, request *api.UpdateUserProfileRequest) (*models.User, error) {
    fullURL := c.baseURL + "/api/v1/account/profile"

    jsonData, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var response api.UpdateUserResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return response.User.ToUser(), nil
}

// UpdateAccountEmail updates the current user's email
func (c *AuthServerClient) UpdateAccountEmail(accessToken string, request *api.UpdateAccountEmailRequest) (*models.User, error) {
    fullURL := c.baseURL + "/api/v1/account/email"

    jsonData, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var response api.UpdateUserResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return response.User.ToUser(), nil
}

// UpdateAccountPhone updates the current user's phone
func (c *AuthServerClient) UpdateAccountPhone(accessToken string, request *api.UpdateAccountPhoneRequest) (*models.User, error) {
    fullURL := c.baseURL + "/api/v1/account/phone"

    jsonData, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var response api.UpdateUserResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return response.User.ToUser(), nil
}

// UpdateAccountAddress updates the current user's address
func (c *AuthServerClient) UpdateAccountAddress(accessToken string, request *api.UpdateUserAddressRequest) (*models.User, error) {
    fullURL := c.baseURL + "/api/v1/account/address"

    jsonData, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var response api.UpdateUserResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return response.User.ToUser(), nil
}

// UpdateAccountPassword changes the current user's password
func (c *AuthServerClient) UpdateAccountPassword(accessToken string, request *api.UpdateAccountPasswordRequest) (*models.User, error) {
    fullURL := c.baseURL + "/api/v1/account/password"

    jsonData, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var response api.UpdateUserResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return response.User.ToUser(), nil
}

// GetAccountOTPEnrollment generates an OTP enrollment secret and QR for current user
func (c *AuthServerClient) GetAccountOTPEnrollment(accessToken string) (*api.AccountOTPEnrollmentResponse, error) {
    fullURL := c.baseURL + "/api/v1/account/otp/enrollment"

    req, err := http.NewRequest("GET", fullURL, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var response api.AccountOTPEnrollmentResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return &response, nil
}

// UpdateAccountOTP enables or disables OTP for the current user
func (c *AuthServerClient) UpdateAccountOTP(accessToken string, request *api.UpdateAccountOTPRequest) (*models.User, error) {
    fullURL := c.baseURL + "/api/v1/account/otp"

    jsonData, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var response api.UpdateUserResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return response.User.ToUser(), nil
}
