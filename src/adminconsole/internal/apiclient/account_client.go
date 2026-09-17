package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// ProfilePictureUploadResponse represents the response from uploading a profile picture
type ProfilePictureUploadResponse struct {
	Success    bool   `json:"success"`
	PictureUrl string `json:"pictureUrl"`
}

// GetAccountProfile retrieves the current user's profile
func (c *AuthServerClient) GetAccountProfile(accessToken string) (*api.UserResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/profile"

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.GetUserResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.User, nil
}

// UpdateAccountProfile updates the current user's profile
func (c *AuthServerClient) UpdateAccountProfile(accessToken string, request *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/profile"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.User, nil
}

// UpdateAccountEmail updates the current user's email
func (c *AuthServerClient) UpdateAccountEmail(accessToken string, request *api.UpdateAccountEmailRequest) (*api.UserResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/email"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.User, nil
}

// UpdateAccountPhone updates the current user's phone
func (c *AuthServerClient) UpdateAccountPhone(accessToken string, request *api.UpdateAccountPhoneRequest) (*api.UserResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/phone"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.User, nil
}

// UpdateAccountAddress updates the current user's address
func (c *AuthServerClient) UpdateAccountAddress(accessToken string, request *api.UpdateUserAddressRequest) (*api.UserResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/address"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.User, nil
}

// UpdateAccountPassword changes the current user's password
func (c *AuthServerClient) UpdateAccountPassword(accessToken string, request *api.UpdateAccountPasswordRequest) (*api.UserResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/password"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.User, nil
}

// SendAccountEmailVerification triggers sending a verification code to the user's email
func (c *AuthServerClient) SendAccountEmailVerification(accessToken string) (*api.AccountEmailVerificationSendResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/email/verification/send"

	// empty JSON object
	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.AccountEmailVerificationSendResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}

// VerifyAccountEmail sends the verification code to confirm the user's email
func (c *AuthServerClient) VerifyAccountEmail(accessToken string, request *api.VerifyAccountEmailRequest) (*api.UserResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/email/verification"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.User, nil
}

// GetAccountOTPEnrollment generates an OTP enrollment secret and QR for current user
func (c *AuthServerClient) GetAccountOTPEnrollment(accessToken string) (*api.AccountOTPEnrollmentResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/otp/enrollment"

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.AccountOTPEnrollmentResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// UpdateAccountOTP enables or disables OTP for the current user
func (c *AuthServerClient) UpdateAccountOTP(accessToken string, request *api.UpdateAccountOTPRequest) (*api.UserResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/otp"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.User, nil
}

// CreateAccountLogoutRequest asks the auth server to prepare a logout operation. Exactly one of the
// two returns is non-nil, and which one the endpoint chooses is what request.ResponseMode asked for.
//
// The two shapes share no field, so they are told apart by what survived the unmarshal rather than
// by a discriminator: encoding/json fills neither struct from the other's body, and a body that
// fills neither is an error rather than a nil pair, because the caller would otherwise dereference
// whichever it expected.
func (c *AuthServerClient) CreateAccountLogoutRequest(accessToken string, request *api.AccountLogoutRequest) (*api.AccountLogoutFormPostResponse, *api.AccountLogoutRedirectResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/logout-request"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, nil, errs.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, parseAPIError(resp, body)
	}

	// Try to decode as form_post response first
	var formResp api.AccountLogoutFormPostResponse
	if err := json.Unmarshal(body, &formResp); err == nil && formResp.Method != "" && formResp.Endpoint != "" && len(formResp.Params) > 0 {
		return &formResp, nil, nil
	}

	// Fallback: redirect response
	var redirResp api.AccountLogoutRedirectResponse
	if err := json.Unmarshal(body, &redirResp); err == nil && redirResp.LogoutUrl != "" {
		return nil, &redirResp, nil
	}

	return nil, nil, errs.Errorf("unexpected logout-request response format")
}

// GetAccountConsents retrieves the current user's consents
func (c *AuthServerClient) GetAccountConsents(accessToken string) ([]api.UserConsentResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/consents"

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.GetUserConsentsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return response.Consents, nil
}

// RevokeAccountConsent deletes a consent for the current user
func (c *AuthServerClient) RevokeAccountConsent(accessToken string, consentId int64) error {
	fullURL := fmt.Sprintf("%s/api/v1/account/consents/%d", c.baseURL, consentId)

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return errs.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, body)
	}
	return nil
}

// GetAccountProfilePicture retrieves the current user's profile picture info
func (c *AuthServerClient) GetAccountProfilePicture(accessToken string) (*ProfilePictureInfo, error) {
	fullURL := c.baseURL + "/api/v1/account/profile-picture"

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response ProfilePictureInfo
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// UploadAccountProfilePicture uploads a profile picture for the current user
func (c *AuthServerClient) UploadAccountProfilePicture(accessToken string, pictureData []byte, filename string) (*ProfilePictureUploadResponse, error) {
	fullURL := c.baseURL + "/api/v1/account/profile-picture"

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("picture", filename)
	if err != nil {
		return nil, errs.Errorf("failed to create form file: %w", err)
	}

	if _, err := part.Write(pictureData); err != nil {
		return nil, errs.Errorf("failed to write picture data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, errs.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, &buf)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response ProfilePictureUploadResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// DeleteAccountProfilePicture deletes the current user's profile picture
func (c *AuthServerClient) DeleteAccountProfilePicture(accessToken string) error {
	fullURL := c.baseURL + "/api/v1/account/profile-picture"

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, body)
	}

	return nil
}
