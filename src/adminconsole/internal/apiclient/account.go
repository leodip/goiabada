package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// GetAccountProfile retrieves the current user's profile
func (c *AuthServerClient) GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error) {
	response, err := execute[api.GetUserResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/account/profile",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

// UpdateAccountProfile updates the current user's profile
func (c *AuthServerClient) UpdateAccountProfile(ctx context.Context, accessToken string, request *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/account/profile",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

// UpdateAccountEmail updates the current user's email
func (c *AuthServerClient) UpdateAccountEmail(ctx context.Context, accessToken string, request *api.UpdateAccountEmailRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/account/email",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

// UpdateAccountPhone updates the current user's phone
func (c *AuthServerClient) UpdateAccountPhone(ctx context.Context, accessToken string, request *api.UpdateAccountPhoneRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/account/phone",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

// UpdateAccountAddress updates the current user's address
func (c *AuthServerClient) UpdateAccountAddress(ctx context.Context, accessToken string, request *api.UpdateUserAddressRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/account/address",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

// UpdateAccountPassword changes the current user's password
func (c *AuthServerClient) UpdateAccountPassword(ctx context.Context, accessToken string, request *api.UpdateAccountPasswordRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/account/password",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

// SendAccountEmailVerification triggers sending a verification code to the user's email
func (c *AuthServerClient) SendAccountEmailVerification(ctx context.Context, accessToken string) (*api.AccountEmailVerificationSendResponse, error) {
	return execute[api.AccountEmailVerificationSendResponse](ctx, c, accessToken, apiRequest{
		method: "POST",
		url:    c.baseURL + "/api/v1/account/email/verification/send",
		// An empty JSON object, not a marshalled value: this endpoint takes no parameters and the
		// literal is what it has always been sent.
		rawBody:       []byte("{}"),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
		sendsMail:     true,
	})
}

// VerifyAccountEmail sends the verification code to confirm the user's email
func (c *AuthServerClient) VerifyAccountEmail(ctx context.Context, accessToken string, request *api.VerifyAccountEmailRequest) (*api.UserResponse, error) {
	response, err := execute[api.UpdateUserResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/account/email/verification",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.User, nil
}

// GetAccountOTPEnrollment generates an OTP enrollment secret and QR for current user
func (c *AuthServerClient) GetAccountOTPEnrollment(ctx context.Context, accessToken string) (*api.AccountOTPEnrollmentResponse, error) {
	return execute[api.AccountOTPEnrollmentResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/account/otp/enrollment",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// UpdateAccountOTP enables or disables OTP for the current user. An enable answers with the set of
// recovery codes created with the authenticator, which this response alone carries (#257).
func (c *AuthServerClient) UpdateAccountOTP(ctx context.Context, accessToken string, request *api.UpdateAccountOTPRequest) (*api.UpdateAccountOTPResponse, error) {
	return execute[api.UpdateAccountOTPResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.baseURL + "/api/v1/account/otp",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// GetAccountRecoveryCodes answers how many of the current user's recovery codes are unused.
func (c *AuthServerClient) GetAccountRecoveryCodes(ctx context.Context, accessToken string) (*api.AccountRecoveryCodesResponse, error) {
	return execute[api.AccountRecoveryCodesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/account/otp/recovery-codes",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// CreateAccountRecoveryCodes replaces the current user's recovery codes with a new set, given their
// password, and answers it. This response alone carries the new set (#257).
func (c *AuthServerClient) CreateAccountRecoveryCodes(ctx context.Context, accessToken string, request *api.CreateAccountRecoveryCodesRequest) (*api.CreateAccountRecoveryCodesResponse, error) {
	return execute[api.CreateAccountRecoveryCodesResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/account/otp/recovery-codes",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// CreateAccountLogoutRequest asks the auth server to prepare a logout operation. Exactly one of the
// two returns is non-nil, and which one the endpoint chooses is what request.ResponseMode asked for.
//
// The two shapes share no field, so they are told apart by what survived the unmarshal rather than
// by a discriminator: encoding/json fills neither struct from the other's body, and a body that
// fills neither is an error rather than a nil pair, because the caller would otherwise dereference
// whichever it expected. That is why this one takes the body from the executor and decodes it
// itself rather than naming a single response type.
func (c *AuthServerClient) CreateAccountLogoutRequest(ctx context.Context, accessToken string, request *api.AccountLogoutRequest) (*api.AccountLogoutFormPostResponse, *api.AccountLogoutRedirectResponse, error) {
	body, err := c.do(ctx, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/account/logout-request",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		anySuccess2xx: true,
	})
	if err != nil {
		return nil, nil, err
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
func (c *AuthServerClient) GetAccountConsents(ctx context.Context, accessToken string) ([]api.UserConsentResponse, error) {
	response, err := execute[api.GetUserConsentsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/account/consents",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Consents, nil
}

// RevokeAccountConsent deletes a consent for the current user
func (c *AuthServerClient) RevokeAccountConsent(ctx context.Context, accessToken string, consentId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           fmt.Sprintf("%s/api/v1/account/consents/%d", c.baseURL, consentId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}

// GetAccountProfilePicture retrieves the current user's profile picture info
func (c *AuthServerClient) GetAccountProfilePicture(ctx context.Context, accessToken string) (*api.ProfilePictureInfoResponse, error) {
	return execute[api.ProfilePictureInfoResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/account/profile-picture",
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// UploadAccountProfilePicture uploads a profile picture for the current user
func (c *AuthServerClient) UploadAccountProfilePicture(ctx context.Context, accessToken string, pictureData []byte, filename string) (*api.ProfilePictureUploadResponse, error) {
	body, contentType, err := multipartPicture(filename, pictureData)
	if err != nil {
		return nil, err
	}

	return execute[api.ProfilePictureUploadResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/account/profile-picture",
		rawBody:       body,
		contentType:   contentType,
		successStatus: http.StatusOK,
	})
}

// DeleteAccountProfilePicture deletes the current user's profile picture
func (c *AuthServerClient) DeleteAccountProfilePicture(ctx context.Context, accessToken string) error {
	// No Content-Type: this request carries no body, and the header it never set is left unset
	// rather than tidied up, because nothing observable moves in this change.
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.baseURL + "/api/v1/account/profile-picture",
		successStatus: http.StatusOK,
	})
	return err
}

// DeleteAccount deletes the current user's own account, given their password and, while two-factor
// authentication is on, an authenticator code or a recovery code. The auth server answers it only
// for a token issued to the admin console's own client (#783 decision 3). A POST, because the
// credentials are its content, which a DELETE should not carry (RFC 9110 section 9.3.5).
func (c *AuthServerClient) DeleteAccount(ctx context.Context, accessToken string, request *api.DeleteAccountRequest) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "POST",
		url:           c.baseURL + "/api/v1/account/deletion",
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}

// GetAccountExport asks for the current user's own export, the document an administrator's
// GetUserExport answers for them, through GET /api/v1/account/export. It is called and answered as
// GetUserExport is, to hand to the browser as it came (#782 decision 3). The auth server answers it
// only for a token issued to the admin console's own client, from a sign-in recent and strong
// enough: an older or weaker one is refused 401 INSUFFICIENT_USER_AUTHENTICATION (decision 1).
func (c *AuthServerClient) GetAccountExport(ctx context.Context, accessToken string) (*UserExport, error) {
	//nolint:bodyclose // the body is the caller's: UserExport hands it on, and the caller closes it
	resp, err := c.passThrough(ctx, accessToken, apiRequest{
		method:        "GET",
		url:           c.baseURL + "/api/v1/account/export",
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return userExportFrom(resp), nil
}
