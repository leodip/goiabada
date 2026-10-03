package api

// UpdateAccountPasswordRequest is used by the account (self-service) API to
// change the currently authenticated user's password. The auth server validates
// the current password and the new password against the configured policy.
type UpdateAccountPasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// UpdateAccountOTPRequest is used by the account (self-service) API to
// enable or disable OTP for the currently authenticated user. The server
// validates the current password and, when enabling, validates the OTP code
// against the enrollment it issued at GET /api/v1/account/otp/enrollment.
//
// There is deliberately no SecretKey field. The server records the enrollment
// it issued and enrolls that seed and no other, so a caller cannot choose which
// authenticator is installed on its own account. A request that still carries
// secretKey is refused with 400 SECRET_KEY_NOT_ACCEPTED rather than having the
// field ignored, which is a breaking change and was chosen as one: nothing sets
// DisallowUnknownFields, so removing the field alone would have changed which
// secret was enrolled without telling anybody (#247).
type UpdateAccountOTPRequest struct {
	Enabled  bool   `json:"enabled"`
	Password string `json:"password"`
	OtpCode  string `json:"otpCode,omitempty"`
}

// AccountOTPEnrollmentResponse contains the enrollment QR code image (base64)
// and the secret key to set up TOTP in an authenticator app.
type AccountOTPEnrollmentResponse struct {
	Base64Image string `json:"base64Image"`
	SecretKey   string `json:"secretKey"`
}

// UpdateAccountEmailRequest is used by the account (self-service) API to
// update the currently authenticated user's email address.
// Confirmation is handled by the client UI, so it is not sent. The current
// password is: the change is refused without it (#404).
type UpdateAccountEmailRequest struct {
	Email           string `json:"email"`
	CurrentPassword string `json:"currentPassword"`
}

// VerifyAccountEmailRequest is used by the account (self-service) API to
// verify the currently authenticated user's email address using a code
// sent via email.
type VerifyAccountEmailRequest struct {
	VerificationCode string `json:"verificationCode"`
}

// AccountEmailVerificationSendResponse is returned by the account API when
// requesting that a verification email be sent.
type AccountEmailVerificationSendResponse struct {
	EmailVerificationSent bool   `json:"emailVerificationSent"`
	EmailDestination      string `json:"emailDestination"`
	TooManyRequests       bool   `json:"tooManyRequests"`
	WaitInSeconds         int    `json:"waitInSeconds"`
	EmailVerified         bool   `json:"emailVerified"`
}

// UpdateAccountPhoneRequest is used by the account (self-service) API to
// update the currently authenticated user's phone number. The server will
// always set PhoneNumberVerified to false upon change.
type UpdateAccountPhoneRequest struct {
	PhoneCountryUniqueId string `json:"phoneCountryUniqueId"`
	PhoneNumber          string `json:"phoneNumber"`
}

// AccountLogoutRequest is used by clients to request a prepared logout operation.
// The auth server will validate the inputs, mint a short-lived id_token_hint and
// return either a form_post instruction set or a redirect URL.
type AccountLogoutRequest struct {
	PostLogoutRedirectUri string `json:"postLogoutRedirectUri"`
	State                 string `json:"state,omitempty"`
	ClientIdentifier      string `json:"clientIdentifier,omitempty"`
	// ResponseMode selects which of the two response shapes the endpoint answers.
	// AccountLogoutResponseModeFormPost asks for AccountLogoutFormPostResponse; every other
	// value, absent and empty included, answers AccountLogoutRedirectResponse.
	ResponseMode string `json:"responseMode,omitempty"`
}

// AccountLogoutResponseModeFormPost is the one value of AccountLogoutRequest.ResponseMode that
// changes what /api/v1/account/logout-request answers. It is declared here, in the package both
// modules share, because the auth server compares against it and the admin console sends it: two
// literals in two modules is a disagreement nothing in the build can see, and a console that
// misspelt it would silently go back to putting the id_token_hint in a top-level URL (#350).
const AccountLogoutResponseModeFormPost = "form_post"

// AccountLogoutFormPostResponse instructs the client to POST to the OP's
// end-session endpoint with the given parameters. This avoids placing
// id_token_hint into the URL where it could leak via logs or referrer.
type AccountLogoutFormPostResponse struct {
	Method   string            `json:"method"`   // always "POST"
	Endpoint string            `json:"endpoint"` // e.g., {authserver}/auth/logout
	Params   map[string]string `json:"params"`   // id_token_hint, post_logout_redirect_uri, state
}

// AccountLogoutRedirectResponse provides a ready-to-follow URL for logout.
// This is simpler but exposes the token in the URL.
type AccountLogoutRedirectResponse struct {
	LogoutUrl string `json:"logoutUrl"`
}
