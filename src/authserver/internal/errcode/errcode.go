// Package errcode holds the catalog keys of the refusals only the auth server writes: each names a
// sentence in core/i18n's built-in catalogs, which i18n.NewLocalizedError carries and i18n.T
// renders in the request's language. None of them reaches the wire as an error_code: an API refusal
// answers with the call site's code, and a refusal page shows only the sentence. The keys that both
// applications name, or that an API refusal answers as its error_code, stay in core/i18n's
// error_codes.go, and core/i18n/error_codes.md lists every key's English sentence (#819).
package errcode

const (
	// Turnstile challenge — the refusal of a submission whose token Cloudflare did not verify,
	// or that carried none, on each form the challenge is on (#642).
	ChallengeFailed = "handler.challenge.failed"

	// OTP handler — second-factor verification step.
	// A code from the time step after the server's current one, which only an authenticator
	// whose clock runs ahead shows: refused with this rather than as a wrong code (#142).
	OTPClockAhead = "handler.otp.clock_ahead"
	// The recovery-code form's refusals (#257): no code, and a code that is wrong, of a replaced
	// set or already used, which one message answers so the submitter cannot tell them apart.
	OTPRecoveryCodeRequired  = "handler.otp.recovery_code_required"
	OTPIncorrectRecoveryCode = "handler.otp.incorrect_recovery_code"

	// Refusals of the admin and account API that a person reaches through the admin console. The
	// API writes each with the error_code and the status it always had, and only the description
	// comes from here, in the request's language (#559 decisions 1 and 2).
	//
	// Shared by several areas: the two conflicts of a list save, the email taken by a concurrent
	// write, the last administrator, and the image upload's two refusals.
	ListSaveChangedSinceLoaded  = "handler.list_save.changed_since_loaded"
	ListSaveChangedConcurrently = "handler.list_save.changed_concurrently"
	EmailAlreadyExists          = "handler.email.already_exists"
	LastAdministrator           = "handler.administrators.last_administrator"
	ImageUploadTooLarge         = "handler.image_upload.too_large"
	ImageUploadNoFile           = "handler.image_upload.no_file"
	BrandAssetUploadNoFile      = "handler.brand_asset.no_file"

	// Legal documents (#622).
	LegalDocumentPublishedConcurrently = "handler.legal_document.published_concurrently"

	// Users, a user's groups, and the email verification code an administrator generates. The
	// account's own send says the code's sentence too.
	UserEmailTooLong                = "handler.user.email_too_long" // Args: {"max": int}
	UserOTPNotEnabled               = "handler.user.otp_not_enabled"
	EmailVerificationAccountChanged = "handler.email_verification.account_changed"

	// The account: email, email verification, password, two-factor authentication and the logout
	// request. Disabling an authenticator the account does not have is handler.user.otp_not_enabled
	// above, a wrong code on enabling one is handler.otp.incorrect_code, a code from the next time step
	// handler.otp.clock_ahead, and the email verification
	// send's conflict is handler.email_verification.account_changed. SMTP being off is one sentence
	// for every endpoint that needs it.
	AccountCurrentPasswordRequired  = "handler.account.current_password_required"
	AccountNewPasswordRequired      = "handler.account.new_password_required"
	AccountCurrentPasswordIncorrect = "handler.account.current_password_incorrect"
	AccountPasswordIncorrect        = "handler.account.password_incorrect"
	AccountChangedSinceLoaded       = "handler.account.changed_since_loaded"
	SMTPNotEnabled                  = "handler.smtp.not_enabled"
	EmailVerificationCodeInvalid    = "handler.email_verification.code_invalid_or_expired"

	AccountOTPAlreadyEnabled       = "handler.account_otp.already_enabled"
	AccountOTPSecretKeyNotAccepted = "handler.account_otp.secret_key_not_accepted"
	AccountOTPCodeRequired         = "handler.account_otp.code_required"
	AccountOTPCodeInvalid          = "handler.account_otp.code_invalid"
	AccountOTPEnrollmentNotPending = "handler.account_otp.enrollment_not_pending"

	// The account's own deletion (#783 decisions 3 and 9): the setting turned off, the last
	// administrator, worded for a user deleting themselves rather than for an administrator acting on
	// another user, and an authenticator code sent beside a recovery code. A wrong password, code or
	// recovery code is answered with the sentence those checks already use.
	AccountDeletionDisabled          = "handler.account_deletion.disabled"
	AccountDeletionLastAdministrator = "handler.account_deletion.last_administrator"
	AccountDeletionOneSecondFactor   = "handler.account_deletion.one_second_factor"

	AccountLogoutRedirectURIRequired      = "handler.account_logout.post_logout_redirect_uri_required"
	AccountLogoutClientIdentifierInvalid  = "handler.account_logout.client_identifier_invalid"
	AccountLogoutClientUnresolved         = "handler.account_logout.client_unresolved"
	AccountLogoutRedirectURINotRegistered = "handler.account_logout.post_logout_redirect_uri_not_registered"
	AccountLogoutRedirectURINotAbsolute   = "handler.account_logout.post_logout_redirect_uri_not_absolute"
	AccountLogoutRedirectURIInsecureHTTP  = "handler.account_logout.post_logout_redirect_uri_insecure_http"

	SettingsEmailSendFailedHostNotFound   = "handler.settings_email.send_failed_host_not_found"
	SettingsEmailSendFailedTimedOut       = "handler.settings_email.send_failed_timed_out"
	SettingsEmailSendFailedRefused        = "handler.settings_email.send_failed_refused"
	SettingsEmailSendFailed               = "handler.settings_email.send_failed"
	SettingsEmailSTARTTLSNotOffered       = "handler.settings_email.starttls_not_offered"
	SettingsEmailPasswordUnencrypted      = "handler.settings_email.password_unencrypted"
	SettingsEmailNoAuthentication         = "handler.settings_email.no_authentication"
	SettingsEmailNoSupportedMechanism     = "handler.settings_email.no_supported_mechanism"
	SettingsEmailPlainCredentialsUnusable = "handler.settings_email.plain_credentials_unusable"
	SettingsEmailTLSFailed                = "handler.settings_email.tls_failed"
	SettingsEmailAuthenticationRejected   = "handler.settings_email.authentication_rejected"
	SettingsEmailMessageRefused           = "handler.settings_email.message_refused"

	SettingsKeysRotationInProgress   = "handler.settings_keys.rotation_in_progress"
	SettingsKeysCommitOutcomeUnknown = "handler.settings_keys.commit_outcome_unknown"

	// Authorize endpoint, client and redirect_uri validation. These seven are
	// the only authorize-endpoint errors represented here, and the reason is
	// where they come out rather than what they say: RFC 6749 4.1.2.1 forbids
	// redirecting to an invalid redirection URI, so each of these renders a
	// page and none of them ever becomes an error_description. The five
	// validations that run after them do become one, are addressed to the
	// client developer, and stay English (#213).
	AuthorizeClientIDMissing          = "validator.authorize.client_id_missing"
	AuthorizeClientNotFound           = "validator.authorize.client_not_found"
	AuthorizeClientDisabled           = "validator.authorize.client_disabled"
	AuthorizeRedirectURIMissing       = "validator.authorize.redirect_uri_missing"
	AuthorizeRedirectURINotAbsolute   = "validator.authorize.redirect_uri_not_absolute"
	AuthorizeRedirectURIInsecureHTTP  = "validator.authorize.redirect_uri_insecure_http"
	AuthorizeRedirectURINotRegistered = "validator.authorize.redirect_uri_not_registered"
)
