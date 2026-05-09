package i18n

// Error code constants. Stable identifiers used in admin/account API
// error_code field and in catalog keys.
//
// Conventions:
//   - validator.<domain>.<reason>: errors emitted by validators in
//     src/core/validators/. Domain is the entity (e.g. "login", "address",
//     "email"). Reason is a short slug.
//   - handler.<domain>.<reason>: errors emitted by handlers (auth flow,
//     account self-service, admin operations).
//
// Adding a new error means: (1) add a constant here, (2) add a catalog
// entry under the same key in active.en.toml, (3) add the same key to
// active.<other>.toml for every supported locale.
const (
	// Login flow — used by /auth/pwd POST.
	ErrCodeLoginEmailRequired    = "validator.login.email_required"
	ErrCodeLoginPasswordRequired = "validator.login.password_required"
	ErrCodeLoginAuthFailed       = "handler.login.auth_failed"
	ErrCodeLoginAccountDisabled  = "handler.login.account_disabled"

	// Email validator — used wherever an email address is validated outside
	// the OAuth protocol path (account self-service, admin user CRUD, SMTP
	// settings, registration). Protocol token/authorize errors stay in
	// customerrors.ErrorDetail and are not represented here.
	ErrCodeEmailRequired             = "validator.email.required"
	ErrCodeEmailInvalidFormat        = "validator.email.invalid_format"
	ErrCodeEmailTooLong              = "validator.email.too_long"               // Args: {"max": int}
	ErrCodeEmailConfirmationMismatch = "validator.email.confirmation_mismatch"
	ErrCodeEmailAlreadyRegistered    = "validator.email.already_registered"

	// Admin user-groups handler — assignment validation.
	ErrCodeUserGroupsNotFound = "handler.admin_user_groups.not_found"

	// Address validator — used wherever a postal address is validated.
	// Stored country is canonical ISO 3166-1 alpha-2.
	ErrCodeAddressLine1TooLong       = "validator.address.line1_too_long"        // Args: {"max": int}
	ErrCodeAddressLine2TooLong       = "validator.address.line2_too_long"        // Args: {"max": int}
	ErrCodeAddressLocalityTooLong    = "validator.address.locality_too_long"     // Args: {"max": int}
	ErrCodeAddressRegionTooLong      = "validator.address.region_too_long"       // Args: {"max": int}
	ErrCodeAddressPostalCodeTooLong  = "validator.address.postal_code_too_long"  // Args: {"max": int}
	ErrCodeAddressCountryInvalid     = "validator.address.country_invalid"

	// Identifier validator — used for client / resource / permission /
	// group identifiers and attribute keys.
	ErrCodeIdentifierTooLong       = "validator.identifier.too_long"       // Args: {"max": int}
	ErrCodeIdentifierTooShort      = "validator.identifier.too_short"      // Args: {"min": int}
	ErrCodeIdentifierInvalidFormat = "validator.identifier.invalid_format"

	// Phone validator — used for user phone-number fields.
	ErrCodePhoneCountryInvalid  = "validator.phone.country_invalid"
	ErrCodePhoneNumberRequired  = "validator.phone.number_required"
	ErrCodePhoneNumberTooShort  = "validator.phone.number_too_short"  // Args: {"min": int}
	ErrCodePhoneSimplePattern   = "validator.phone.simple_pattern"
	ErrCodePhoneInvalidFormat   = "validator.phone.invalid_format"
	ErrCodePhoneNumberTooLong   = "validator.phone.number_too_long"   // Args: {"max": int}
	ErrCodePhoneCountryRequired = "validator.phone.country_required"

	// Password validator — settings-driven policy enforcement. Used by
	// account self-service password change, admin user CRUD, registration,
	// and reset-password.
	ErrCodePasswordTooShort            = "validator.password.too_short"             // Args: {"min": int}
	ErrCodePasswordTooLong             = "validator.password.too_long"              // Args: {"max": int}
	ErrCodePasswordLowercaseRequired   = "validator.password.lowercase_required"
	ErrCodePasswordUppercaseRequired   = "validator.password.uppercase_required"
	ErrCodePasswordNumberRequired      = "validator.password.number_required"
	ErrCodePasswordSpecialCharRequired = "validator.password.special_char_required"

	// Browser-flow handler errors that mirror UI form validation but are
	// emitted from handler-side checks rather than validators (so they
	// don't go through the validator namespace).
	ErrCodeHandlerEmailRequired                = "handler.email.required"
	ErrCodeHandlerPasswordRequired             = "handler.password.required"
	ErrCodeHandlerPasswordConfirmationRequired = "handler.password.confirmation_required"
	ErrCodeHandlerPasswordConfirmationMismatch = "handler.password.confirmation_mismatch"

	// OTP handler — second-factor verification step.
	ErrCodeOtpAccountDisabled = "handler.otp.account_disabled"
	ErrCodeOtpCodeRequired    = "handler.otp.code_required"
	ErrCodeOtpIncorrectCode   = "handler.otp.incorrect_code"

	// Profile validator — username, names, nickname, website, gender,
	// date of birth, zone info, locale.
	ErrCodeProfileUsernameTaken      = "validator.profile.username_taken"
	ErrCodeProfileUsernameInvalid    = "validator.profile.username_invalid"
	ErrCodeProfileGivenNameInvalid   = "validator.profile.given_name_invalid"
	ErrCodeProfileMiddleNameInvalid  = "validator.profile.middle_name_invalid"
	ErrCodeProfileFamilyNameInvalid  = "validator.profile.family_name_invalid"
	ErrCodeProfileNicknameInvalid    = "validator.profile.nickname_invalid"
	ErrCodeProfileWebsiteInvalid     = "validator.profile.website_invalid"
	ErrCodeProfileWebsiteTooLong     = "validator.profile.website_too_long"   // Args: {"max": int}
	ErrCodeProfileGenderInvalid      = "validator.profile.gender_invalid"
	ErrCodeProfileDobInvalidFormat   = "validator.profile.dob_invalid_format"
	ErrCodeProfileDobInFuture        = "validator.profile.dob_in_future"
	ErrCodeProfileZoneInfoInvalid    = "validator.profile.zone_info_invalid"
	ErrCodeProfileLocaleInvalid      = "validator.profile.locale_invalid"
)
