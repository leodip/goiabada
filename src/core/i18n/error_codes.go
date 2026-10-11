package i18n

// Error code constants. Stable identifiers used in admin/account API
// error_code field and in catalog keys.
//
// Conventions:
//   - validator.<domain>.<reason>: errors emitted by validators in
//     src/authserver/internal/protocolvalidation/, src/authserver/internal/
//     accountvalidation/ and src/core/inputvalidation/. Domain is the entity
//     (e.g. "login", "address", "email"). Reason is a short slug.
//   - handler.<domain>.<reason>: errors emitted by handlers (auth flow,
//     account self-service, admin operations).
//
// Adding a new error means: (1) add a constant here, (2) add a catalog
// entry under the same key in active.en.toml, (3) add the same key to
// active.<other>.toml for every supported locale.
const (
	// Login flow — used by /auth/pwd POST.
	ErrCodeLoginEmailRequired    = "validator.login.email_required"
	ErrCodeLoginPasswordRequired = "validator.login.password_required" //nolint:gosec // G101: a catalog key naming a message, not a credential
	ErrCodeLoginAuthFailed       = "handler.login.auth_failed"
	ErrCodeLoginAccountDisabled  = "handler.login.account_disabled"

	// Email validator — used wherever an email address is validated outside
	// the OAuth protocol path (account self-service, admin user CRUD, SMTP
	// settings, registration). Errors that become an RFC 6749
	// error_description stay in oauth.ErrorDetail and are not
	// represented here; see the authorize group at the end of this block for
	// where that line falls on the authorization endpoint.
	ErrCodeEmailRequired          = "validator.email.required"
	ErrCodeEmailInvalidFormat     = "validator.email.invalid_format"
	ErrCodeEmailTooLong           = "validator.email.too_long" // Args: {"max": int}
	ErrCodeEmailAlreadyRegistered = "validator.email.already_registered"

	// Admin user-groups handler — assignment validation.
	ErrCodeUserGroupsNotFound = "handler.admin_user_groups.not_found"

	// Address validator — used wherever a postal address is validated.
	// Stored country is canonical ISO 3166-1 alpha-2.
	ErrCodeAddressLine1TooLong      = "validator.address.line1_too_long"       // Args: {"max": int}
	ErrCodeAddressLine2TooLong      = "validator.address.line2_too_long"       // Args: {"max": int}
	ErrCodeAddressLocalityTooLong   = "validator.address.locality_too_long"    // Args: {"max": int}
	ErrCodeAddressRegionTooLong     = "validator.address.region_too_long"      // Args: {"max": int}
	ErrCodeAddressPostalCodeTooLong = "validator.address.postal_code_too_long" // Args: {"max": int}
	ErrCodeAddressCountryInvalid    = "validator.address.country_invalid"
	ErrCodeAddressAngleBrackets     = "validator.address.angle_brackets"

	// Angle brackets validator — ValidateNoAngleBrackets refuses "<" and ">" in
	// the plain-text fields that no other validator constrains. One code per
	// field family, so the banner the API's error_description feeds names the
	// field that was refused (#275). The permission description keeps its own
	// handler.admin_resource_permissions.description_html_not_allowed.
	ErrCodeDescriptionAngleBrackets          = "validator.description.angle_brackets"
	ErrCodeDisplayNameAngleBrackets          = "validator.display_name.angle_brackets"
	ErrCodeAttributeValueAngleBrackets       = "validator.attribute.value_angle_brackets"
	ErrCodeSettingsAppNameAngleBrackets      = "validator.settings.app_name_angle_brackets"
	ErrCodeSettingsIssuerAngleBrackets       = "validator.settings.issuer_angle_brackets"
	ErrCodeSettingsSmtpFromNameAngleBrackets = "validator.settings.smtp_from_name_angle_brackets"

	// Identifier validator — used for client / resource / permission /
	// group identifiers and attribute keys.
	ErrCodeIdentifierTooLong       = "validator.identifier.too_long"  // Args: {"max": int}
	ErrCodeIdentifierTooShort      = "validator.identifier.too_short" // Args: {"min": int}
	ErrCodeIdentifierInvalidFormat = "validator.identifier.invalid_format"

	// Phone validator — used for user phone-number fields.
	ErrCodePhoneCountryInvalid  = "validator.phone.country_invalid"
	ErrCodePhoneNumberRequired  = "validator.phone.number_required"
	ErrCodePhoneNumberTooShort  = "validator.phone.number_too_short" // Args: {"min": int}
	ErrCodePhoneSimplePattern   = "validator.phone.simple_pattern"
	ErrCodePhoneInvalidFormat   = "validator.phone.invalid_format"
	ErrCodePhoneNumberTooLong   = "validator.phone.number_too_long" // Args: {"max": int}
	ErrCodePhoneCountryRequired = "validator.phone.country_required"

	// Password validator — settings-driven policy enforcement. Used by
	// account self-service password change, admin user CRUD, registration,
	// and reset-password.
	ErrCodePasswordTooShort            = "validator.password.too_short" // Args: {"min": int}
	ErrCodePasswordTooLong             = "validator.password.too_long"  // Args: {"max": int}
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

	// Admin resource permissions handler — in-page validation for the
	// permission-creation form (browser-flow JSON, surface A).
	ErrCodeAdminResourcePermissionsDescriptionHtmlNotAllowed = "handler.admin_resource_permissions.description_html_not_allowed"
	ErrCodeAdminResourcePermissionsIdentifierRequired        = "handler.admin_resource_permissions.permission_identifier_required"
	ErrCodeAdminResourcePermissionsDescriptionTooLong        = "handler.admin_resource_permissions.description_too_long" // Args: {"max": int}

	// Refusals the admin console and the admin API both write, the console before it calls the
	// API and the API when a caller sends the same request without the console's check. One key
	// for each, so the two say the same sentence in every language (#559).
	ErrCodeClientIdentifierRequired         = "handler.client.identifier_required"
	ErrCodeAttributeKeyRequired             = "handler.attribute.key_required"
	ErrCodeSettingsEmailDestinationRequired = "handler.settings_email.destination_required"

	// Refusals of the admin and account API that a person reaches through the admin console. The
	// API writes each with the error_code and the status it always had, and only the description
	// comes from here, in the request's language (#559 decisions 1 and 2).
	//
	// Shared by several areas: the two conflicts of a list save, the email taken by a concurrent
	// write, the last administrator, and the image upload's two refusals.
	ErrCodeListSaveChangedSinceLoaded  = "handler.list_save.changed_since_loaded"
	ErrCodeListSaveChangedConcurrently = "handler.list_save.changed_concurrently"
	ErrCodeEmailAlreadyExists          = "handler.email.already_exists"
	ErrCodeLastAdministrator           = "handler.administrators.last_administrator"
	ErrCodeImageUploadTooLarge         = "handler.image_upload.too_large"
	ErrCodeImageUploadNoFile           = "handler.image_upload.no_file"

	// Resources.
	ErrCodeResourceIdentifierRequired          = "handler.resource.identifier_required"
	ErrCodeResourceDescriptionTooLong          = "handler.resource.description_too_long" // Args: {"max": int}
	ErrCodeResourceIdentifierInUse             = "handler.resource.identifier_in_use"
	ErrCodeResourceSystemLevelIdentifierFixed  = "handler.resource.system_level_identifier_fixed"
	ErrCodeResourceSystemLevelDeleteNotAllowed = "handler.resource.system_level_delete_not_allowed"

	// A resource's permissions. The description bound is the console's own
	// handler.admin_resource_permissions.description_too_long, which says the same sentence.
	ErrCodePermissionDuplicateIds       = "handler.permission.duplicate_ids"
	ErrCodePermissionIdentifierRequired = "handler.permission.identifier_required"
	ErrCodePermissionDuplicated         = "handler.permission.duplicated"        // Args: {"identifier": string}
	ErrCodePermissionBuiltInDeleted     = "handler.permission.built_in_deleted"  // Args: {"identifier": string}
	ErrCodePermissionBuiltInRenamed     = "handler.permission.built_in_renamed"  // Args: {"identifier": string}
	ErrCodePermissionIdentifierInUse    = "handler.permission.identifier_in_use" // Args: {"identifier": string}

	// Groups, their members and attributes, and a user's attributes. A group's and a user's attribute
	// key is the console's own handler.attribute.key_required above, and the value bound is one
	// sentence for both, whose codes differ (VALIDATION_ERROR and VALUE_TOO_LONG).
	ErrCodeGroupIdentifierRequired  = "handler.group.identifier_required"
	ErrCodeGroupDescriptionTooLong  = "handler.group.description_too_long" // Args: {"max": int}
	ErrCodeGroupIdentifierInUse     = "handler.group.identifier_in_use"
	ErrCodeGroupMemberAlreadyMember = "handler.group_member.already_member"
	ErrCodeGroupMemberNotMember     = "handler.group_member.not_member"
	ErrCodeAttributeValueTooLong    = "handler.attribute.value_too_long" // Args: {"max": int}

	// Users, a user's groups, and the email verification code an administrator generates. The
	// account's own send says the code's sentence too.
	ErrCodeUserEmailRequired               = "handler.user.email_required"
	ErrCodeUserEmailTooLong                = "handler.user.email_too_long" // Args: {"max": int}
	ErrCodeUserSetPasswordTypeInvalid      = "handler.user.set_password_type_invalid"
	ErrCodeUserPasswordRequired            = "handler.user.password_required"
	ErrCodeUserNewPasswordRequired         = "handler.user.new_password_required"
	ErrCodeUserOTPEnableNotSupported       = "handler.user.otp_enable_not_supported"
	ErrCodeUserOTPNotEnabled               = "handler.user.otp_not_enabled"
	ErrCodeUserGroupsTooMany               = "handler.user_groups.too_many"
	ErrCodeEmailVerificationAccountChanged = "handler.email_verification.account_changed"

	// RP-initiated logout via /auth/logout carries no error codes. It used to
	// carry ten, all of which rendered an error page to the End-User instead of
	// logging them out. A hint the OP cannot confirm is now answered with the
	// consent page the spec requires, and a redirect target it may not use costs
	// the request its redirect and nothing else, so there is no failure left on
	// that endpoint that the End-User is the right audience for (#109).

	// Profile validator — username, names, nickname, website, gender,
	// date of birth, zone info, locale.
	ErrCodeProfileUsernameTaken     = "validator.profile.username_taken"
	ErrCodeProfileUsernameInvalid   = "validator.profile.username_invalid"
	ErrCodeProfileGivenNameInvalid  = "validator.profile.given_name_invalid"
	ErrCodeProfileMiddleNameInvalid = "validator.profile.middle_name_invalid"
	ErrCodeProfileFamilyNameInvalid = "validator.profile.family_name_invalid"
	ErrCodeProfileNicknameInvalid   = "validator.profile.nickname_invalid"
	ErrCodeProfileWebsiteInvalid    = "validator.profile.website_invalid"
	ErrCodeProfileWebsiteTooLong    = "validator.profile.website_too_long" // Args: {"max": int}
	ErrCodeProfileGenderInvalid     = "validator.profile.gender_invalid"
	ErrCodeProfileDobInvalidFormat  = "validator.profile.dob_invalid_format"
	ErrCodeProfileDobInFuture       = "validator.profile.dob_in_future"
	ErrCodeProfileZoneInfoInvalid   = "validator.profile.zone_info_invalid"
	ErrCodeProfileLocaleInvalid     = "validator.profile.locale_invalid"

	// Image validator — profile picture and client logo uploads, from
	// authserver/internal/imageupload.
	ErrCodeImageTooLarge           = "validator.image.too_large" // Args: {"max": int64}
	ErrCodeImageEmpty              = "validator.image.empty"
	ErrCodeImageUnsupportedType    = "validator.image.unsupported_type"
	ErrCodeImageUndecodable        = "validator.image.undecodable"
	ErrCodeImageDimensionsTooSmall = "validator.image.dimensions_too_small" // Args: {"min": int}
	ErrCodeImageDimensionsTooLarge = "validator.image.dimensions_too_large" // Args: {"max": int}

	// Authorize endpoint, client and redirect_uri validation. These seven are
	// the only authorize-endpoint errors represented here, and the reason is
	// where they come out rather than what they say: RFC 6749 4.1.2.1 forbids
	// redirecting to an invalid redirection URI, so each of these renders a
	// page and none of them ever becomes an error_description. The five
	// validations that run after them do become one, are addressed to the
	// client developer, and stay English (#213).
	ErrCodeAuthorizeClientIdMissing          = "validator.authorize.client_id_missing"
	ErrCodeAuthorizeClientNotFound           = "validator.authorize.client_not_found"
	ErrCodeAuthorizeClientDisabled           = "validator.authorize.client_disabled"
	ErrCodeAuthorizeAuthCodeNotEnabled       = "validator.authorize.auth_code_not_enabled"
	ErrCodeAuthorizeRedirectURIMissing       = "validator.authorize.redirect_uri_missing"
	ErrCodeAuthorizeRedirectURINotAbsolute   = "validator.authorize.redirect_uri_not_absolute"
	ErrCodeAuthorizeRedirectURINotRegistered = "validator.authorize.redirect_uri_not_registered"
)
