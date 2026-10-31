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

	// Turnstile challenge — the refusal of a submission whose token Cloudflare did not verify,
	// or that carried none, on each form the challenge is on (#642).
	ErrCodeChallengeFailed = "handler.challenge.failed"

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
	// activation, reset-password and the recover command. The last two codes
	// are the nist policy's: a listed password, and one too close to the
	// account's words or the app's name (#550 decision 10).
	ErrCodePasswordTooShort            = "validator.password.too_short" // Args: {"min": int}
	ErrCodePasswordTooLong             = "validator.password.too_long"  // Args: {"max": int}
	ErrCodePasswordLowercaseRequired   = "validator.password.lowercase_required"
	ErrCodePasswordUppercaseRequired   = "validator.password.uppercase_required"
	ErrCodePasswordNumberRequired      = "validator.password.number_required"
	ErrCodePasswordSpecialCharRequired = "validator.password.special_char_required"
	ErrCodePasswordTooCommon           = "validator.password.too_common"
	ErrCodePasswordTooCloseToAccount   = "validator.password.too_close_to_account"

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
	// A code from the time step after the server's current one, which only an authenticator
	// whose clock runs ahead shows: refused with this rather than as a wrong code (#142).
	ErrCodeOtpClockAhead = "handler.otp.clock_ahead"
	// The recovery-code form's refusals (#257): no code, and a code that is wrong, of a replaced
	// set or already used, which one message answers so the submitter cannot tell them apart.
	ErrCodeOtpRecoveryCodeRequired  = "handler.otp.recovery_code_required"
	ErrCodeOtpIncorrectRecoveryCode = "handler.otp.incorrect_recovery_code"

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
	ErrCodeResourceIdentifierNamesClient       = "handler.resource.identifier_names_client"
	ErrCodeResourceSystemLevelIdentifierFixed  = "handler.resource.system_level_identifier_fixed"
	ErrCodeResourceSystemLevelDeleteNotAllowed = "handler.resource.system_level_delete_not_allowed"

	// Legal documents (#622).
	ErrCodeLegalDocumentKindInvalid           = "handler.legal_document.kind_invalid"
	ErrCodeLegalDocumentShortNameRequired     = "handler.legal_document.short_name_required"
	ErrCodeLegalDocumentShortNameInvalid      = "handler.legal_document.short_name_invalid"
	ErrCodeLegalDocumentShortNameTooLong      = "handler.legal_document.short_name_too_long" // Args: {"max": int}
	ErrCodeLegalDocumentShortNameInUse        = "handler.legal_document.short_name_in_use"
	ErrCodeLegalDocumentShortNameFixed        = "handler.legal_document.short_name_fixed"
	ErrCodeLegalDocumentTitleRequired         = "handler.legal_document.title_required"
	ErrCodeLegalDocumentTitleTooLong          = "handler.legal_document.title_too_long"    // Args: {"max": int}
	ErrCodeLegalDocumentMarkdownTooLong       = "handler.legal_document.markdown_too_long" // Args: {"max": int}
	ErrCodeLegalDocumentNoDraft               = "handler.legal_document.no_draft"
	ErrCodeLegalDocumentDraftEmpty            = "handler.legal_document.draft_empty"
	ErrCodeLegalDocumentRetired               = "handler.legal_document.retired"
	ErrCodeLegalDocumentNotPublished          = "handler.legal_document.not_published"
	ErrCodeLegalDocumentAlreadyRetired        = "handler.legal_document.already_retired"
	ErrCodeLegalDocumentNotRetired            = "handler.legal_document.not_retired"
	ErrCodeLegalDocumentPublishedNotDeleted   = "handler.legal_document.published_not_deleted"
	ErrCodeLegalDocumentPublishedConcurrently = "handler.legal_document.published_concurrently"
	ErrCodeLegalDocumentAppliesToInvalid      = "handler.legal_document.applies_to_invalid"
	ErrCodeLegalDocumentAppsWithAllApps       = "handler.legal_document.apps_with_all_apps"
	ErrCodeLegalDocumentAdminConsoleClient    = "handler.legal_document.admin_console_client"

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
	ErrCodeGroupIdentifierRequired       = "handler.group.identifier_required"
	ErrCodeGroupDescriptionTooLong       = "handler.group.description_too_long" // Args: {"max": int}
	ErrCodeGroupIdentifierInUse          = "handler.group.identifier_in_use"
	ErrCodeGroupMemberAlreadyMember      = "handler.group_member.already_member"
	ErrCodeGroupMemberNotMember          = "handler.group_member.not_member"
	ErrCodeGroupAttributeGroupIdRequired = "handler.group_attribute.group_id_required"
	ErrCodeAttributeValueTooLong         = "handler.attribute.value_too_long" // Args: {"max": int}

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

	// Clients, their administrative scopes, permissions, redirect URIs, web origins and tokens. A
	// client's identifier refusal is handler.client.identifier_required above, and its description
	// bound is handler.admin_resource_permissions.description_too_long, which says the same sentence.
	ErrCodeClientDescriptionTooLong             = "handler.client.description_too_long"  // Args: {"max": int}
	ErrCodeClientDisplayNameTooLong             = "handler.client.display_name_too_long" // Args: {"max": int}
	ErrCodeClientIdentifierInUse                = "handler.client.identifier_in_use"
	ErrCodeClientIdentifierNamesResource        = "handler.client.identifier_names_resource"
	ErrCodeClientSystemLevelDeleteNotAllowed    = "handler.client.system_level_delete_not_allowed"
	ErrCodeClientSystemLevelIdentifierFixed     = "handler.client.system_level_identifier_fixed"
	ErrCodeClientSelfRegisteredIdentifierFixed  = "handler.client.self_registered_identifier_fixed"
	ErrCodeClientDefaultAcrNotApplicable        = "handler.client.default_acr_not_applicable"
	ErrCodeClientDefaultAcrInvalid              = "handler.client.default_acr_invalid"
	ErrCodeClientWebsiteURLTooLong              = "handler.client.website_url_too_long" // Args: {"max": int}
	ErrCodeClientWebsiteURLInvalid              = "handler.client.website_url_invalid"
	ErrCodeClientWebsiteURLSchemeInvalid        = "handler.client.website_url_scheme_invalid"
	ErrCodeClientPrivacyPolicyURLTooLong        = "handler.client.privacy_policy_url_too_long" // Args: {"max": int}
	ErrCodeClientPrivacyPolicyURLInvalid        = "handler.client.privacy_policy_url_invalid"
	ErrCodeClientPrivacyPolicyURLSchemeInvalid  = "handler.client.privacy_policy_url_scheme_invalid"
	ErrCodeClientTermsOfServiceURLTooLong       = "handler.client.terms_of_service_url_too_long" // Args: {"max": int}
	ErrCodeClientTermsOfServiceURLInvalid       = "handler.client.terms_of_service_url_invalid"
	ErrCodeClientTermsOfServiceURLSchemeInvalid = "handler.client.terms_of_service_url_scheme_invalid"
	ErrCodeClientSecretInvalid                  = "handler.client.secret_invalid"

	ErrCodeClientAdministrativeScopesAllowedRequired      = "handler.client_administrative_scopes.allowed_required"
	ErrCodeClientAdministrativeScopesConsoleAlwaysAllowed = "handler.client_administrative_scopes.console_always_allowed"
	ErrCodeClientIntrospectionResourcesPublicClient       = "handler.client_introspection_resources.public_client"
	ErrCodeClientPermissionsClientCredentialsDisabled     = "handler.client_permissions.client_credentials_disabled"

	ErrCodeClientRedirectURIsNoRedirectFlow = "handler.client_redirect_uris.no_redirect_flow"
	ErrCodeClientRedirectURIsTooMany        = "handler.client_redirect_uris.too_many" // Args: {"max": int, "count": int}
	ErrCodeClientRedirectURIEmpty           = "handler.client_redirect_uris.empty"
	ErrCodeClientRedirectURITooLong         = "handler.client_redirect_uris.too_long"      // Args: {"length": int, "max": int, "prefix": string}
	ErrCodeClientRedirectURIInvalid         = "handler.client_redirect_uris.invalid"       // Args: {"uri": string}
	ErrCodeClientRedirectURIInsecureHTTP    = "handler.client_redirect_uris.insecure_http" // Args: {"uri": string}
	ErrCodeClientRedirectURINotAbsolute     = "handler.client_redirect_uris.not_absolute"  // Args: {"uri": string}
	ErrCodeClientRedirectURIsDuplicate      = "handler.client_redirect_uris.duplicate"

	// The sign-out list's refusals, one for each of the redirect URI save's, since the two lists
	// are saved under the same rules and a refusal must say which list it is about (#147).
	ErrCodeClientPostLogoutRedirectURIsNoRedirectFlow = "handler.client_post_logout_redirect_uris.no_redirect_flow"
	ErrCodeClientPostLogoutRedirectURIsTooMany        = "handler.client_post_logout_redirect_uris.too_many" // Args: {"max": int, "count": int}
	ErrCodeClientPostLogoutRedirectURIEmpty           = "handler.client_post_logout_redirect_uris.empty"
	ErrCodeClientPostLogoutRedirectURITooLong         = "handler.client_post_logout_redirect_uris.too_long"      // Args: {"length": int, "max": int, "prefix": string}
	ErrCodeClientPostLogoutRedirectURIInvalid         = "handler.client_post_logout_redirect_uris.invalid"       // Args: {"uri": string}
	ErrCodeClientPostLogoutRedirectURIInsecureHTTP    = "handler.client_post_logout_redirect_uris.insecure_http" // Args: {"uri": string}
	ErrCodeClientPostLogoutRedirectURINotAbsolute     = "handler.client_post_logout_redirect_uris.not_absolute"  // Args: {"uri": string}
	ErrCodeClientPostLogoutRedirectURIsDuplicate      = "handler.client_post_logout_redirect_uris.duplicate"

	ErrCodeClientWebOriginEmpty            = "handler.client_web_origins.empty"
	ErrCodeClientWebOriginInvalid          = "handler.client_web_origins.invalid"  // Args: {"origin": string}
	ErrCodeClientWebOriginTooLong          = "handler.client_web_origins.too_long" // Args: {"length": int, "max": int, "origin": string}
	ErrCodeClientWebOriginsDuplicate       = "handler.client_web_origins.duplicate"
	ErrCodeClientWebOriginsExpectedInvalid = "handler.client_web_origins.expected_invalid" // Args: {"origin": string}

	ErrCodeClientTokensTokenExpirationOutOfRange          = "handler.client_tokens.token_expiration_out_of_range"     // Args: {"max": int}
	ErrCodeClientTokensOfflineIdleTimeoutOutOfRange       = "handler.client_tokens.offline_idle_timeout_out_of_range" // Args: {"max": int}
	ErrCodeClientTokensOfflineMaxLifetimeOutOfRange       = "handler.client_tokens.offline_max_lifetime_out_of_range" // Args: {"max": int}
	ErrCodeClientTokensOfflineIdleTimeoutAboveMaxLifetime = "handler.client_tokens.offline_idle_timeout_above_max_lifetime"
	ErrCodeClientTokensIncludeClaimsInAccessTokenInvalid  = "handler.client_tokens.include_claims_in_access_token_invalid"
	ErrCodeClientTokensIncludeClaimsInIdTokenInvalid      = "handler.client_tokens.include_claims_in_id_token_invalid"

	// The account: email, email verification, password, two-factor authentication and the logout
	// request. Disabling an authenticator the account does not have is handler.user.otp_not_enabled
	// above, a wrong code on enabling one is handler.otp.incorrect_code, a code from the next time step
	// handler.otp.clock_ahead, and the email verification
	// send's conflict is handler.email_verification.account_changed. SMTP being off is one sentence
	// for every endpoint that needs it.
	ErrCodeAccountCurrentPasswordRequired  = "handler.account.current_password_required"
	ErrCodeAccountNewPasswordRequired      = "handler.account.new_password_required"
	ErrCodeAccountCurrentPasswordIncorrect = "handler.account.current_password_incorrect"
	ErrCodeAccountPasswordIncorrect        = "handler.account.password_incorrect"
	ErrCodeAccountChangedSinceLoaded       = "handler.account.changed_since_loaded"
	ErrCodeSMTPNotEnabled                  = "handler.smtp.not_enabled"
	ErrCodeEmailVerificationCodeInvalid    = "handler.email_verification.code_invalid_or_expired"

	ErrCodeAccountOTPAlreadyEnabled       = "handler.account_otp.already_enabled"
	ErrCodeAccountOTPSecretKeyNotAccepted = "handler.account_otp.secret_key_not_accepted"
	ErrCodeAccountOTPCodeRequired         = "handler.account_otp.code_required"
	ErrCodeAccountOTPCodeInvalid          = "handler.account_otp.code_invalid"
	ErrCodeAccountOTPEnrollmentNotPending = "handler.account_otp.enrollment_not_pending"

	ErrCodeAccountLogoutRedirectURIRequired      = "handler.account_logout.post_logout_redirect_uri_required"
	ErrCodeAccountLogoutClientIdentifierInvalid  = "handler.account_logout.client_identifier_invalid"
	ErrCodeAccountLogoutClientUnresolved         = "handler.account_logout.client_unresolved"
	ErrCodeAccountLogoutRedirectURINotRegistered = "handler.account_logout.post_logout_redirect_uri_not_registered"
	ErrCodeAccountLogoutRedirectURINotAbsolute   = "handler.account_logout.post_logout_redirect_uri_not_absolute"
	ErrCodeAccountLogoutRedirectURIInsecureHTTP  = "handler.account_logout.post_logout_redirect_uri_insecure_http"

	// Settings: general, sessions, tokens, email, signing keys, the UI theme and audit logs. A settings
	// refusal sentence that a client's tokens or the account already say reuses that key: the offline
	// idle timeout above its max lifetime is handler.client_tokens.offline_idle_timeout_above_max_lifetime,
	// SMTP being off handler.smtp.not_enabled, and the test send's missing destination
	// handler.settings_email.destination_required. The SMTP connection and send failures are one
	// whole sentence per cause, never an opening and a cause joined at run time.
	ErrCodeSettingsGeneralAppNameRequired       = "handler.settings_general.app_name_required"
	ErrCodeSettingsGeneralAppNameTooLong        = "handler.settings_general.app_name_too_long" // Args: {"max": int}
	ErrCodeSettingsGeneralIssuerURIInvalid      = "handler.settings_general.issuer_uri_invalid"
	ErrCodeSettingsGeneralIssuerTooLong         = "handler.settings_general.issuer_too_long" // Args: {"max": int}
	ErrCodeSettingsGeneralPasswordPolicyInvalid = "handler.settings_general.password_policy_invalid"

	ErrCodeSettingsSessionsIdleTimeoutNotPositive       = "handler.settings_sessions.idle_timeout_not_positive"
	ErrCodeSettingsSessionsMaxLifetimeNotPositive       = "handler.settings_sessions.max_lifetime_not_positive"
	ErrCodeSettingsSessionsIdleTimeoutTooLarge          = "handler.settings_sessions.idle_timeout_too_large" // Args: {"max": int}
	ErrCodeSettingsSessionsMaxLifetimeTooLarge          = "handler.settings_sessions.max_lifetime_too_large" // Args: {"max": int}
	ErrCodeSettingsSessionsIdleTimeoutAboveMaxLifetime  = "handler.settings_sessions.idle_timeout_above_max_lifetime"
	ErrCodeSettingsSessionsMaxSessionsPerUserRequired   = "handler.settings_sessions.max_sessions_per_user_required"
	ErrCodeSettingsSessionsMaxSessionsPerUserOutOfRange = "handler.settings_sessions.max_sessions_per_user_out_of_range" // Args: {"max": int}

	ErrCodeSettingsTokensTokenExpirationNotPositive    = "handler.settings_tokens.token_expiration_not_positive"
	ErrCodeSettingsTokensTokenExpirationTooLarge       = "handler.settings_tokens.token_expiration_too_large" // Args: {"max": int}
	ErrCodeSettingsTokensOfflineIdleTimeoutNotPositive = "handler.settings_tokens.offline_idle_timeout_not_positive"
	ErrCodeSettingsTokensOfflineIdleTimeoutTooLarge    = "handler.settings_tokens.offline_idle_timeout_too_large" // Args: {"max": int}
	ErrCodeSettingsTokensOfflineMaxLifetimeNotPositive = "handler.settings_tokens.offline_max_lifetime_not_positive"
	ErrCodeSettingsTokensOfflineMaxLifetimeTooLarge    = "handler.settings_tokens.offline_max_lifetime_too_large" // Args: {"max": int}

	ErrCodeSettingsEmailSMTPHostRequired      = "handler.settings_email.smtp_host_required"
	ErrCodeSettingsEmailSMTPPortRequired      = "handler.settings_email.smtp_port_required"
	ErrCodeSettingsEmailSMTPFromEmailRequired = "handler.settings_email.smtp_from_email_required"
	ErrCodeSettingsEmailSMTPHostTooLong       = "handler.settings_email.smtp_host_too_long" // Args: {"max": int}
	ErrCodeSettingsEmailSMTPPortOutOfRange    = "handler.settings_email.smtp_port_out_of_range"
	ErrCodeSettingsEmailSMTPEncryptionInvalid = "handler.settings_email.smtp_encryption_invalid"
	ErrCodeSettingsEmailSMTPUsernameTooLong   = "handler.settings_email.smtp_username_too_long"   // Args: {"max": int}
	ErrCodeSettingsEmailSMTPPasswordTooLong   = "handler.settings_email.smtp_password_too_long"   // Args: {"max": int}
	ErrCodeSettingsEmailSMTPFromNameTooLong   = "handler.settings_email.smtp_from_name_too_long"  // Args: {"max": int}
	ErrCodeSettingsEmailSMTPFromEmailTooLong  = "handler.settings_email.smtp_from_email_too_long" // Args: {"max": int}
	ErrCodeSettingsEmailSMTPPasswordAndClear  = "handler.settings_email.smtp_password_and_clear"
	ErrCodeSettingsEmailSMTPHostChanged       = "handler.settings_email.smtp_host_changed"

	ErrCodeSettingsTurnstileSiteKeyRequired            = "handler.settings_turnstile.site_key_required"
	ErrCodeSettingsTurnstileSecretKeyRequired          = "handler.settings_turnstile.secret_key_required"
	ErrCodeSettingsTurnstileSecretKeyClearWhileEnabled = "handler.settings_turnstile.secret_key_clear_while_enabled"
	ErrCodeSettingsTurnstileSiteKeyChanged             = "handler.settings_turnstile.site_key_changed"
	ErrCodeSettingsTurnstileSecretKeyAndClear          = "handler.settings_turnstile.secret_key_and_clear"
	ErrCodeSettingsTurnstileSiteKeyTooLong             = "handler.settings_turnstile.site_key_too_long"   // Args: {"max": int}
	ErrCodeSettingsTurnstileSecretKeyTooLong           = "handler.settings_turnstile.secret_key_too_long" // Args: {"max": int}
	ErrCodeSettingsTurnstileSecretKeyRejected          = "handler.settings_turnstile.secret_key_rejected"
	ErrCodeSettingsTurnstileSecretKeyUnchecked         = "handler.settings_turnstile.secret_key_unchecked"

	ErrCodeSettingsEmailConnectFailedHostNotFound = "handler.settings_email.connect_failed_host_not_found"
	ErrCodeSettingsEmailConnectFailedTimedOut     = "handler.settings_email.connect_failed_timed_out"
	ErrCodeSettingsEmailConnectFailedRefused      = "handler.settings_email.connect_failed_refused"
	ErrCodeSettingsEmailConnectFailed             = "handler.settings_email.connect_failed"

	ErrCodeSettingsEmailSendFailedHostNotFound = "handler.settings_email.send_failed_host_not_found"
	ErrCodeSettingsEmailSendFailedTimedOut     = "handler.settings_email.send_failed_timed_out"
	ErrCodeSettingsEmailSendFailedRefused      = "handler.settings_email.send_failed_refused"
	ErrCodeSettingsEmailSendFailed             = "handler.settings_email.send_failed"
	ErrCodeSettingsEmailSTARTTLSNotOffered     = "handler.settings_email.starttls_not_offered"
	ErrCodeSettingsEmailPasswordUnencrypted    = "handler.settings_email.password_unencrypted"
	ErrCodeSettingsEmailNoAuthentication       = "handler.settings_email.no_authentication"
	ErrCodeSettingsEmailNoSupportedMechanism   = "handler.settings_email.no_supported_mechanism"
	ErrCodeSettingsEmailTLSFailed              = "handler.settings_email.tls_failed"
	ErrCodeSettingsEmailAuthenticationRejected = "handler.settings_email.authentication_rejected"
	ErrCodeSettingsEmailMessageRefused         = "handler.settings_email.message_refused"

	ErrCodeSettingsKeysRotationInProgress    = "handler.settings_keys.rotation_in_progress"
	ErrCodeSettingsKeysCommitOutcomeUnknown  = "handler.settings_keys.commit_outcome_unknown"
	ErrCodeSettingsKeysKeyNotFound           = "handler.settings_keys.key_not_found"
	ErrCodeSettingsKeysOnlyPreviousRevocable = "handler.settings_keys.only_previous_revocable"

	ErrCodeSettingsUIThemeInvalid                 = "handler.settings_ui_theme.theme_invalid"
	ErrCodeSettingsAuditLogsRetentionDaysNegative = "handler.settings_audit_logs.retention_days_negative"
	ErrCodeSettingsAuditLogsRetentionDaysTooLarge = "handler.settings_audit_logs.retention_days_too_large"

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
	ErrCodeProfileNicknameTooLong   = "validator.profile.nickname_too_long" // Args: {"max": int}
	// The nickname's angle-brackets refusal is emitted by ValidateNoAngleBrackets and
	// lives here with its family, as the address family's does (#275).
	ErrCodeProfileNicknameAngleBrackets = "validator.profile.nickname_angle_brackets"
	ErrCodeProfileWebsiteInvalid        = "validator.profile.website_invalid"
	ErrCodeProfileWebsiteTooLong        = "validator.profile.website_too_long" // Args: {"max": int}
	ErrCodeProfileGenderInvalid         = "validator.profile.gender_invalid"
	ErrCodeProfileDobInvalidFormat      = "validator.profile.dob_invalid_format"
	ErrCodeProfileDobInFuture           = "validator.profile.dob_in_future"
	ErrCodeProfileZoneInfoInvalid       = "validator.profile.zone_info_invalid"
	ErrCodeProfileLocaleInvalid         = "validator.profile.locale_invalid"
	ErrCodeProfilePageLanguageInvalid   = "validator.profile.page_language_invalid"

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
	ErrCodeAuthorizeRedirectURIMissing       = "validator.authorize.redirect_uri_missing"
	ErrCodeAuthorizeRedirectURINotAbsolute   = "validator.authorize.redirect_uri_not_absolute"
	ErrCodeAuthorizeRedirectURIInsecureHTTP  = "validator.authorize.redirect_uri_insecure_http"
	ErrCodeAuthorizeRedirectURINotRegistered = "validator.authorize.redirect_uri_not_registered"
)
