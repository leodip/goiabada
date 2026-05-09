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
)
