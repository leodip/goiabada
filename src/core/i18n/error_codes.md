# Error code taxonomy

Catalog of every stable error code emitted by Goiabada's localizable error
paths. Companion to `error_codes.go`. Adding a new code means: add a constant
to `error_codes.go`, add an entry here with the English message and arg shape,
and add the same key to every `active.*.toml` catalog.

## Login flow

| Code | Args | English message |
|---|---|---|
| `validator.login.email_required` | (none) | Email is required. |
| `validator.login.password_required` | (none) | Password is required. |
| `handler.login.auth_failed` | (none) | Authentication failed. |
| `handler.login.account_disabled` | (none) | Your user account is disabled. |

## Email validator

Used outside the OAuth protocol path (account self-service, admin user CRUD,
SMTP settings, registration). Protocol token/authorize email errors stay in
`oauth.ErrorDetail`.

| Code | Args | English message |
|---|---|---|
| `validator.email.required` | (none) | Please enter an email address. |
| `validator.email.invalid_format` | (none) | Please enter a valid email address. |
| `validator.email.too_long` | `max` (int) | The email address cannot exceed a maximum length of {{.max}} characters. |
| `validator.email.already_registered` | (none) | Apologies, but this email address is already registered. |

## Admin user-groups handler

| Code | Args | English message |
|---|---|---|
| `handler.admin_user_groups.not_found` | (none) | One or more groups not found. |

## Address validator

| Code | Args | English message |
|---|---|---|
| `validator.address.line1_too_long` | `max` (int) | Please ensure the address line 1 is no longer than {{.max}} characters. |
| `validator.address.line2_too_long` | `max` (int) | Please ensure the address line 2 is no longer than {{.max}} characters. |
| `validator.address.locality_too_long` | `max` (int) | Please ensure the locality is no longer than {{.max}} characters. |
| `validator.address.region_too_long` | `max` (int) | Please ensure the region is no longer than {{.max}} characters. |
| `validator.address.postal_code_too_long` | `max` (int) | Please ensure the postal code is no longer than {{.max}} characters. |
| `validator.address.country_invalid` | (none) | Invalid country. |
| `validator.address.angle_brackets` | (none) | Address fields cannot contain the characters < or >. |

## Angle brackets validator

Emitted by `accountvalidation.ValidateNoAngleBrackets`, one code per field family. The
address family's code is in the address table above.

| Code | Args | English message |
|---|---|---|
| `validator.description.angle_brackets` | (none) | The description cannot contain the characters < or >. |
| `validator.display_name.angle_brackets` | (none) | The display name cannot contain the characters < or >. |
| `validator.attribute.value_angle_brackets` | (none) | The attribute value cannot contain the characters < or >. |
| `validator.settings.app_name_angle_brackets` | (none) | The app name cannot contain the characters < or >. |
| `validator.settings.issuer_angle_brackets` | (none) | The issuer cannot contain the characters < or >. |
| `validator.settings.smtp_from_name_angle_brackets` | (none) | The from name cannot contain the characters < or >. |

## Identifier validator

| Code | Args | English message |
|---|---|---|
| `validator.identifier.too_long` | `max` (int) | The identifier cannot exceed a maximum length of {{.max}} characters. |
| `validator.identifier.too_short` | `min` (int) | The identifier must be at least {{.min}} characters long. |
| `validator.identifier.invalid_format` | (none) | Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores. |

## Phone validator

| Code | Args | English message |
|---|---|---|
| `validator.phone.country_invalid` | (none) | Phone country is invalid. |
| `validator.phone.number_required` | (none) | The phone number field must contain a valid phone number. To remove the phone number information, please select the (blank) option from the dropdown menu for the phone country and leave the phone number field empty. |
| `validator.phone.number_too_short` | `min` (int) | The phone number must be at least {{.min}} digits long. |
| `validator.phone.simple_pattern` | (none) | The phone number appears to be a simple pattern. Please enter a valid phone number. |
| `validator.phone.invalid_format` | (none) | Please enter a valid number. Phone numbers can contain only digits, and may include single spaces or hyphens as separators. |
| `validator.phone.number_too_long` | `max` (int) | The maximum allowed length for a phone number is {{.max}} characters. |
| `validator.phone.country_required` | (none) | You must select a country for your phone number. |

## Browser-flow handler form errors

Emitted from handler-side checks (presence, confirmation match) rather than
the validator layer.

| Code | Args | English message |
|---|---|---|
| `handler.email.required` | (none) | Email is required. |
| `handler.password.required` | (none) | Password is required. |
| `handler.password.confirmation_required` | (none) | Confirm your password. |
| `handler.password.confirmation_mismatch` | (none) | The passwords don't match. |

## OTP handler

| Code | Args | English message |
|---|---|---|
| `handler.otp.account_disabled` | (none) | Your account is disabled. |
| `handler.otp.code_required` | (none) | Enter the 6-digit code from your authenticator app. |
| `handler.otp.incorrect_code` | (none) | That code isn't right. Codes change every 30 seconds, so enter the one your app shows now. |

## Admin resource permissions handler

In-page validation messages for the permission-creation form on the admin
resource-permissions page.

| Code | Args | English message |
|---|---|---|
| `handler.admin_resource_permissions.description_html_not_allowed` | (none) | The description contains invalid characters, as we do not permit the use of HTML in the description. |
| `handler.admin_resource_permissions.permission_identifier_required` | (none) | Permission identifier is required. |
| `handler.admin_resource_permissions.description_too_long` | `max` (int) | The description cannot exceed a maximum length of {{.max}} characters. |

## Refusals the admin console and the admin API share

Written by the admin console before it calls the admin API, and by the API
when a caller sends the same request without the console's check.

| Code | Args | English message |
|---|---|---|
| `handler.client.identifier_required` | (none) | Client identifier is required. |
| `handler.attribute.key_required` | (none) | Attribute key is required |
| `handler.settings_email.destination_required` | (none) | Destination email is required. |

## Admin and account API refusals a person reaches through the console

The admin and account API writes each of these with the `error_code` and the
status it always had (`VALIDATION_ERROR`, `CONCURRENT_UPDATE`,
`EMAIL_ALREADY_EXISTS`, `LAST_ADMINISTRATOR`, `FILE_TOO_LARGE`, `NO_FILE`,
`VALUE_TOO_LONG`, `EMAIL_TOO_LONG`, `OTP_NOT_ENABLED`, `AUTHENTICATION_FAILED`,
`SMTP_NOT_ENABLED`, `INVALID_OR_EXPIRED_VERIFICATION_CODE`, `OTP_ALREADY_ENABLED`,
`SECRET_KEY_NOT_ACCEPTED`, `OTP_CODE_REQUIRED`, `INVALID_OTP_CODE`,
`OTP_ENROLLMENT_NOT_PENDING`, `SEND_FAILED`, `ROTATION_IN_PROGRESS`), so the key is not on the wire: only
`error_description` comes from here, in the request's language.
The account API's
disable of an authenticator it does not have reuses `handler.user.otp_not_enabled`,
its wrong code on enabling one `handler.otp.incorrect_code`, its email
verification send's conflict `handler.email_verification.account_changed`, and
its phone country refusal `validator.phone.country_invalid`. The test email's
SMTP being off reuses `handler.smtp.not_enabled`. The SMTP send failures are one
key per cause, each a whole sentence.

| Code | Args | English message |
|---|---|---|
| `handler.list_save.changed_since_loaded` | (none) | The list was changed by another save after it was loaded. Nothing was saved: reload it and make the change again. |
| `handler.list_save.changed_concurrently` | (none) | The list was changed by another save at the same moment. Nothing was saved: reload it and make the change again. |
| `handler.email.already_exists` | (none) | This email address is already registered |
| `handler.administrators.last_administrator` | (none) | This change would leave no enabled user holding authserver:manage. Grant it to another user first. |
| `handler.image_upload.too_large` | (none) | File too large or invalid form data |
| `handler.image_upload.no_file` | (none) | No picture file provided |
| `handler.user.email_too_long` | `max` (int) | The email address cannot exceed a maximum length of {{.max}} characters |
| `handler.user.otp_not_enabled` | (none) | User does not have OTP enabled |
| `handler.email_verification.account_changed` | (none) | The account was changed by another request while the code was being sent. Nothing was sent: try again. |
| `handler.account.current_password_required` | (none) | Current password is required. |
| `handler.account.new_password_required` | (none) | New password is required. |
| `handler.account.current_password_incorrect` | (none) | That password isn't right. Try again. |
| `handler.account.password_incorrect` | (none) | That password isn't right. Try again. |
| `handler.account.changed_since_loaded` | (none) | The account was changed by another request after it was loaded. Nothing was saved: reload it and make the change again. |
| `handler.smtp.not_enabled` | (none) | SMTP is not enabled |
| `handler.email_verification.code_invalid_or_expired` | (none) | That code isn't right, or it has expired. Send a new one if you need to. |
| `handler.account_otp.already_enabled` | (none) | OTP is already enabled |
| `handler.account_otp.secret_key_not_accepted` | (none) | This endpoint no longer accepts a secretKey. Start an enrollment with GET /api/v1/account/otp/enrollment and submit only the code from your authenticator app. |
| `handler.account_otp.code_required` | (none) | OTP code is required to enable. |
| `handler.account_otp.code_invalid` | (none) | Invalid OTP code. |
| `handler.account_otp.enrollment_not_pending` | (none) | No OTP enrollment is pending, or the one you started has expired. Request a new one with GET /api/v1/account/otp/enrollment and try again. |
| `handler.account_logout.post_logout_redirect_uri_required` | (none) | postLogoutRedirectUri is required |
| `handler.account_logout.client_identifier_invalid` | (none) | Invalid client identifier |
| `handler.account_logout.client_unresolved` | (none) | Unable to resolve client from postLogoutRedirectUri; supply clientIdentifier. |
| `handler.account_logout.post_logout_redirect_uri_not_registered` | (none) | postLogoutRedirectUri is not registered for the client |
| `handler.settings_email.send_failed_host_not_found` | (none) | Unable to send the test email: host name not found. |
| `handler.settings_email.send_failed_timed_out` | (none) | Unable to send the test email: connection timed out. |
| `handler.settings_email.send_failed_refused` | (none) | Unable to send the test email: connection refused. |
| `handler.settings_email.send_failed` | (none) | Unable to send the test email. |
| `handler.settings_email.starttls_not_offered` | (none) | The SMTP server did not offer STARTTLS; set the encryption to None only if the server has no TLS. |
| `handler.settings_email.password_unencrypted` | (none) | The SMTP server would receive the password unencrypted; set the encryption to STARTTLS or SSL/TLS. |
| `handler.settings_email.no_authentication` | (none) | SMTP credentials are configured but the server offers no authentication. |
| `handler.settings_email.no_supported_mechanism` | (none) | The SMTP server offers none of PLAIN, LOGIN or CRAM-MD5. |
| `handler.settings_email.tls_failed` | (none) | The TLS connection failed; check the encryption setting and the server's certificate. |
| `handler.settings_email.authentication_rejected` | (none) | The SMTP server rejected the username or password. |
| `handler.settings_email.message_refused` | (none) | The SMTP server refused the message. |
| `handler.settings_keys.rotation_in_progress` | (none) | Another key rotation is in progress |

## Refusals the admin API answers by key

The admin API's operations on clients, users, groups, resources and settings
write each of these with the key itself as the `error_code`, as `validator.*`
keys are written, so the admin console marks the field a refusal is about
(#617). Some reuse a key from above, written the same way: a client's
identifier left blank `handler.client.identifier_required`, a group's and a
user's attribute key `handler.attribute.key_required`, the resource permissions
save's description bound
`handler.admin_resource_permissions.description_too_long`, the user's phone
country `validator.phone.country_invalid`, and the test email's missing
destination `handler.settings_email.destination_required`; the token settings'
offline idle timeout above its max lifetime reuses the client tokens' key
below. An email settings save whose connection fails answers one key per
cause, each a whole sentence.

| Code | Args | English message |
|---|---|---|
| `handler.client.description_too_long` | `max` (int) | The description cannot exceed a maximum length of {{.max}} characters. |
| `handler.client.display_name_too_long` | `max` (int) | The display name cannot exceed a maximum length of {{.max}} characters. |
| `handler.client.identifier_in_use` | (none) | The client identifier is already in use. |
| `handler.client.identifier_names_resource` | (none) | The client identifier is already in use by a resource. |
| `handler.client.system_level_delete_not_allowed` | (none) | Trying to delete a system level client |
| `handler.client.system_level_identifier_fixed` | (none) | The identifier of a system-level client cannot be changed. |
| `handler.client.self_registered_identifier_fixed` | (none) | The identifier of a self-registered client cannot be changed. |
| `handler.client.default_acr_not_applicable` | (none) | Default ACR level is not applicable when authorization code flow is disabled. |
| `handler.client.default_acr_invalid` | (none) | Invalid default ACR level |
| `handler.client.website_url_too_long` | `max` (int) | The website URL cannot exceed a maximum length of {{.max}} characters. |
| `handler.client.website_url_invalid` | (none) | Invalid website URL. |
| `handler.client.website_url_scheme_invalid` | (none) | Website URL must use http or https scheme. |
| `handler.client.secret_invalid` | (none) | Invalid client secret. Please generate a new one. |
| `handler.client_administrative_scopes.allowed_required` | (none) | allowed is required. |
| `handler.client_administrative_scopes.console_always_allowed` | (none) | The admin console's client is always allowed to request the administrative scopes. |
| `handler.client_permissions.client_credentials_disabled` | (none) | Client permissions can only be configured when client credentials flow is enabled |
| `handler.client_redirect_uris.no_redirect_flow` | (none) | Redirect URIs are used by the authorization code with PKCE flow and by the implicit flow, and neither is enabled for this client. |
| `handler.client_redirect_uris.too_many` | `max` (int), `count` (int) | A client can have at most {{.max}} redirect URIs, and this list has {{.count}}. |
| `handler.client_redirect_uris.empty` | (none) | Redirect URI cannot be empty |
| `handler.client_redirect_uris.too_long` | `length` (int), `max` (int), `prefix` (string) | Redirect URI is too long ({{.length}} bytes, the maximum is {{.max}}): {{.prefix}}... |
| `handler.client_redirect_uris.invalid` | `uri` (string) | Invalid redirect URI: {{.uri}} |
| `handler.client_redirect_uris.insecure_http` | `uri` (string) | Redirect URI must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost): {{.uri}} |
| `handler.client_redirect_uris.not_absolute` | `uri` (string) | Redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): {{.uri}} |
| `handler.client_redirect_uris.duplicate` | (none) | Duplicate redirect URIs are not allowed |
| `handler.client_web_origins.empty` | (none) | Web origin cannot be empty |
| `handler.client_web_origins.invalid` | `origin` (string) | Invalid web origin: {{.origin}}. A web origin is a scheme, a host and an optional port, with nothing after the host: for example https://www.example.com or https://myapp:8080. The scheme must be http or https; the host must be ASCII, must carry no user information, and must not be an IPv6 literal or an abbreviated IPv4 address; and a port, if present, must be plain decimal below 65536 with no leading zero. |
| `handler.client_web_origins.too_long` | `length` (int), `max` (int), `origin` (string) | Web origin is too long ({{.length}} characters, the maximum is {{.max}}): {{.origin}} |
| `handler.client_web_origins.duplicate` | (none) | Duplicate web origins are not allowed |
| `handler.client_web_origins.expected_invalid` | `origin` (string) | Invalid web origin in expectedWebOrigins: {{.origin}}. Send the web origins exactly as you last read them. |
| `handler.client_tokens.token_expiration_out_of_range` | `max` (int) | Token lifetime must be between 0 and {{.max}} seconds. |
| `handler.client_tokens.offline_idle_timeout_out_of_range` | `max` (int) | Offline idle timeout must be between 0 and {{.max}} seconds. |
| `handler.client_tokens.offline_max_lifetime_out_of_range` | `max` (int) | Offline maximum lifetime must be between 0 and {{.max}} seconds. |
| `handler.client_tokens.offline_idle_timeout_above_max_lifetime` | (none) | The offline idle timeout can't be longer than the offline maximum lifetime. |
| `handler.client_tokens.include_claims_in_access_token_invalid` | (none) | Invalid value for includeOpenIDConnectClaimsInAccessToken. |
| `handler.client_tokens.include_claims_in_id_token_invalid` | (none) | Invalid value for includeOpenIDConnectClaimsInIdToken. |
| `handler.resource.identifier_required` | (none) | Resource identifier is required |
| `handler.resource.description_too_long` | `max` (int) | The description cannot exceed a maximum length of {{.max}} characters |
| `handler.resource.identifier_in_use` | (none) | The resource identifier is already in use |
| `handler.resource.identifier_names_client` | (none) | The resource identifier is already in use by a client |
| `handler.resource.system_level_identifier_fixed` | (none) | The identifier of a system-level resource cannot be changed. |
| `handler.resource.system_level_delete_not_allowed` | (none) | Trying to delete a system level resource |
| `handler.permission.duplicate_ids` | (none) | Duplicate permission IDs in request are not allowed |
| `handler.permission.identifier_required` | (none) | Permission identifier is required |
| `handler.permission.duplicated` | `identifier` (string) | Permission {{.identifier}} is duplicated. |
| `handler.permission.built_in_deleted` | `identifier` (string) | Built-in permission '{{.identifier}}' cannot be deleted. |
| `handler.permission.built_in_renamed` | `identifier` (string) | Built-in permission '{{.identifier}}' cannot be renamed. |
| `handler.permission.identifier_in_use` | `identifier` (string) | Permission identifier {{.identifier}} is already in use. |
| `handler.group.identifier_required` | (none) | Group identifier is required |
| `handler.group.description_too_long` | `max` (int) | The description cannot exceed a maximum length of {{.max}} characters |
| `handler.group.identifier_in_use` | (none) | The group identifier is already in use |
| `handler.group_member.already_member` | (none) | User is already a member of this group |
| `handler.group_member.not_member` | (none) | User is not a member of this group |
| `handler.group_attribute.group_id_required` | (none) | Group ID is required |
| `handler.attribute.value_too_long` | `max` (int) | The attribute value cannot exceed a maximum length of {{.max}} characters |
| `handler.user.email_required` | (none) | Email is required |
| `handler.user.set_password_type_invalid` | (none) | setPasswordType must be "now" or "email" |
| `handler.user.password_required` | (none) | Password is required |
| `handler.user.new_password_required` | (none) | New password is required |
| `handler.user.otp_enable_not_supported` | (none) | Enabling OTP is not supported through this endpoint |
| `handler.user_groups.too_many` | (none) | Too many group ids |
| `handler.settings_general.app_name_too_long` | `max` (int) | App name is too long. The maximum length is {{.max}} characters. |
| `handler.settings_general.issuer_uri_invalid` | (none) | Invalid issuer. Enter an https URL with no query, fragment or user info, or the auth server's base URL. |
| `handler.settings_general.issuer_too_long` | `max` (int) | Issuer is too long. The maximum length is {{.max}} characters. |
| `handler.settings_general.password_policy_invalid` | (none) | Invalid password policy |
| `handler.settings_sessions.idle_timeout_not_positive` | (none) | The idle timeout must be greater than zero. |
| `handler.settings_sessions.max_lifetime_not_positive` | (none) | The maximum lifetime must be greater than zero. |
| `handler.settings_sessions.idle_timeout_too_large` | `max` (int) | The idle timeout can't be more than {{.max}} seconds. |
| `handler.settings_sessions.max_lifetime_too_large` | `max` (int) | The maximum lifetime can't be more than {{.max}} seconds. |
| `handler.settings_sessions.idle_timeout_above_max_lifetime` | (none) | The idle timeout can't be longer than the maximum lifetime. |
| `handler.settings_sessions.max_sessions_per_user_required` | (none) | Enter the maximum sessions per user. |
| `handler.settings_sessions.max_sessions_per_user_out_of_range` | `max` (int) | The maximum sessions per user must be between 0 and {{.max}}. |
| `handler.settings_tokens.token_expiration_not_positive` | (none) | The token lifetime must be greater than zero. |
| `handler.settings_tokens.token_expiration_too_large` | `max` (int) | The token lifetime can't be more than {{.max}} seconds. |
| `handler.settings_tokens.offline_idle_timeout_not_positive` | (none) | The offline idle timeout must be greater than zero. |
| `handler.settings_tokens.offline_idle_timeout_too_large` | `max` (int) | The offline idle timeout can't be more than {{.max}} seconds. |
| `handler.settings_tokens.offline_max_lifetime_not_positive` | (none) | The offline maximum lifetime must be greater than zero. |
| `handler.settings_tokens.offline_max_lifetime_too_large` | `max` (int) | The offline maximum lifetime can't be more than {{.max}} seconds. |
| `handler.settings_email.smtp_host_required` | (none) | SMTP host is required. |
| `handler.settings_email.smtp_port_required` | (none) | SMTP port is required. |
| `handler.settings_email.smtp_from_email_required` | (none) | SMTP from email is required. |
| `handler.settings_email.smtp_host_too_long` | `max` (int) | SMTP host must be less than {{.max}} characters. |
| `handler.settings_email.smtp_port_out_of_range` | (none) | SMTP port must be between 1 and 65535. |
| `handler.settings_email.smtp_encryption_invalid` | (none) | Invalid SMTP encryption. |
| `handler.settings_email.smtp_username_too_long` | `max` (int) | SMTP username must be less than {{.max}} characters. |
| `handler.settings_email.smtp_password_too_long` | `max` (int) | SMTP password must be at most {{.max}} bytes. |
| `handler.settings_email.smtp_from_name_too_long` | `max` (int) | SMTP from name must be less than {{.max}} characters. |
| `handler.settings_email.smtp_from_email_too_long` | `max` (int) | SMTP from email must be less than {{.max}} characters. |
| `handler.settings_email.smtp_password_and_clear` | (none) | Send either a new SMTP password or clearSmtpPassword, not both. |
| `handler.settings_email.smtp_host_changed` | (none) | The SMTP host has changed: enter the SMTP password again, or remove it. |
| `handler.settings_email.connect_failed_host_not_found` | (none) | Unable to connect to the SMTP server: host name not found. |
| `handler.settings_email.connect_failed_timed_out` | (none) | Unable to connect to the SMTP server: connection timed out. |
| `handler.settings_email.connect_failed_refused` | (none) | Unable to connect to the SMTP server: connection refused. |
| `handler.settings_email.connect_failed` | (none) | Unable to connect to the SMTP server. |
| `handler.settings_keys.key_not_found` | (none) | Key not found |
| `handler.settings_keys.only_previous_revocable` | (none) | Only a previous key can be revoked |
| `handler.settings_ui_theme.theme_invalid` | (none) | Invalid theme. |
| `handler.settings_audit_logs.retention_days_negative` | (none) | The retention can't be negative. Use 0 to keep stored events forever. |
| `handler.settings_audit_logs.retention_days_too_large` | (none) | The retention can't be more than 3650 days (10 years). |

## Password validator

| Code | Args | English message |
|---|---|---|
| `validator.password.too_short` | `min` (int) | Use at least {{.min}} characters for the password. |
| `validator.password.too_long` | `max` (int) | Use at most {{.max}} bytes for the password. Accented and other non-English characters count as two or more bytes each. |
| `validator.password.lowercase_required` | (none) | Add a lowercase letter to the password. |
| `validator.password.uppercase_required` | (none) | Add an uppercase letter to the password. |
| `validator.password.number_required` | (none) | Add a number to the password. |
| `validator.password.special_char_required` | (none) | Add a symbol to the password. |

## Profile validator

| Code | Args | English message |
|---|---|---|
| `validator.profile.username_taken` | (none) | Sorry, this username is already taken. |
| `validator.profile.username_invalid` | (none) | Usernames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long. |
| `validator.profile.given_name_invalid` | (none) | Please enter a valid given name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length. |
| `validator.profile.middle_name_invalid` | (none) | Please enter a valid middle name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length. |
| `validator.profile.family_name_invalid` | (none) | Please enter a valid family name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length. |
| `validator.profile.nickname_invalid` | (none) | Nicknames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long. |
| `validator.profile.website_invalid` | (none) | Please enter a valid website URL. |
| `validator.profile.website_too_long` | `max` (int) | Please ensure the website URL is no longer than {{.max}} characters. |
| `validator.profile.gender_invalid` | (none) | Gender is invalid. |
| `validator.profile.dob_invalid_format` | (none) | The date of birth is invalid. Please use the format YYYY-MM-DD. |
| `validator.profile.dob_in_future` | (none) | The date of birth can't be in the future. |
| `validator.profile.zone_info_invalid` | (none) | The zone info is invalid. |
| `validator.profile.locale_invalid` | (none) | The locale is invalid. |

## Image validator

| Code | Args | English message |
|---|---|---|
| `validator.image.too_large` | `max` (int) | The image can be at most {{.max}} bytes. |
| `validator.image.empty` | (none) | The image file is empty. |
| `validator.image.unsupported_type` | (none) | The image type is not supported. Allowed types are JPEG, PNG, GIF and WebP. |
| `validator.image.undecodable` | (none) | The image could not be read. The file may be damaged. |
| `validator.image.dimensions_too_small` | `min` (int) | The image must be at least {{.min}}x{{.min}} pixels. |
| `validator.image.dimensions_too_large` | `max` (int) | The image can be at most {{.max}}x{{.max}} pixels. |

## Authorize validator

Emitted by `ValidateClientAndRedirectURI` before any redirect is possible, so
these are rendered on the refusal page rather than returned to the client
(#213).

| Code | Args | English message |
|---|---|---|
| `validator.authorize.client_id_missing` | (none) | The client_id parameter is missing. |
| `validator.authorize.client_not_found` | (none) | Invalid client_id parameter. The application does not exist. |
| `validator.authorize.client_disabled` | (none) | Invalid client_id parameter. The application is disabled. |
| `validator.authorize.redirect_uri_missing` | (none) | The redirect_uri parameter is missing. |
| `validator.authorize.redirect_uri_not_absolute` | (none) | Invalid redirect_uri parameter. The redirect URI must be an absolute URI: a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host. |
| `validator.authorize.redirect_uri_not_registered` | (none) | Invalid redirect_uri parameter. The application does not have this redirect URI registered. |
