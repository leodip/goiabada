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
| `validator.settings.app_name_angle_brackets` | (none) | The application name cannot contain the characters < or >. |
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
| `handler.password.confirmation_required` | (none) | Password confirmation is required. |
| `handler.password.confirmation_mismatch` | (none) | The password confirmation does not match the password. |

## OTP handler

| Code | Args | English message |
|---|---|---|
| `handler.otp.account_disabled` | (none) | Your account is disabled. |
| `handler.otp.code_required` | (none) | OTP code is required. |
| `handler.otp.incorrect_code` | (none) | Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app. |

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
`VALUE_TOO_LONG`, `EMAIL_TOO_LONG`, `OTP_NOT_ENABLED`), so the key is not on
the wire: only `error_description` comes from here, in the request's language.
The resource permissions save's description bound reuses
`handler.admin_resource_permissions.description_too_long` above, a group's and
a user's attribute key reuses `handler.attribute.key_required`, the user's
phone country refusal reuses `validator.phone.country_invalid`, and a client's
identifier and description refusals reuse `handler.client.identifier_required`
and `handler.admin_resource_permissions.description_too_long`.

| Code | Args | English message |
|---|---|---|
| `handler.list_save.changed_since_loaded` | (none) | The list was changed by another save after it was loaded. Nothing was saved: reload it and make the change again. |
| `handler.list_save.changed_concurrently` | (none) | The list was changed by another save at the same moment. Nothing was saved: reload it and make the change again. |
| `handler.email.already_exists` | (none) | This email address is already registered |
| `handler.administrators.last_administrator` | (none) | This change would leave no enabled user holding authserver:manage. Grant it to another user first. |
| `handler.image_upload.too_large` | (none) | File too large or invalid form data |
| `handler.image_upload.no_file` | (none) | No picture file provided |
| `handler.resource.identifier_required` | (none) | Resource identifier is required |
| `handler.resource.description_too_long` | `max` (int) | The description cannot exceed a maximum length of {{.max}} characters |
| `handler.resource.identifier_in_use` | (none) | The resource identifier is already in use |
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
| `handler.attribute.value_too_long` | `max` (int) | The attribute value cannot exceed a maximum length of {{.max}} characters |
| `handler.user.email_required` | (none) | Email is required |
| `handler.user.email_too_long` | `max` (int) | The email address cannot exceed a maximum length of {{.max}} characters |
| `handler.user.set_password_type_invalid` | (none) | setPasswordType must be "now" or "email" |
| `handler.user.password_required` | (none) | Password is required |
| `handler.user.new_password_required` | (none) | New password is required |
| `handler.user.otp_enable_not_supported` | (none) | Enabling OTP is not supported through this endpoint |
| `handler.user.otp_not_enabled` | (none) | User does not have OTP enabled |
| `handler.user_groups.too_many` | (none) | Too many group ids |
| `handler.email_verification.account_changed` | (none) | The account was changed by another request while the code was being sent. Nothing was sent: try again. |
| `handler.client.display_name_too_long` | `max` (int) | The display name cannot exceed a maximum length of {{.max}} characters. |
| `handler.client.identifier_in_use` | (none) | The client identifier is already in use. |
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
| `handler.client_redirect_uris.not_absolute` | `uri` (string) | Redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): {{.uri}} |
| `handler.client_redirect_uris.duplicate` | (none) | Duplicate redirect URIs are not allowed |
| `handler.client_web_origins.empty` | (none) | Web origin cannot be empty |
| `handler.client_web_origins.invalid` | `origin` (string) | Invalid web origin: {{.origin}}. A web origin is a scheme, a host and an optional port, with nothing after the host: for example https://www.example.com or https://myapp:8080. The scheme must be http or https; the host must be ASCII, must carry no user information, and must not be an IPv6 literal or an abbreviated IPv4 address; and a port, if present, must be plain decimal below 65536 with no leading zero. |
| `handler.client_web_origins.too_long` | `length` (int), `max` (int), `origin` (string) | Web origin is too long ({{.length}} characters, the maximum is {{.max}}): {{.origin}} |
| `handler.client_web_origins.duplicate` | (none) | Duplicate web origins are not allowed |
| `handler.client_web_origins.expected_invalid` | `origin` (string) | Invalid web origin in expectedWebOrigins: {{.origin}}. Send the web origins exactly as you last read them. |
| `handler.client_tokens.token_expiration_out_of_range` | `max` (int) | Token expiration in seconds must be between 0 and {{.max}}. |
| `handler.client_tokens.offline_idle_timeout_out_of_range` | `max` (int) | Refresh token offline - idle timeout in seconds must be between 0 and {{.max}}. |
| `handler.client_tokens.offline_max_lifetime_out_of_range` | `max` (int) | Refresh token offline - max lifetime in seconds must be between 0 and {{.max}}. |
| `handler.client_tokens.offline_idle_timeout_above_max_lifetime` | (none) | Refresh token offline - idle timeout cannot be greater than max lifetime. |
| `handler.client_tokens.include_claims_in_access_token_invalid` | (none) | Invalid value for includeOpenIDConnectClaimsInAccessToken. |
| `handler.client_tokens.include_claims_in_id_token_invalid` | (none) | Invalid value for includeOpenIDConnectClaimsInIdToken. |

## Password validator

| Code | Args | English message |
|---|---|---|
| `validator.password.too_short` | `min` (int) | The minimum length for the password is {{.min}} characters |
| `validator.password.too_long` | `max` (int) | The password can be at most {{.max}} bytes long. Accented and other non-English characters count as two or more bytes each. |
| `validator.password.lowercase_required` | (none) | As per our policy, a lowercase character is required in the password. |
| `validator.password.uppercase_required` | (none) | As per our policy, an uppercase character is required in the password. |
| `validator.password.number_required` | (none) | As per our policy, your password must contain a numerical digit. |
| `validator.password.special_char_required` | (none) | As per our policy, a special character/symbol is required in the password. |

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
| `validator.authorize.client_not_found` | (none) | Invalid client_id parameter. The client does not exist. |
| `validator.authorize.client_disabled` | (none) | Invalid client_id parameter. The client is disabled. |
| `validator.authorize.auth_code_not_enabled` | (none) | Invalid client_id parameter. The client does not support the authorization code flow. |
| `validator.authorize.redirect_uri_missing` | (none) | The redirect_uri parameter is missing. |
| `validator.authorize.redirect_uri_not_absolute` | (none) | Invalid redirect_uri parameter. The redirect URI must be an absolute URI: a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host. |
| `validator.authorize.redirect_uri_not_registered` | (none) | Invalid redirect_uri parameter. The client does not have this redirect URI registered. |
