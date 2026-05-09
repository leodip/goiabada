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
`customerrors.ErrorDetail`.

| Code | Args | English message |
|---|---|---|
| `validator.email.required` | (none) | Please enter an email address. |
| `validator.email.invalid_format` | (none) | Please enter a valid email address. |
| `validator.email.too_long` | `max` (int) | The email address cannot exceed a maximum length of {{.max}} characters. |
| `validator.email.confirmation_mismatch` | (none) | The email and email confirmation entries must be identical. |
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
