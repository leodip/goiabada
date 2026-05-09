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

## Browser-flow handler form errors

Emitted from handler-side checks (presence, confirmation match) rather than
the validator layer.

| Code | Args | English message |
|---|---|---|
| `handler.email.required` | (none) | Email is required. |
| `handler.password.required` | (none) | Password is required. |
| `handler.password.confirmation_required` | (none) | Password confirmation is required. |
| `handler.password.confirmation_mismatch` | (none) | The password confirmation does not match the password. |

## Password validator

| Code | Args | English message |
|---|---|---|
| `validator.password.too_short` | `min` (int) | The minimum length for the password is {{.min}} characters |
| `validator.password.too_long` | `max` (int) | The maximum length for the password is {{.max}} characters |
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
