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
