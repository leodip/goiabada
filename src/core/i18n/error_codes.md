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
