package apihandlers

// The survivor table TestAPIErrorCodes_MatchTheSurvivorTable holds the API to, in a file of its own
// because the documentation tests read it too, under the race detector as well as without it,
// while the lint builds only without it.

// apiErrorCodes is the survivor table: every error_code the admin and account API may write, and
// who acts on it. "Category" means no caller routes on it and the HTTP status carries the meaning;
// it is the answer decision 18 flattened the spellings into.
var apiErrorCodes = map[string]string{
	// The three generic conditions decision 18 settled.
	"VALIDATION_ERROR":     "category: a rejected value, 400. The console's render.ErrorFieldOrBlank marks the first required field sent blank on it.",
	"INVALID_REQUEST_BODY": "category: a body that will not parse, 400.",
	"NOT_FOUND":            "category: an absent entity, 404.",

	// Codes the admin console's Go code routes on, beyond VALIDATION_ERROR above.
	// isHandledAccountOTPError in adminconsole/.../handler_account_otp.go holds the first eight.
	"AUTHENTICATION_FAILED":                "adminconsole: isHandledAccountOTPError redraws the OTP form with the API's sentence.",
	"INVALID_OTP_CODE":                     "adminconsole: isHandledAccountOTPError.",
	"OTP_CODE_REQUIRED":                    "adminconsole: isHandledAccountOTPError.",
	"OTP_ENROLLMENT_NOT_PENDING":           "adminconsole: isHandledAccountOTPError.",
	"OTP_CLOCK_AHEAD":                      "adminconsole: isHandledAccountOTPError shows it on the code field (#142).",
	"SECRET_KEY_NOT_ACCEPTED":              "adminconsole: isHandledAccountOTPError.",
	"OTP_ALREADY_ENABLED":                  "adminconsole: handler_account_otp.go reloads the page on it, from the enable and from the enrolment fetch.",
	"OTP_NOT_ENABLED":                      "adminconsole: handler_account_otp.go reloads the page on it, from the disable.",
	"INVALID_RECOVERY_CODE":                "400 on the account's own deletion: the recovery code sent in place of an authenticator code is wrong or already used, the sign-in page's answer to both (#783).",
	"ACCOUNT_DELETION_DISABLED":            "403 on the account's own deletion: an administrator turned it off, so only an administrator can delete the account (#783).",
	"INVALID_OR_EXPIRED_VERIFICATION_CODE": "adminconsole: handler_account_email_verification.go:139.",

	// Conditions an integrator can act on, distinguishable from a plain rejected value. #279 kept
	// these codes live for that reason, and they are documented in openapi.yaml.
	"EMAIL_ALREADY_EXISTS": "409 on createUser: the address is taken, so the caller picks another.",
	"EMAIL_TOO_LONG":       "400: the address exceeds the column, so the caller shortens it.",
	"VALUE_TOO_LONG":       "400: an attribute value exceeds the column.",
	"FILE_TOO_LARGE":       "400 on an upload: the caller re-encodes smaller.",
	"NO_FILE":              "400 on an upload: the multipart part is missing.",
	"CONCURRENT_UPDATE":    "409 on a list save, the account's email change and code send, the administrator's email verification code generation, and an OTP enable or disable: the stored list or account changed after it was loaded, or another save added the same value at the same moment, so nothing was written and the caller reads it again and retries (#428, #404, #471).",
	"SMTP_NOT_ENABLED":     "400 on the test email and the email verification code's send and check: SMTP is off, so the caller turns it on first.",
	"SEND_FAILED":          "400 on the test email: it could not be sent, and error_description says what to check.",
	"LAST_ADMINISTRATOR":   "409 on the six writes that can remove a holder of authserver:manage: the change would leave no enabled user holding it, so the caller grants it to another user first (#402).",

	// Authentication and authorization. A caller distinguishes "send a token", "the token is not
	// good enough" and "the session is gone", and retries differently for each.
	// ACCESS_TOKEN_REQUIRED, INVALID_REQUEST, INVALID_TOKEN, INVALID_DPOP_PROOF, USER_CONTEXT_REQUIRED,
	// INSUFFICIENT_SCOPE, CLIENT_NOT_ALLOWED and INSUFFICIENT_USER_AUTHENTICATION are the bearer
	// middleware's; the rest are handlers'. An account handler reached without the token or subject
	// that middleware guarantees answers the 500, not a 401 of its own (#522 decision 4).
	"ACCESS_TOKEN_REQUIRED":            "401: no bearer token, so the caller obtains one.",
	"INVALID_REQUEST":                  "400: the bearer token was sent by two methods at once, or its access_token parameter twice: RFC 6750 section 3.1's invalid_request.",
	"INVALID_TOKEN":                    "401: the bearer token did not validate.",
	"INVALID_DPOP_PROOF":               "401: the token was sent with the DPoP scheme and its DPoP proof is missing, invalid or used before, so the caller sends a fresh proof (RFC 9449 section 7.1, #42).",
	"INVALID_SESSION":                  "401: the session behind the token is gone.",
	"USER_CONTEXT_REQUIRED":            "403: the endpoint needs a user, and the token carries none.",
	"INSUFFICIENT_SCOPE":               "403: the token's scopes do not cover the route.",
	"CLIENT_NOT_ALLOWED":               "403 from RequireAdminConsoleClient: the route answers only tokens issued to the admin console's own client, whatever the token's scopes (#783).",
	"INSUFFICIENT_USER_AUTHENTICATION": "401 from RequireRecentAuthentication, RFC 9470 section 3's step-up refusal: the token's sign-in is too old or below the route's level, so the caller signs the user in again with the challenge's acr_values and max_age (#782).",
	"FORBIDDEN":                        "403: the caller may not act on this resource.",
	"MANAGE_SCOPE_REQUIRED":            "403 from the administrative policy: the request acts on an administrator or an administrative permission, which only authserver:manage may do, so no granular scope will ever be enough (#402).",

	// Key rotation, kept by decision 7 where every other 500-adjacent code went: a caller acts on
	// each, and openapi.yaml documents them.
	"ROTATION_IN_PROGRESS":     "409 on rotateKeys: another rotation won the race and this call rotated nothing, so the caller does not retry.",
	"ROTATION_OUTCOME_UNKNOWN": "409 on rotateKeys: the commit that would end the rotation failed for a reason other than a deadlock, so its outcome is unknown and the caller inspects the key set before retrying.",
	"KEY_SET_INCOMPLETE":       "500 on rotateKeys: the key set is not in a rotatable state.",

	// Written outside a handler, by something in front of one.
	"INTERNAL_SERVER_ERROR": "category: every 500 on this surface, decision 7.",
	"TOO_MANY_REQUESTS":     "429 from the auth server's rate limiter: the caller waits and retries.",
}
