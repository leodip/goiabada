package api

// ErrorResponse is the admin/account API error envelope:
//
//	{
//	  "error_code":        "VALIDATION_ERROR",
//	  "error_args":        {"max": 60},
//	  "error_description": "Please ensure the locality is no longer than 60 characters."
//	}
//
// Field semantics:
//   - error_code: specific stable identifier for the failure (UPPER_SNAKE
//     for legacy codes, dotted lowercase for catalog-keyed localized codes).
//   - error_args: parameters to substitute into the localized message
//     when the consumer renders error_code via the i18n catalog.
//   - error_description: rendered English message — for non-localizing
//     consumers (logs, curl, scripts) and as a debugging aid.
//
// Consumers route by HTTP status code (4xx vs 5xx), not by an in-body
// category string.
//
// Protocol endpoints (/auth/token, /auth/authorize, /connect/register, /userinfo)
// keep their RFC-defined error envelopes and do NOT use this struct.
type ErrorResponse struct {
	ErrorCode        string         `json:"error_code,omitempty"`
	ErrorArgs        map[string]any `json:"error_args,omitempty"`
	ErrorDescription string         `json:"error_description"`
}

type SuccessResponse struct {
	Success bool `json:"success"`
}
