package api

// ErrorResponse is the admin/account API error envelope:
//
//	{
//	  "error_code":        "VALIDATION_ERROR",
//	  "error_description": "Please ensure the locality is no longer than 60 characters."
//	}
//
// Field semantics:
//   - error_code: specific stable identifier for the failure (UPPER_SNAKE
//     for legacy codes, dotted lowercase for catalog-keyed localized codes).
//   - error_description: a sentence for people to read, in the request's
//     language when error_code is a catalog key and in English otherwise.
//   - error_field: when set, a JSON Pointer (RFC 6901) to the member of the
//     request body the refusal is about, such as /footerLinks/1/url. Only
//     the refusals of a brand's footer links set it (#814 decision 10).
//
// Consumers route by HTTP status code (4xx vs 5xx), not by an in-body
// category string.
//
// Protocol endpoints (/auth/token, /auth/authorize, /connect/register, /userinfo)
// keep their RFC-defined error envelopes and do NOT use this struct.
type ErrorResponse struct {
	ErrorCode        string `json:"error_code,omitempty"`
	ErrorDescription string `json:"error_description"`
	ErrorField       string `json:"error_field,omitempty"`
}

type SuccessResponse struct {
	Success bool `json:"success"`
}
