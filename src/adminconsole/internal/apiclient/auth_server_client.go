package apiclient

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

type AuthServerClient struct {
	baseURL    string
	httpClient *http.Client
}

// APIError mirrors the flat ErrorResponse envelope returned by the
// admin/account API. Code and Message are populated from the wire's
// error_code and error_description fields respectively. Consumers route
// on StatusCode (4xx vs 5xx) rather than on an in-body category.
type APIError struct {
	Code       string         // "error_code" — stable identifier (UPPER_SNAKE for legacy, dotted lowercase for catalog-keyed)
	ErrorArgs  map[string]any // "error_args" — substitutions for the localized message
	Message    string         // "error_description" — rendered English text
	StatusCode int
}

func (e *APIError) Error() string {
	return e.Message
}

func parseAPIError(resp *http.Response, body []byte) *APIError {
	// Try to parse as JSON error response
	var errorResp api.ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err == nil && (errorResp.ErrorCode != "" || errorResp.ErrorDescription != "") {
		return &APIError{
			Code:       errorResp.ErrorCode,
			ErrorArgs:  errorResp.ErrorArgs,
			Message:    errorResp.ErrorDescription,
			StatusCode: resp.StatusCode,
		}
	}

	// Fall back to plain text error (for backward compatibility)
	return &APIError{
		Code:       "UNKNOWN_ERROR",
		Message:    string(body),
		StatusCode: resp.StatusCode,
	}
}

func NewAuthServerClient(authServerBaseURL string) *AuthServerClient {
	return &AuthServerClient{
		baseURL: authServerBaseURL,
		httpClient: &http.Client{
			Timeout: generalAPITimeout,
		},
	}
}
