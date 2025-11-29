package customerrors

import (
	"fmt"
	"sort"
	"strings"
)

var (
	ErrNoAuthContext = NewErrorDetail("no_auth_context", "no auth context in session")
	ErrUserDisabled  = NewErrorDetailWithHttpStatusCode("invalid_grant", "The user account is disabled.", 400)
)

type ErrorDetail struct {
	details map[string]string
}

func NewErrorDetail(code string, description string) *ErrorDetail {
	details := make(map[string]string)
	details["code"] = code
	details["description"] = description
	return &ErrorDetail{
		details: details,
	}
}

func NewErrorDetailWithHttpStatusCode(code string, description string, httpStatusCode int) *ErrorDetail {
	details := make(map[string]string)
	details["code"] = code
	details["description"] = description
	if httpStatusCode >= 100 && httpStatusCode < 600 {
		details["httpStatusCode"] = fmt.Sprintf("%d", httpStatusCode)
	}
	return &ErrorDetail{
		details: details,
	}
}

// NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate creates an ErrorDetail with WWW-Authenticate header info.
// Per RFC 6749 Section 5.2, when the client attempted to authenticate via the Authorization header
// and authentication failed, the server MUST respond with 401 and include WWW-Authenticate.
func NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate(code string, description string, httpStatusCode int, wwwAuthenticate string) *ErrorDetail {
	details := make(map[string]string)
	details["code"] = code
	details["description"] = description
	if httpStatusCode >= 100 && httpStatusCode < 600 {
		details["httpStatusCode"] = fmt.Sprintf("%d", httpStatusCode)
	}
	if wwwAuthenticate != "" {
		details["wwwAuthenticate"] = wwwAuthenticate
	}
	return &ErrorDetail{
		details: details,
	}
}

func (e *ErrorDetail) Error() string {
	if e.details["code"] == "" && e.details["httpStatusCode"] == "" {
		return e.details["description"]
	}

	// Create a slice of keys
	keys := make([]string, 0, len(e.details))
	for k := range e.details {
		keys = append(keys, k)
	}

	// Sort the keys alphabetically
	sort.Strings(keys)

	var sb strings.Builder
	for _, key := range keys {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(fmt.Sprintf("%v: %v", key, e.details[key]))
	}
	return sb.String()
}

func (e *ErrorDetail) GetCode() string {
	return e.details["code"]
}

func (e *ErrorDetail) GetDescription() string {
	return e.details["description"]
}

func (e *ErrorDetail) GetHttpStatusCode() int {
	statusCode := e.details["httpStatusCode"]
	if statusCode == "" {
		return 0
	}

	httpStatusCode := 0
	_, err := fmt.Sscanf(statusCode, "%d", &httpStatusCode)
	if err != nil {
		return 0
	}
	return httpStatusCode
}

// GetWWWAuthenticate returns the WWW-Authenticate header value if set.
// Per RFC 6749 Section 5.2, this should be included in 401 responses when
// the client attempted to authenticate via the Authorization header.
func (e *ErrorDetail) GetWWWAuthenticate() string {
	return e.details["wwwAuthenticate"]
}

func (e *ErrorDetail) IsError(target *ErrorDetail) bool {
	if target == nil {
		return false
	}

	if len(e.details) != len(target.details) {
		return false
	}

	for key, value := range e.details {
		targetValue, exists := target.details[key]
		if !exists || value != targetValue {
			return false
		}
	}

	return true
}
