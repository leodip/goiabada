package customerrors

import (
	"fmt"
	"sort"
	"strings"
)

var (
	ErrNoAuthContext = NewErrorDetail("no_auth_context", "no auth context in session")
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
