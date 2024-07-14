package customerrors

import (
	"fmt"
	"strings"
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
	details["httpStatusCode"] = fmt.Sprintf("%d", httpStatusCode)
	return &ErrorDetail{
		details: details,
	}
}

func (e *ErrorDetail) Error() string {
	var sb strings.Builder

	for key, value := range e.details {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(fmt.Sprintf("%v: %v", key, value))
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

func (e *ErrorDetail) AddProperty(key string, value string) {
	e.details[key] = value
}
