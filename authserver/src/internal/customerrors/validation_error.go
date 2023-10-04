package customerrors

import (
	"fmt"
	"strings"
)

type ValidationError struct {
	Code        string
	Description string
}

func NewValidationError(code string, description string) *ValidationError {
	return &ValidationError{
		Code:        code,
		Description: description,
	}
}

func (e ValidationError) Error() string {
	msg := ""
	if len(strings.TrimSpace(e.Code)) > 0 {
		msg = fmt.Sprintf("(%v) %v", e.Code, e.Description)
	} else {
		msg = fmt.Sprintf("%v", e.Description)
	}
	return msg
}
