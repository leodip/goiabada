package customerrors

import (
	"fmt"
	"net/http"
	"strings"
)

type AppError struct {
	Err            error
	Code           string
	Description    string
	StatusCode     int
	UseRedirectUri bool
}

func NewAppError(err error, code string, description string, statusCode int) *AppError {
	return &AppError{
		Err:         err,
		Code:        code,
		Description: description,
		StatusCode:  statusCode,
	}
}

func NewInternalServerError(err error, requestId string) *AppError {
	return &AppError{
		Err:         err,
		Code:        "server_error",
		Description: fmt.Sprintf("An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: %v", requestId),
		StatusCode:  http.StatusInternalServerError,
	}
}

func (e AppError) Error() string {
	msg := ""
	if len(strings.TrimSpace(e.Code)) > 0 {
		msg = fmt.Sprintf("(%v) %v", e.Code, e.Description)
	} else {
		msg = fmt.Sprintf("%v", e.Description)
	}
	if e.Err != nil {
		msg = msg + ":" + e.Err.Error()
	}
	return msg
}

func (e AppError) Unwrap() error {
	return e.Err // Returns inner error
}
