package adminuserhandlers

import (
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
)

// handleAPIError - for simple operations without forms (delete, etc.)
func handleAPIError(httpHelper handlers.HttpHelper, w http.ResponseWriter, r *http.Request, err error) {
	if apiErr, ok := err.(*apiclient.APIError); ok {
		httpHelper.InternalServerError(w, r, fmt.Errorf("API error: %s (Code: %s, StatusCode: %d)", apiErr.Message, apiErr.Code, apiErr.StatusCode))
	} else {
		httpHelper.InternalServerError(w, r, err)
	}
}

// handleAPIErrorWithCallback - for form operations that can show validation errors
func handleAPIErrorWithCallback(httpHelper handlers.HttpHelper, w http.ResponseWriter, r *http.Request, err error, renderErrorFunc func(string)) {
	if apiErr, ok := err.(*apiclient.APIError); ok {
		// Check if it's a user-facing validation error
		switch apiErr.Code {
		case "VALIDATION_ERROR", "EMAIL_REQUIRED", "EMAIL_TOO_LONG", "EMAIL_ALREADY_EXISTS",
			"PASSWORD_REQUIRED":
			renderErrorFunc(apiErr.Message)
		default:
			// System errors should crash
			httpHelper.InternalServerError(w, r, fmt.Errorf("API error: %s (Code: %s, StatusCode: %d)", apiErr.Message, apiErr.Code, apiErr.StatusCode))
		}
	} else {
		httpHelper.InternalServerError(w, r, err)
	}
}
