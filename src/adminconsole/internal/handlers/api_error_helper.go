package handlers

import (
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
)

// HandleAPIError - for simple operations without forms (delete, etc.)
func HandleAPIError(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error) {
	if apiErr, ok := err.(*apiclient.APIError); ok {
		httpHelper.InternalServerError(w, r, fmt.Errorf("API error: %s (Code: %s, StatusCode: %d)", apiErr.Message, apiErr.Code, apiErr.StatusCode))
	} else {
		httpHelper.InternalServerError(w, r, err)
	}
}

// HandleAPIErrorWithCallback - for form operations that can show validation errors.
//
// Routes on HTTP status: 400 Bad Request is treated as a user-correctable
// validation failure and surfaced back to the form via renderErrorFunc;
// anything else escalates to InternalServerError. The English description
// from the API response is surfaced verbatim.
func HandleAPIErrorWithCallback(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error, renderErrorFunc func(string)) {
	if apiErr, ok := err.(*apiclient.APIError); ok {
		if apiErr.StatusCode == http.StatusBadRequest {
			renderErrorFunc(apiErr.Message)
			return
		}
		httpHelper.InternalServerError(w, r, fmt.Errorf("API error: %s (Code: %s, StatusCode: %d)", apiErr.Message, apiErr.Code, apiErr.StatusCode))
	} else {
		httpHelper.InternalServerError(w, r, err)
	}
}
