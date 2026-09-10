package handlers

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
)

// HandleAPIError - for simple operations without forms (delete, etc.)
//
// A 404 is answered with the 404 page. This is the console's live "the entity is gone" path and
// the only one that fires: every apiclient method funnels a non-2xx through parseAPIError, so the
// admin API's NOT_FOUND arrives here as an *apiclient.APIError rather than as the (nil, nil) the
// callers' own `== nil` guards were written for. Until this arm existed, following a stale link or
// a bookmark to a deleted user told the administrator the server had broken, and spent a stack, a
// log record and a request id saying so (#279).
func HandleAPIError(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusNotFound {
			httpHelper.NotFound(w, r)
			return
		}
		httpHelper.InternalServerError(w, r, errs.Errorf("API error: %s (Code: %s, StatusCode: %d)", apiErr.Message, apiErr.Code, apiErr.StatusCode))
	} else {
		httpHelper.InternalServerError(w, r, err)
	}
}

// HandleAPIErrorWithCallback - for form operations that can show validation errors.
//
// Routes on HTTP status: 400 Bad Request is treated as a user-correctable
// validation failure and surfaced back to the form via renderErrorFunc; 404 Not Found means the
// thing the form edits no longer exists, so there is no form to re-render and the 404 page is the
// answer (#279); anything else escalates to InternalServerError. The English description
// from the API response is surfaced verbatim.
func HandleAPIErrorWithCallback(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error, renderErrorFunc func(string)) {
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusBadRequest {
			renderErrorFunc(apiErr.Message)
			return
		}
		if apiErr.StatusCode == http.StatusNotFound {
			httpHelper.NotFound(w, r)
			return
		}
		httpHelper.InternalServerError(w, r, errs.Errorf("API error: %s (Code: %s, StatusCode: %d)", apiErr.Message, apiErr.Code, apiErr.StatusCode))
	} else {
		httpHelper.InternalServerError(w, r, err)
	}
}

// HandleAPIErrorJson - the AJAX counterpart of HandleAPIErrorWithCallback, for handlers
// that answer with JSON rather than a rendered form.
//
// Routes on HTTP status the same way: 400 Bad Request from the auth server API is a
// user-correctable validation failure, so its status and English description are forwarded
// to the browser. 409 Conflict is forwarded for the same reason: it says another operation
// won a race, which is a fact about the administrator's own request rather than a server
// fault, and it names an action they should not repeat. Anything else, including an error
// that is not an *apiclient.APIError, falls through to JsonError's other branch: HTTP 500,
// the detail in the server log, and a request id on screen.
//
// This exists because JsonError preserves a status and a description only for
// *customerrors.ErrorDetail. An *apiclient.APIError handed to it directly takes the generic
// branch, so an administrator who typed a value the API refused is told "An unexpected
// server error has occurred", and the sentence naming the offending value goes to the log
// instead of to the screen (#122).
//
// Whatever renders the forwarded description must escape it: it can carry the caller's own
// input echoed back by the API. sendAjaxRequest in adminconsole's utils.js does, and that
// escaping is load-bearing rather than defensive, because showModalDialog assigns the
// description to innerHTML.
func HandleAPIErrorJson(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusBadRequest || apiErr.StatusCode == http.StatusConflict) {
		httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode(
			apiErr.Code, apiErr.Message, apiErr.StatusCode))
		return
	}
	httpHelper.JsonError(w, r, err)
}
