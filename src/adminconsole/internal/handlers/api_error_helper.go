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
// 404 joins them, and is the AJAX half of what HandleAPIError answers with the 404 page: every
// apiclient method funnels a non-2xx through parseAPIError, so "the row is gone" reaches this
// function as an *apiclient.APIError and nothing else. It answers the console's own 404 sentence
// rather than forwarding the API's, matching what the page beside it shows (#279 decision 11).
func HandleAPIErrorJson(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusNotFound {
			JsonNotFound(httpHelper, w, r)
			return
		}
		if apiErr.StatusCode == http.StatusBadRequest || apiErr.StatusCode == http.StatusConflict {
			httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode(
				apiErr.Code, apiErr.Message, apiErr.StatusCode))
			return
		}
	}
	httpHelper.JsonError(w, r, err)
}

// JsonNotFound is the AJAX counterpart of HttpHelper.NotFound, and answers the same three
// conditions with the same status and the same silence: a URL id the router never bound, one that
// does not parse, and an id the API says names nothing.
//
// An AJAX request has the same relationship to its target URI as the page beside it does -- RFC
// 9110 section 15.5.5, 404 "indicates that the origin server did not find a current representation
// for the target resource" -- so only the representation differs, JSON rather than the 404 page.
// Before this, 54 such sites answered 500: a stack, a log record and a request id spent telling an
// administrator that the server had broken when what had actually happened is that somebody else
// deleted the row while their page was open (#279).
//
// It is silent because JsonError does not log an *ErrorDetail, which is the property that makes it
// the counterpart of NotFound rather than a differently spelled 500.
func JsonNotFound(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) {
	httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("not_found",
		"Sorry, the item you are looking for could not be found. It may have been deleted, or the address may be incorrect.",
		http.StatusNotFound))
}

// JsonBadRequestBody answers a request whose body did not arrive, did not decode, or decoded
// without something the endpoint requires.
//
// RFC 9110 section 15.5.1: 400 "indicates that the server cannot or will not process the request
// due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
// request message framing...)". All four routes to it are that: json.Decoder.Decode and
// json.Unmarshal reject the syntax, io.ReadAll(r.Body) fails when the framing is broken or the
// client went away mid-request, and a decoded map missing its id is a body the console's own
// script should never have sent. None is a server fault, and answering 500 logged a stack for each
// of them (#279 decision 12).
func JsonBadRequestBody(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) {
	httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request_body",
		"The request body is not valid JSON, or is missing information this endpoint requires.",
		http.StatusBadRequest))
}
