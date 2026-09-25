package handlers

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// sessionEndedPath is the console route an admin API 401 sends the browser to, which clears the
// stored tokens and leaves a notice on the home page (#427 decision 17).
const sessionEndedPath = "/auth/session-ended"

// sessionEndedCode is the error code HandleAPIErrorJson answers an admin API 401 with. The three
// fetch sites in web/static/utils.js and web/static/image-upload.js key on this literal, not on the
// 403 status, to navigate to sessionEndedPath; every other 403 keeps its modal and signs nobody out.
const sessionEndedCode = "session_ended"

// IsSessionEnded reports whether the admin API refused the console's access token.
//
// RFC 6750 section 3.1: invalid_token is answered 401 when the token "is expired, revoked,
// malformed, or invalid for other reasons". The admin API's RequireValidSession answers it for an
// unexpired token whenever the account is disabled or its session has ended, idled out, outlived
// its maximum lifetime or been superseded, and the console's refresh token is bound to the same
// session, so a refresh and a retry would meet the same refusal. The administrator is signed out
// and told why instead of being shown the 500 page every 401 answered before (#427 decision 17).
//
// Exported for a read a page can do without, such as the client logo or the theme list redrawn
// beside a refused form. The page may carry on past any other failure of such a read, but not
// past this one, since every later call with the same token meets the same refusal: it hands the
// error to HandleAPIError, which signs the administrator out.
func IsSessionEnded(err error) bool {
	var apiErr *apiclient.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

// HandleAPIError - for simple operations without forms (delete, etc.)
//
// A 404 is answered with the 404 page. This is the console's live "the entity is gone" path and
// the only one that fires: every apiclient method funnels a non-2xx through parseAPIError, so the
// admin API's NOT_FOUND arrives here as an *apiclient.APIError rather than as the (nil, nil) the
// callers' own `== nil` guards were written for. Until this arm existed, following a stale link or
// a bookmark to a deleted user told the administrator the server had broken, and spent a stack, a
// log record and a request id saying so (#279).
//
// A 401 sends the browser to sessionEndedPath (see IsSessionEnded).
func HandleAPIError(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error) {
	if IsSessionEnded(err) {
		http.Redirect(w, r, sessionEndedPath, http.StatusFound)
		return
	}
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
//
// 409 Conflict joins 400, as it does in HandleAPIErrorJson. RFC 9110 section 15.5.10 uses it where
// "the user might be able to resolve the conflict and resubmit the request": an email address
// another account took between the form's check and its write is exactly that, and the 500 page
// this answered before threw the form away and blamed the server (#425).
//
// A 401 sends the browser to sessionEndedPath, as HandleAPIError does: no resubmission of the form
// can succeed with a token the admin API has refused.
func HandleAPIErrorWithCallback(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error, renderErrorFunc func(string)) {
	if IsSessionEnded(err) {
		http.Redirect(w, r, sessionEndedPath, http.StatusFound)
		return
	}
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusBadRequest || apiErr.StatusCode == http.StatusConflict {
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
//
// A 401 is answered 403 with sessionEndedCode and the console's own "sign-in has ended" sentence,
// which the browser follows to sessionEndedPath (see IsSessionEnded). Not 401: RFC 9110 section
// 15.5.2 says a 401 "MUST send a WWW-Authenticate header field", and the console signs in with a
// cookie and has no challenge to send; with 403 the client "MAY repeat the request with new or
// different credentials", section 15.5.4, which is what signing in again is (#427 decision 18).
func HandleAPIErrorJson(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error) {
	if IsSessionEnded(err) {
		httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode(sessionEndedCode,
			i18n.T(r.Context(), "adminconsole.session_ended.message"), http.StatusForbidden))
		return
	}
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
