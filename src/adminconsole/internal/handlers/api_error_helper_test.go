package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This is the first behavioural test in this package: the three files here today are two lint tests
// and TestMain.
//
// It owns what HandleAPIErrorJson forwards, which is the only observable half of #251's admin
// console change. The modal itself is sendAjaxRequest in utils.js, unchanged, and no test in this
// repository drives a browser, so this is where "the administrator reads the API's sentence rather
// than a request id" is pinned. The distinction it tests is invisible at runtime unless you read the
// screen: both branches call JsonError, and only the argument differs.
//
// mocks_handlerhelpers.HttpHelper is the core module's mock. Its method set is a superset of this
// package's HttpHelper interface, so it satisfies it without a hand-written stub.

// captureJsonError registers JsonError and returns a pointer to the error it was handed.
func captureJsonError(httpHelper *mocks_handlerhelpers.HttpHelper) *error {
	var captured error
	httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured, _ = args.Get(2).(error)
		}).Return().Once()
	return &captured
}

// TestHandleAPIErrorJson_ForwardsConflict is #251's case. A 409 from the auth server API says
// another rotation won the race, which is a fact about the administrator's own request, so its code,
// description and status reach the browser instead of "An unexpected server error has occurred".
func TestHandleAPIErrorJson_ForwardsConflict(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	captured := captureJsonError(httpHelper)

	HandleAPIErrorJson(httpHelper, httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/settings/keys/rotate", nil),
		&apiclient.APIError{
			Code:       "ROTATION_IN_PROGRESS",
			Message:    "Another key rotation is in progress",
			StatusCode: http.StatusConflict,
		})

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, "ROTATION_IN_PROGRESS", detail.GetCode())
	assert.Equal(t, "Another key rotation is in progress", detail.GetDescription())
	assert.Equal(t, http.StatusConflict, detail.GetHttpStatusCode())
}

// TestHandleAPIErrorJson_ForwardsBadRequest pins the behaviour #122 established. It is here so that
// adding 409 to the condition cannot quietly replace 400 rather than join it.
func TestHandleAPIErrorJson_ForwardsBadRequest(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	captured := captureJsonError(httpHelper)

	HandleAPIErrorJson(httpHelper, httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/clients/1/redirect-uris", nil),
		&apiclient.APIError{
			Code:       "VALIDATION_ERROR",
			Message:    "Invalid redirect URI",
			StatusCode: http.StatusBadRequest,
		})

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, "VALIDATION_ERROR", detail.GetCode())
	assert.Equal(t, "Invalid redirect URI", detail.GetDescription())
	assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
}

// TestHandleAPIErrorJson_GenericBranchForOtherStatuses is the other side of the boundary. A 500 from
// the API is a server fault, so it keeps going to the log with a request id on screen rather than
// having its English text shown to an administrator who can do nothing with it.
func TestHandleAPIErrorJson_GenericBranchForOtherStatuses(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	captured := captureJsonError(httpHelper)

	apiErr := &apiclient.APIError{
		Code:       "INTERNAL_ERROR",
		Message:    "Failed to rotate signing keys",
		StatusCode: http.StatusInternalServerError,
	}
	HandleAPIErrorJson(httpHelper, httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/settings/keys/rotate", nil), apiErr)

	assert.Same(t, apiErr, *captured,
		"a status outside the forwarded set must reach JsonError unwrapped, for its generic branch")
}

// TestHandleAPIErrorJson_ForwardsAWrappedAPIError is decision 6's regression guard at this helper.
// The three tests above hand it the *APIError itself, which is what the api client returns today, so
// they pass against a bare type assertion as well as against errors.As. This one does not: the
// moment anything between the api client and the handler adds context to the error, the assertion
// stops seeing the 409 and the administrator gets "An unexpected server error has occurred" for a
// race they could have retried (#279).
func TestHandleAPIErrorJson_ForwardsAWrappedAPIError(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	captured := captureJsonError(httpHelper)

	HandleAPIErrorJson(httpHelper, httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/settings/keys/rotate", nil),
		errs.Wrap(&apiclient.APIError{
			Code:       "ROTATION_IN_PROGRESS",
			Message:    "Another key rotation is in progress",
			StatusCode: http.StatusConflict,
		}, "unable to rotate the signing keys"))

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, "ROTATION_IN_PROGRESS", detail.GetCode())
	assert.Equal(t, "Another key rotation is in progress", detail.GetDescription())
	assert.Equal(t, http.StatusConflict, detail.GetHttpStatusCode())
}

// TestHandleAPIErrorWithCallback_RendersAWrappedBadRequest is the same guard on the form path, which
// routes on the same type through its own assertion. A 400 here is the API telling the administrator
// what is wrong with the form they just submitted, so a wrap losing it replaces that sentence with a
// 500 page and discards the form.
func TestHandleAPIErrorWithCallback_RendersAWrappedBadRequest(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	rendered := ""
	HandleAPIErrorWithCallback(httpHelper, httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/clients/1/settings", nil),
		errs.Wrap(&apiclient.APIError{
			Code:       "VALIDATION_ERROR",
			Message:    "Invalid client identifier",
			StatusCode: http.StatusBadRequest,
		}, "unable to save the client"),
		func(message string) { rendered = message })

	assert.Equal(t, "Invalid client identifier", rendered)
}

// The 404 arm is the one decision 11 is actually about. The console's own `if resp == nil` guards
// were written for a (nil, nil) the api client never returns: every method funnels a non-2xx through
// parseAPIError, so an administrator following a link to a deleted client arrives here holding a 404
// *APIError, and before this arm existed the answer was a 500 page with a stack in the log.
//
// The table runs both HTML helpers over the same statuses, because the 404 has to join the form
// path's 400 rather than displace it, and everything else has to stay a 500 (#279 decision 11).
func TestHandleAPIError_RoutesOnStatus(t *testing.T) {
	testCases := []struct {
		name         string
		err          error
		wantNotFound bool
	}{
		{
			name:         "a 404 is answered with the 404 page",
			err:          &apiclient.APIError{Code: "NOT_FOUND", Message: "Client not found", StatusCode: http.StatusNotFound},
			wantNotFound: true,
		},
		{
			name:         "a wrapped 404 is still answered with the 404 page",
			err:          errs.Wrap(&apiclient.APIError{Code: "NOT_FOUND", Message: "Client not found", StatusCode: http.StatusNotFound}, "unable to load the client"),
			wantNotFound: true,
		},
		{
			name: "a 500 from the API stays a 500",
			err:  &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError},
		},
		{
			name: "a 403 from the API stays a 500",
			err:  &apiclient.APIError{Code: "FORBIDDEN", Message: "insufficient permissions", StatusCode: http.StatusForbidden},
		},
		{
			name: "a 400 from the API stays a 500 on this helper, which has no form to re-render",
			err:  &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "Invalid client identifier", StatusCode: http.StatusBadRequest},
		},
		{
			name: "a transport error stays a 500",
			err:  errs.New("connection refused"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			if testCase.wantNotFound {
				httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			} else {
				httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
			}

			HandleAPIError(httpHelper, httptest.NewRecorder(),
				httptest.NewRequest(http.MethodGet, "/admin/clients/42/settings", nil), testCase.err)

			httpHelper.AssertExpectations(t)
		})
	}
}

// The form path's own table. A 400 still re-renders the form with the API's sentence, which is what
// #122 established; a 404 means the thing the form edits is gone, so there is no form to re-render.
func TestHandleAPIErrorWithCallback_RoutesOnStatus(t *testing.T) {
	testCases := []struct {
		name         string
		err          error
		wantNotFound bool
		wantRendered string
	}{
		{
			name:         "a 404 is answered with the 404 page and never reaches the form",
			err:          &apiclient.APIError{Code: "NOT_FOUND", Message: "Client not found", StatusCode: http.StatusNotFound},
			wantNotFound: true,
		},
		{
			name:         "a 400 still re-renders the form with the API's sentence",
			err:          &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "Invalid client identifier", StatusCode: http.StatusBadRequest},
			wantRendered: "Invalid client identifier",
		},
		{
			name: "a 500 from the API stays a 500",
			err:  &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError},
		},
		{
			name: "a transport error stays a 500",
			err:  errs.New("connection refused"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			switch {
			case testCase.wantNotFound:
				httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			case testCase.wantRendered == "":
				httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
			}

			rendered := ""
			HandleAPIErrorWithCallback(httpHelper, httptest.NewRecorder(),
				httptest.NewRequest(http.MethodPost, "/admin/clients/42/settings", nil), testCase.err,
				func(message string) { rendered = message })

			assert.Equal(t, testCase.wantRendered, rendered)
			httpHelper.AssertExpectations(t)
		})
	}
}

// The two writers below are #279 decisions 11 and 12 answered for an AJAX request. Both own a
// status and a silence: JsonError does not log an *ErrorDetail, so neither spends a stack, a log
// record and a request id on a stale link or a malformed body the way the 500 they replace did.
//
// The status is the whole claim, so it is what these assert. A row that read only the code would
// still pass if the constructor lost its status, and JsonError answers 500 for an *ErrorDetail
// whose status is zero -- which is the exact regression, silently.

func TestJsonNotFound_Answers404WithoutLogging(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	captured := captureJsonError(httpHelper)

	JsonNotFound(httpHelper, httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/users/42/attributes/7/remove", nil))

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, http.StatusNotFound, detail.GetHttpStatusCode())
	assert.Equal(t, "not_found", detail.GetCode())
	assert.NotEmpty(t, detail.GetDescription())
}

func TestJsonBadRequestBody_Answers400WithoutLogging(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	captured := captureJsonError(httpHelper)

	JsonBadRequestBody(httpHelper, httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/users/42/consents", nil))

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
	assert.Equal(t, "invalid_request_body", detail.GetCode())
	assert.NotEmpty(t, detail.GetDescription())
}

// TestHandleAPIErrorJson_AnswersNotFound is decision 11's AJAX half. Until it existed, an
// administrator clicking a row another administrator had just deleted was told the server had
// broken: a 404 from the API fell past the forwarded set into the generic arm, so it answered 500
// with a stack and a request id. It answers the console's own 404 sentence rather than forwarding
// the API's, which is what the page beside it shows.
func TestHandleAPIErrorJson_AnswersNotFound(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	captured := captureJsonError(httpHelper)

	HandleAPIErrorJson(httpHelper, httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/users/42/attributes/7/remove", nil),
		&apiclient.APIError{
			Code:       "NOT_FOUND",
			Message:    "User not found",
			StatusCode: http.StatusNotFound,
		})

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, http.StatusNotFound, detail.GetHttpStatusCode())
	assert.Equal(t, "not_found", detail.GetCode())
	assert.NotContains(t, detail.GetDescription(), "User not found",
		"the API's own sentence is not forwarded; the console shows the sentence its 404 page shows")
}
