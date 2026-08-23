package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/customerrors"
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
